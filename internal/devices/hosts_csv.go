package devices

import (
	"bytes"
	"encoding/csv"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Un archivo para Excel: una celda que empieza con = + - @ tab o CR se ejecutaría como fórmula (Excel ignora los
// espacios y apóstrofos que van antes). Al escribir se le antepone «'»; al leer se quita ese «'» si, saltando
// espacios y apóstrofos, sigue uno de esos caracteres. Las dos mitades deciden con la misma regla, así una celda
// que ya empezaba con «'» o con espacios ir y volver no pierde nada.
func esFormula(c byte) bool { return strings.IndexByte("=+-@\t\r", c) >= 0 }

func apuntaAFormula(c string) bool {
	t := strings.TrimLeft(c, " '")
	return t != "" && esFormula(t[0])
}

func protege(c string) string {
	if apuntaAFormula(c) {
		return "'" + c
	}
	return c
}

func desprotege(c string) string {
	if strings.HasPrefix(c, "'") && apuntaAFormula(c) {
		return c[1:]
	}
	return c
}

const bom = "\xef\xbb\xbf"

// MarshalHostsCSV escribe el CSV: un BOM UTF-8, el encabezado fijo y una fila por host, comillas RFC 4180, sin suma.
func MarshalHostsCSV(hosts []FileHost) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(bom) // para que Excel detecte UTF-8 y muestre bien los acentos; el lector lo quita
	w := csv.NewWriter(&buf)
	w.Write(HostsHeader())
	for _, h := range hosts {
		cells := make([]string, len(HostFields))
		for i, f := range HostFields {
			cells[i] = protege(f.get(h))
		}
		w.Write(cells)
	}
	w.Flush()
	return buf.Bytes(), w.Error()
}

// ParseHostsCSV lee un CSV de import: acepta un BOM, exige el encabezado fijo (sin importar mayúsculas ni
// espacios) y valida cada fila por su cuenta; solo el tamaño, el encabezado o el tope de filas rechazan el archivo.
func ParseHostsCSV(b []byte) (Parsed, error) {
	var out Parsed
	if len(b) > MaxImportBytes {
		return out, i18n.New("hostfile.too_big", nil)
	}
	b = bytes.TrimPrefix(b, []byte(bom))
	if !utf8.Valid(b) {
		return out, i18n.New("hostfile.not_utf8", nil)
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	head, err := r.Read()
	if err == io.EOF {
		return out, i18n.New("hostfile.empty", i18n.A("header", strings.Join(HostsHeader(), ",")))
	}
	if err != nil {
		return out, i18n.Wrap("hostfile.header_read", err, nil)
	}
	if err := checkHeader(head); err != nil {
		return out, err
	}
	var rows []row
	var malas []LineError
	for n := 1; ; n++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if n > MaxImportHosts {
			return out, i18n.New("hostfile.too_many_rows", i18n.A("max", MaxImportHosts))
		}
		var pe *csv.ParseError
		if errors.As(err, &pe) {
			var reason error = pe.Err // texto de la biblioteca csv
			switch {
			case errors.Is(pe.Err, csv.ErrQuote) && r.InputOffset() >= int64(len(b)):
				// comilla abierta que no se cierra: el lector se tragó todo hasta el final
				reason = i18n.New("hostfile.quote_open", i18n.A("line", pe.StartLine))
			case errors.Is(pe.Err, csv.ErrQuote) || errors.Is(pe.Err, csv.ErrBareQuote):
				reason = i18n.New("hostfile.quote_bad", nil)
			}
			malas = append(malas, lineErr(pe.StartLine, "", reason))
			continue
		}
		if err != nil {
			return out, err
		}
		line, _ := r.FieldPos(0)
		if len(rec) != len(HostFields) {
			malas = append(malas, lineErr(line, "", i18n.New("hostfile.columns", i18n.A("got", len(rec), "want", len(HostFields)))))
			continue
		}
		for i := range rec {
			rec[i] = desprotege(rec[i])
		}
		h, ferr := rowToHost(rec)
		if ferr != nil {
			malas = append(malas, lineErr(line, ferr.Field, ferr))
			continue
		}
		rows = append(rows, row{line, h})
	}
	var errs []LineError
	out.Hosts, errs = validateRows(rows)
	out.Errors = append(malas, errs...)
	sortErrors(out.Errors)
	return out, nil
}

func lineErr(line int, field string, err error) LineError {
	return LineError{Line: line, Field: field, Reason: err.Error(), Err: err}
}

func sortErrors(e []LineError) {
	for i := 1; i < len(e); i++ {
		for j := i; j > 0 && e[j].Line < e[j-1].Line; j-- {
			e[j], e[j-1] = e[j-1], e[j]
		}
	}
}

func checkHeader(got []string) error {
	want := HostsHeader()
	norm := make([]string, len(got))
	have := map[string]bool{}
	for i, g := range got {
		norm[i] = strings.ToLower(strings.TrimSpace(g))
		have[norm[i]] = true
	}
	if strings.Join(norm, ",") == strings.Join(want, ",") {
		return nil
	}
	var faltan, sobran []string
	for _, w := range want {
		if !have[w] {
			faltan = append(faltan, w)
		}
	}
	wantSet := map[string]bool{}
	for _, w := range want {
		wantSet[w] = true
	}
	for _, g := range norm {
		if !wantSet[g] {
			sobran = append(sobran, g)
		}
	}
	if len(faltan) == 0 && len(sobran) == 0 {
		return i18n.New("hostfile.header_order", i18n.A("want", strings.Join(want, ",")))
	}
	return i18n.New("hostfile.header_diff", i18n.A("want", strings.Join(want, ","), "missing", strings.Join(faltan, ","), "extra", strings.Join(sobran, ",")))
}
