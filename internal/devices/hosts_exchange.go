package devices

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	HostsFormato   = "macuahuitl-hosts"
	HostsVersion   = 1
	MaxImportBytes = 5 << 20
)

// FileHost es un host en el archivo de export: la credencial viaja solo como su etiqueta, nunca su id ni un secreto.
type FileHost struct {
	Name            string   `json:"name"`
	Address         string   `json:"address"`
	Port            int      `json:"port"`
	Platform        string   `json:"platform"`
	Folder          string   `json:"folder"`
	Tags            []string `json:"tags"`
	CredentialLabel string   `json:"credential_label"`
	Notes           string   `json:"notes"`
}

// Host es el host del archivo sin credencial resuelta (CredentialID vacío).
func (f FileHost) Host() Host {
	return Host{Name: f.Name, Address: f.Address, Port: f.Port, Platform: f.Platform, Folder: f.Folder, Tags: f.Tags, Notes: f.Notes}
}

// ToFile es el host listo para el archivo, con la etiqueta de su credencial (vacía si no tiene o no se resolvió).
func ToFile(h Host, label string) FileHost {
	return FileHost{Name: h.Name, Address: h.Address, Port: h.Port, Platform: h.Platform, Folder: h.Folder, Tags: h.Tags, CredentialLabel: label, Notes: h.Notes}
}

// archivoHosts: sha256 es la suma del JSON canónico del arreglo hosts; protege contra un archivo corrupto, no
// prueba quién lo hizo (cualquiera puede recalcularla).
type archivoHosts struct {
	Formato   string          `json:"formato"`
	Version   int             `json:"version"`
	Exportado string          `json:"exportado"`
	Hosts     json.RawMessage `json:"hosts"`
	SHA256    string          `json:"sha256,omitempty"`
}

// canon deja las etiquetas como arreglo (nunca null) para que el JSON canónico no dependa de cómo llegaron.
func canon(in []FileHost) []FileHost {
	out := make([]FileHost, len(in))
	for i, h := range in {
		if h.Tags == nil {
			h.Tags = []string{}
		}
		out[i] = h
	}
	return out
}

func sumaHosts(hosts []FileHost) (raw []byte, sum string, err error) {
	if raw, err = json.Marshal(canon(hosts)); err != nil {
		return nil, "", err
	}
	h := sha256.Sum256(raw)
	return raw, hex.EncodeToString(h[:]), nil
}

// MarshalHosts arma el archivo de export, con su suma.
func MarshalHosts(hosts []FileHost, now time.Time) ([]byte, error) {
	return marshalHosts(hosts, now, true)
}

func marshalHosts(hosts []FileHost, now time.Time, conSuma bool) ([]byte, error) {
	raw, sum, err := sumaHosts(hosts)
	if err != nil {
		return nil, err
	}
	if !conSuma {
		sum = ""
	}
	return json.Marshal(archivoHosts{Formato: HostsFormato, Version: HostsVersion, Exportado: now.UTC().Format(time.RFC3339), Hosts: raw, SHA256: sum})
}

// LineError es una fila (CSV) o entrada (JSON) inválida del archivo. Line es la línea del archivo en CSV
// (el encabezado es la 1) y la posición, desde 1, dentro de «hosts» en JSON. Field vacío = la fila entera.
type LineError struct {
	Line          int
	Field, Reason string
}

// Parsed es un archivo de import leído: los hosts válidos (canónicos), los errores por fila y si el JSON
// no traía suma. Solo un encabezado, formato o tamaño roto hace fallar el archivo completo.
type Parsed struct {
	Hosts  []FileHost
	Errors []LineError
	NoSum  bool
}

type row struct {
	line int
	h    FileHost
}

// validateRows aplica las reglas de cada host y que no haya nombres ni destinos repetidos dentro del archivo;
// la segunda fila que repite es la inválida.
func validateRows(rows []row) (ok []FileHost, errs []LineError) {
	nombres, claves := map[string]int{}, map[string]int{}
	for _, r := range rows {
		h, err := Clean(r.h.Host())
		if err == nil && (utf8.RuneCountInString(r.h.CredentialLabel) > MaxLabel || hasControl(r.h.CredentialLabel, false)) {
			err = fe("credential_label", "la etiqueta de credencial pasa de %d caracteres o trae caracteres de control", MaxLabel)
		}
		if err == nil {
			if l, dup := nombres[NameKey(h.Name)]; dup {
				err = fe("name", "el nombre ya está en la fila %d", l)
			} else if l, dup := claves[Key(h)]; dup {
				err = fe("address", "%s ya está en la fila %d", Key(h), l)
			}
		}
		if err != nil {
			le := LineError{Line: r.line, Reason: err.Error()}
			var f *FieldError
			if errors.As(err, &f) {
				le.Field = f.Field
			}
			errs = append(errs, le)
			continue
		}
		nombres[NameKey(h.Name)], claves[Key(h)] = r.line, r.line
		ok = append(ok, ToFile(h, r.h.CredentialLabel))
	}
	return
}

// ParseHosts lee un archivo JSON de import: tamaño, formato, versión, tope y suma (si la trae; si no, NoSum).
// Con suma que no coincide se rechaza todo; sin ella, cada host se valida por su cuenta.
func ParseHosts(b []byte) (Parsed, error) {
	var out Parsed
	if len(b) > MaxImportBytes {
		return out, errors.New("el archivo pasa de 5 MB")
	}
	// Primero solo formato y versión, sin modo estricto: una versión futura puede traer campos que esta no conoce.
	var cab struct {
		Formato string `json:"formato"`
		Version int    `json:"version"`
	}
	if err := json.NewDecoder(bytes.NewReader(b)).Decode(&cab); err != nil {
		return out, fmt.Errorf("no es un archivo de hosts: %w", err)
	}
	if cab.Formato != HostsFormato {
		return out, fmt.Errorf("formato %q: se esperaba %q", cab.Formato, HostsFormato)
	}
	if cab.Version != HostsVersion {
		return out, fmt.Errorf("versión %d no soportada (solo la %d)", cab.Version, HostsVersion)
	}
	var a archivoHosts
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return out, fmt.Errorf("no es un archivo de hosts: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return out, errors.New("hay datos después del JSON del archivo")
	}
	var entradas []json.RawMessage
	if len(a.Hosts) == 0 {
		return out, errors.New("falta la lista «hosts»")
	}
	if err := json.Unmarshal(a.Hosts, &entradas); err != nil {
		return out, fmt.Errorf("«hosts» no es una lista: %w", err)
	}
	if len(entradas) > MaxImportHosts {
		return out, fmt.Errorf("el archivo trae %d hosts; el tope es %d", len(entradas), MaxImportHosts)
	}
	var rows []row
	var malas []LineError
	for i, raw := range entradas {
		var h FileHost
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&h); err != nil {
			malas = append(malas, LineError{Line: i + 1, Reason: "entrada ilegible: " + err.Error()})
			continue
		}
		rows = append(rows, row{i + 1, h})
	}
	if a.SHA256 == "" {
		out.NoSum = true
	} else {
		leidos := make([]FileHost, len(rows))
		for i, r := range rows {
			leidos[i] = r.h
		}
		if _, sum, err := sumaHosts(leidos); err != nil || len(malas) > 0 || !strings.EqualFold(sum, a.SHA256) {
			return out, errors.New("la suma de verificación no coincide: el archivo está dañado o fue modificado")
		}
	}
	rows2 := make([]row, len(rows))
	for i, r := range rows {
		r.h = canon([]FileHost{r.h})[0]
		rows2[i] = r
	}
	var errs []LineError
	out.Hosts, errs = validateRows(rows2)
	out.Errors = append(malas, errs...)
	sortErrors(out.Errors)
	return out, nil
}
