// labcheck revisa la evidencia de un trabajo de Patrol para el día de laboratorio (docs/plans/validacion-labs.md):
// por playbook, los comandos rechazados, incompletos, truncados, vacíos, lentos o que no corrieron, y las líneas que
// parecen secretos sin enmascarar. Solo lee archivos: no habla con el núcleo ni con los equipos.
//
// Uso: go run ./tools/labcheck -pack packs/<paquete> [-pack ...] [-lento 30s] <carpeta del trabajo>
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var packs list
	flag.Var(&packs, "pack", "carpeta de un paquete (packs/<nombre>); repetible")
	slow := flag.Duration("lento", 30*time.Second, "un comando que tarda más que esto se reporta")
	flag.Parse()
	if flag.NArg() != 1 || len(packs) == 0 {
		fmt.Fprintln(os.Stderr, "uso: labcheck -pack packs/<paquete> [-pack ...] [-lento 30s] <carpeta del trabajo>")
		os.Exit(2)
	}
	if err := report(os.Stdout, flag.Arg(0), packs, *slow); err != nil {
		fmt.Fprintln(os.Stderr, "labcheck:", err)
		os.Exit(1)
	}
}

// Respuestas de rechazo conocidas de IOS, IOS-XE, NX-OS, AireOS, ISE, ASA/FTD y AAA; las más largas primero. El
// reporte imprime solo la marca, nunca la línea del equipo (podría traer un secreto, p. ej. un %PARSER con el comando
// registrado). Toda otra línea que empieza con «%» cuenta como rechazo sin texto. Se buscan en las primeras líneas
// (más abajo podrían ser texto de un log y no la respuesta).
var rejectMarks = []string{"% Invalid input", "% Invalid command", "% Invalid parameter", "% Incomplete command", "% Ambiguous command",
	"% Permission denied", "% Unrecognized", "% Invalid", "% Incomplete", "% Ambiguous", "Incorrect usage", "Syntax error", "ERROR: %",
	"Authorization failed"}

// Valores con pinta de secreto: tras una palabra clave (con su número de tipo opcional), key/message-digest-key con
// tipo, auth/priv 0x de SNMPv3 (NX-OS), un hash crypt ($1$, $8$, $9$...) o una llave privada. Cada alternativa
// captura el valor; los que son <MASKED:...> no cuentan. Da candidatos para revisar a mano, no veredictos.
var secretRe = regexp.MustCompile(`(?i)\b(?:password|secret|key-string|pre-shared-key|shared-secret|passphrase|community|server-key|authentication-key|wpa-psk|psk)\s+(?:[0-9]\s+)?(\S+)` +
	`|\bmessage-digest-key\s+\d+\s+md5\s+(?:[0-9]\s+)?(\S+)|\bkey\s+[0-9]\s+(\S+)|\b(?:auth|priv)\s+(?:\S+\s+)?(0x[0-9a-f]+)` +
	`|(\$[1-9][a-z]?\$\S{4,})|(BEGIN [A-Z ]*PRIVATE KEY)`)

// secretAt dice si la línea trae un valor con pinta de secreto que no sea <MASKED:...>, con la palabra clave y el
// largo de lo que la sigue hasta el fin de línea. El reporte imprime solo eso: el regex captura un token y el secreto
// puede ser otro de la misma línea (ntp authentication-key 1 md5 X, pre-shared-key local X...), así que nada del
// texto de la línea sale, ni lo que va antes.
func secretAt(ln string) (kw string, n int, ok bool) {
	for _, m := range secretRe.FindAllStringSubmatchIndex(ln, -1) {
		for g := 2; g < len(m); g += 2 {
			if m[g] < 0 || strings.HasPrefix(ln[m[g]:], "<MASKED:") {
				continue
			}
			word := strings.Fields(ln[m[0]:m[1]])[0]
			switch {
			case strings.HasPrefix(word, "$"):
				kw = "hash"
			case strings.EqualFold(word, "begin"):
				kw = "llave privada"
			default:
				kw = strings.ToLower(word) // una de las palabras del regex
			}
			return kw, utf8.RuneCountInString(strings.TrimSpace(ln[m[0]+len(word):])), true
		}
	}
	return "", 0, false
}

// Cabecera de sección que escribe patrol.Writer; una línea del equipo que la imita viene escapada con «\».
var headerRe = regexp.MustCompile(`^===== (?:ronda \d+ · )?\S+ · (.*?)(?: · comando inválido)?(?: · incompleto)? =====$`)

// secretsIn busca candidatos a secreto en los .txt de la carpeta de un equipo, con archivo y número de línea para que
// el dueño los abra él mismo. Los iguales (comando, palabra clave y largo) salen en una línea con todas sus ubicaciones.
func secretsIn(jobDir, dev string) (out []string, err error) {
	ents, err := os.ReadDir(filepath.Join(jobDir, dev))
	if err != nil {
		return nil, err
	}
	var keys []string
	locs := map[string][]string{}
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".txt" {
			continue
		}
		rel := filepath.Join(dev, e.Name())
		f, err := os.Open(filepath.Join(jobDir, rel))
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		cmd := ""
		for n := 1; sc.Scan(); n++ {
			ln := sc.Text()
			if m := headerRe.FindStringSubmatch(ln); m != nil {
				cmd = m[1] // texto del playbook, no del equipo
				continue
			}
			kw, size, ok := secretAt(ln)
			if !ok {
				continue
			}
			k := fmt.Sprintf("`%s` · %s ⟦secreto? %d car.⟧", cmd, kw, size)
			if locs[k] == nil {
				keys = append(keys, k)
			}
			locs[k] = append(locs[k], fmt.Sprintf("%s:%d", rel, n))
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
	}
	for _, k := range keys {
		out = append(out, "- "+k+" · "+strings.Join(locs[k], ", "))
	}
	return out, nil
}

type expected struct {
	pb, cmd string
	done    bool
}

func report(w io.Writer, jobDir string, packDirs []string, slow time.Duration) error {
	raw, err := os.ReadFile(filepath.Join(jobDir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("%w (el trabajo debe estar cerrado: el manifest se escribe al final)", err)
	}
	var m patrol.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}
	pbs := map[string]playbook.Playbook{}
	for _, d := range packDirs {
		if fi, err := os.Stat(filepath.Join(d, "playbooks")); err == nil && fi.IsDir() {
			d = filepath.Join(d, "playbooks")
		}
		got, err := playbook.Load(os.DirFS(d))
		if err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		for _, p := range got {
			pbs[p.ID] = p
		}
	}
	fmt.Fprintf(w, "# labcheck · %s\n\n", filepath.Base(jobDir))
	if len(m.Devices) == 0 {
		return errors.New("el manifest no trae equipos: no corrió ninguna ronda")
	}
	for _, r := range m.Devices {
		fmt.Fprintf(w, "- %s (%s) ronda %d: %s · %d comandos, %d inválidos según el driver", r.Hostname, r.Target.Address, r.Round, r.State, r.Commands, r.Invalid)
		if _, _, secret := secretAt(r.Detail); secret {
			fmt.Fprint(w, " · (detalle omitido: parece traer un secreto; míralo en la auditoría)")
		} else if r.Detail != "" {
			fmt.Fprintf(w, " · %s", r.Detail)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "- enmascarado: %v · conteos: %v\n", m.Masked, m.MaskCounts)

	issues := map[string][]string{} // playbook -> líneas
	var order, outside, notes, secrets []string
	// Sin salidas (el equipo falló al conectar) analyze da error: el estado ya salió arriba y lo demás queda «no corrió».
	b, err := analyze.Load(jobDir)
	if err != nil {
		notes, b = append(notes, "- "+err.Error()), &analyze.Bundle{}
	}
	if zips, _ := filepath.Glob(filepath.Join(jobDir, "*.zip")); len(zips) > 0 {
		notes = append(notes, "- hay .zip en la carpeta: labcheck no busca secretos dentro (usa zip: ZIP_POLICY_NONE)")
	}
	for _, wn := range b.Warnings { // lo que el lector no pudo leer entero: lo que sigue puede salir como «no corrió»
		notes = append(notes, fmt.Sprintf("- %s · `%s`: %s", wn.Device, wn.Command, wn.Msg))
	}
	for _, r := range m.Devices {
		// shortcut: sin Ran se toman todos los playbooks del manifest; en un trabajo con varios equipos y gemelos
		// (ios/ios-xe) los del otro equipo saldrían como «no corrió». El runbook usa un equipo por trabajo.
		ids := r.Ran
		if ids == nil {
			for _, p := range m.Playbooks {
				ids = append(ids, p.ID)
			}
		}
		var exp []expected
		for _, id := range ids {
			if !slices.Contains(order, id) {
				order = append(order, id)
			}
			p, ok := pbs[id]
			if !ok {
				issues[id] = append(issues[id], "- no está en los paquetes dados (-pack): no se revisó")
				continue
			}
			vals := map[string]string{}
			for _, q := range p.Params {
				if v, ok := m.Params[q.Name]; ok {
					vals[q.Name] = v
				}
			}
			cmds, err := p.Expand(vals)
			if err != nil {
				issues[id] = append(issues[id], fmt.Sprintf("- sus datos no sirven (%v): no se revisó", err))
				continue
			}
			for _, c := range p.Pre {
				exp = append(exp, expected{pb: id, cmd: c})
			}
			for _, c := range cmds {
				if c.Applies(r.Platform) { // como patrol.commands: los de otra plataforma no corren ni se esperan
					exp = append(exp, expected{pb: id, cmd: c.Text})
				}
			}
		}
		dev := patrol.DeviceDirOf(r.Hostname, r.Target)
		var secs []analyze.Section
		for _, s := range b.Sections {
			if s.Device == dev && s.Round == r.Round {
				secs = append(secs, s)
			}
		}
		next := 0
		for i, s := range secs {
			pb := ""
			for j := next; j < len(exp); j++ {
				if exp[j].cmd == s.Command {
					exp[j].done, pb, next = true, exp[j].pb, j+1
					break
				}
			}
			end := m.EndedAt
			if i+1 < len(secs) {
				end = secs[i+1].At
			}
			for _, prob := range problems(s, end, slow) {
				line := fmt.Sprintf("- `%s` — %s", s.Command, prob)
				if pb == "" {
					outside = append(outside, line)
				} else {
					issues[pb] = append(issues[pb], line)
				}
			}
			if pb == "" && len(problems(s, end, slow)) == 0 {
				outside = append(outside, fmt.Sprintf("- `%s`", s.Command))
			}
		}
		if sec, err := secretsIn(jobDir, dev); err == nil {
			secrets = append(secrets, sec...)
		} else if !errors.Is(err, fs.ErrNotExist) {
			notes = append(notes, "- secretos sin revisar: "+err.Error())
		}
		for _, e := range exp {
			if !e.done {
				issues[e.pb] = append(issues[e.pb], fmt.Sprintf("- `%s` — no corrió (sin salida en la evidencia)", e.cmd))
			}
		}
	}

	clean := 0
	for _, id := range order {
		if len(issues[id]) == 0 {
			clean++
			continue
		}
		name := pbs[id].NameEn
		if name == "" {
			name = pbs[id].Name
		}
		fmt.Fprintf(w, "\n## %s · %s\n\n%s\n", id, name, strings.Join(issues[id], "\n"))
	}
	fmt.Fprintf(w, "\n%d de %d playbooks sin problemas.\n", clean, len(order))
	for _, part := range []struct {
		title string
		lines []string
	}{{"Fuera de playbook", outside}, {"Avisos", notes}, {"Posibles secretos sin enmascarar (revisar a mano)", secrets}} {
		if len(part.lines) > 0 {
			fmt.Fprintf(w, "\n## %s\n\n%s\n", part.title, strings.Join(part.lines, "\n"))
		}
	}
	return nil
}

// problems da lo que falla en la salida de un comando; end es cuándo empezó el siguiente (o el fin del trabajo).
func problems(s analyze.Section, end time.Time, slow time.Duration) (out []string) {
	rejected := ""
	n := 0
	for _, ln := range strings.Split(s.Text, "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		if n++; n > 5 {
			break
		}
		if i := slices.IndexFunc(rejectMarks, func(mk string) bool { return strings.Contains(strings.ToLower(ln), strings.ToLower(mk)) }); i >= 0 {
			rejected = rejectMarks[i]
			break
		}
		if strings.HasPrefix(ln, "%") {
			rejected = "% (otro mensaje del equipo)"
			break
		}
	}
	switch {
	case rejected != "":
		out = append(out, "rechazado: "+rejected)
	case s.Invalid:
		out = append(out, "rechazado (marcado por el driver)")
	}
	if s.Incomplete {
		out = append(out, "incompleto (se cortó o falló)")
	}
	if s.Truncated {
		out = append(out, "truncado al leer (tope de analyze)")
	}
	if strings.TrimSpace(s.Text) == "" {
		out = append(out, "salida vacía")
	}
	if d := end.Sub(s.At); !s.At.IsZero() && d > slow {
		out = append(out, fmt.Sprintf("lento: %d s", int(d.Round(time.Second)/time.Second)))
	}
	return out
}
