// labcheck revisa la evidencia de un trabajo de Patrol para el día de laboratorio (docs/plans/validacion-labs.md):
// por playbook, los comandos rechazados, incompletos, truncados, vacíos, lentos o que no corrieron, y las líneas que
// parecen secretos sin enmascarar. Solo lee archivos: no habla con el núcleo ni con los equipos.
//
// Uso: go run ./tools/labcheck -pack packs/<paquete> [-pack ...] [-lento 30s] <carpeta del trabajo>
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

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

// Respuestas de rechazo que no empiezan con «%» (AireOS, ISE, ASA/FTD, AAA de IOS). Toda línea que empieza con «%»
// cuenta (% Invalid, % Incomplete, % Ambiguous, % Permission denied...). El driver solo marca algunas como «comando
// inválido»; aquí se buscan en las primeras líneas (más abajo podrían ser texto de un log y no la respuesta).
var rejectMarks = []string{"Incorrect usage", "Syntax error", "ERROR: %", "uthorization failed"}

// Valores con pinta de secreto: tras una palabra clave (con su número de tipo opcional), key/message-digest-key con
// tipo, auth/priv 0x de SNMPv3 (NX-OS), un hash crypt ($1$, $8$, $9$...) o una llave privada. Cada alternativa
// captura el valor; los que son <MASKED:...> no cuentan. Da candidatos para revisar a mano, no veredictos.
var secretRe = regexp.MustCompile(`(?i)\b(?:password|secret|key-string|pre-shared-key|shared-secret|passphrase|community|server-key|authentication-key|wpa-psk|psk)\s+(?:[0-9]\s+)?(\S+)` +
	`|\bmessage-digest-key\s+\d+\s+md5\s+(?:[0-9]\s+)?(\S+)|\bkey\s+[0-9]\s+(\S+)|\b(?:auth|priv)\s+(?:\S+\s+)?(0x[0-9a-f]+)` +
	`|(\$[1-9][a-z]?\$\S{4,})|(BEGIN [A-Z ]*PRIVATE KEY)`)

// leaks dice si la línea trae algún valor con pinta de secreto que no esté enmascarado.
func leaks(ln string) bool {
	for _, m := range secretRe.FindAllStringSubmatchIndex(ln, -1) {
		for g := 2; g < len(m); g += 2 {
			if m[g] >= 0 && !strings.HasPrefix(ln[m[g]:], "<MASKED:") {
				return true
			}
		}
	}
	return false
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
		if r.Detail != "" {
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
	for _, wn := range b.Warnings { // lo que el lector no pudo leer entero: lo que sigue puede salir como «no corrió»
		notes = append(notes, fmt.Sprintf("- %s · `%s`: %s", wn.Device, wn.Command, wn.Msg))
	}
	seenSecret := map[string]bool{}
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
			for _, ln := range strings.Split(s.Text, "\n") {
				ln = strings.TrimSpace(ln)
				if !leaks(ln) || seenSecret[dev+ln] {
					continue
				}
				seenSecret[dev+ln] = true
				if len(ln) > 200 {
					ln = ln[:200] + "…"
				}
				secrets = append(secrets, fmt.Sprintf("- %s · `%s`: %s", dev, s.Command, ln))
			}
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
		if strings.HasPrefix(ln, "%") || slices.ContainsFunc(rejectMarks, func(mk string) bool { return strings.Contains(ln, mk) }) {
			rejected = ln
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
