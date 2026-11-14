// Package capture lee la evidencia que dejó Patrol (o texto pegado de una
// sesión) y la parte en salidas por comando, para compararla o verificarla.
//
// No hace: conectarse a equipos; la recolección siempre es de Patrol.
package capture

import (
	"encoding/json"
	"fmt"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// maxFile acota lo que se lee por archivo: un show tech de varios cientos de MB no cabe en un reporte.
const maxFile = 64 << 20

// Key normaliza un comando: minúsculas y espacios simples.
// shortcut: no expande abreviaturas ("sh ver"); usar los comandos completos de los playbooks.
func Key(cmd string) string { return strings.ToLower(strings.Join(strings.Fields(cmd), " ")) }

var prompt = regexp.MustCompile(`^[A-Za-z0-9][\w.\-]*#\s*(\S.*)?$`)

// Split parte texto en salidas por comando. Entiende las cabeceras de Patrol
// ("===== hora · comando =====") y, si no hay, los prompts de una sesión pegada ("SW1#show version").
// Las salidas de comandos inválidos o incompletas se descartan.
func Split(text string) map[string]string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	out := map[string]string{}
	patrolFmt := strings.Contains(text, "===== ")
	cur, invalid := "", false
	var b strings.Builder
	flush := func() {
		if cur != "" && !invalid {
			out[cur] = b.String()
		}
		b.Reset()
	}
	for _, ln := range strings.SplitAfter(text, "\n") {
		body := strings.TrimSuffix(ln, "\n")
		if patrolFmt && strings.HasPrefix(body, "===== ") && strings.HasSuffix(body, " =====") {
			flush()
			parts := strings.Split(strings.TrimSuffix(strings.TrimPrefix(body, "===== "), " ====="), " · ")
			if strings.HasPrefix(parts[0], "ronda ") {
				parts = parts[1:]
			}
			cur, invalid = "", false
			if len(parts) >= 2 {
				cur = Key(parts[1])
				for _, p := range parts[2:] {
					invalid = invalid || strings.Contains(p, "inválido") || p == "incompleto"
				}
			}
			continue
		}
		if !patrolFmt {
			if m := prompt.FindStringSubmatch(body); m != nil {
				flush()
				cur, invalid = Key(m[1]), false
				continue
			}
		}
		if cur != "" {
			b.WriteString(ln)
		}
	}
	flush()
	return out
}

// Get devuelve la primera salida que exista entre los comandos dados y cuál fue.
func Get(outputs map[string]string, cmds ...string) (string, string) {
	for _, c := range cmds {
		if v, ok := outputs[Key(c)]; ok {
			return v, c
		}
	}
	return "", ""
}

type Device struct {
	Address  string            `json:"address"`
	Hostname string            `json:"hostname"`
	State    string            `json:"state"`
	Detail   string            `json:"detail,omitempty"`
	Outputs  map[string]string `json:"-"`
}

// ReadDir lee una carpeta de trabajo de Patrol (con su manifest.json). Un equipo
// aparece una vez, con su última ronda; sus salidas son las de la última ronda que las tenga.
func ReadDir(dir string) ([]Device, error) {
	b, err := readLimited(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, i18n.Wrap("capture.err.not_finished", err, i18n.A("dir", dir))
	}
	var m patrol.Manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("capture: manifest.json: %w", err)
	}
	last := map[string]patrol.DeviceResult{}
	var order []string
	for _, d := range m.Devices {
		a := patrol.Hostport(d.Target) // host:puerto: la misma dirección con otro puerto es otro equipo
		if _, seen := last[a]; !seen {
			order = append(order, a)
		}
		if prev, ok := last[a]; !ok || d.Round >= prev.Round {
			last[a] = d
		}
	}
	owned := map[string]bool{} // carpetas que ya son de un equipo del manifest: el reintento sin puerto no las toma
	for _, d := range m.Devices {
		owned[patrol.DeviceDirOf(d.Hostname, d.Target)] = true
	}
	var out []Device
	for _, a := range order {
		d := last[a]
		addr := d.Target.Address
		if patrol.EffectivePort(d.Target.Port) != 22 {
			addr = a // host:puerto, para que Compare no mezcle dos equipos con la misma dirección
		}
		dev := Device{Address: addr, Hostname: d.Hostname, State: d.State, Detail: d.Detail, Outputs: map[string]string{}}
		if d.Hostname != "" {
			files, _ := filepath.Glob(filepath.Join(dir, patrol.DeviceDirOf(d.Hostname, d.Target), "*.txt"))
			if old := patrol.DeviceDir(d.Hostname, d.Target.Address); len(files) == 0 && !owned[old] { // evidencia vieja: la carpeta no llevaba el puerto
				files, _ = filepath.Glob(filepath.Join(dir, old, "*.txt"))
			}
			sort.Strings(files)
			for _, f := range files {
				b, err := readLimited(f)
				if err != nil {
					return nil, fmt.Errorf("capture: %w", err)
				}
				for k, v := range Split(string(b)) {
					dev.Outputs[k] = v
				}
			}
		}
		out = append(out, dev)
	}
	return out, nil
}

func readLimited(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFile {
		return nil, fmt.Errorf("%s supera %d MiB", filepath.Base(p), maxFile>>20)
	}
	return b, nil
}
