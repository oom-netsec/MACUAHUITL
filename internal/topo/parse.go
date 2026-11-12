// Package topo arma la topología L2 de un caso a partir de CDP/LLDP: salidas
// de Patrol (show cdp|lldp neighbors detail, show spanning-tree, show
// etherchannel|port-channel summary, show version) y vecinos de un PCAP.
// Lógica pura, sin red.
//
// Los parsers siguen el formato de la documentación pública de Cisco (IOS-XE
// 17.x, NX-OS 9.3); sin validar en laboratorio con transcripciones reales.
package topo

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Device es un equipo recolectado por Patrol: sus salidas por comando.
type Device struct {
	Name, IP, Platform, Version string
	Outputs                     map[string]string // comando tal como se ejecutó → texto
}

var header = regexp.MustCompile(`^===== (?:ronda \d+ · )?\S+ · (.+?)(?: · comando inválido)? =====$`)

// LoadPatrolDir lee la carpeta de salida de un trabajo (un subdirectorio
// <equipo>_<IP> por equipo con archivos .txt). Si un comando aparece en varias
// rondas se queda la última.
func LoadPatrolDir(dir string) ([]Device, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []Device
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		files, _ := filepath.Glob(filepath.Join(dir, e.Name(), "*.txt"))
		sort.Strings(files)
		d := Device{Name: e.Name(), Outputs: map[string]string{}}
		if i := strings.LastIndexByte(e.Name(), '_'); i > 0 {
			d.Name, d.IP = e.Name()[:i], e.Name()[i+1:]
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return nil, err
			}
			var cmd string
			var sb strings.Builder
			flush := func() {
				if cmd != "" {
					d.Outputs[cmd] = sb.String()
				}
				sb.Reset()
			}
			for line := range strings.SplitSeq(string(b), "\n") {
				if m := header.FindStringSubmatch(line); m != nil {
					flush()
					cmd = strings.ToLower(strings.TrimSpace(m[1]))
					continue
				}
				sb.WriteString(line + "\n")
			}
			flush()
		}
		if len(d.Outputs) == 0 {
			continue
		}
		if out := output(d, "show version"); out != "" {
			v, _ := iosxe.ParseVersion(out)
			if v.Host != "" {
				d.Name = v.Host
			}
			d.Platform, d.Version = v.Model, v.Version
		}
		out = append(out, d)
	}
	return out, nil
}

// output busca la salida de un comando aceptando abreviaturas de IOS (sh cdp nei det).
func output(d Device, full string) string {
	want := strings.Fields(full)
	for cmd, text := range d.Outputs {
		got := strings.Fields(strings.SplitN(cmd, "|", 2)[0])
		if len(got) != len(want) {
			continue
		}
		ok := true
		for i := range got {
			ok = ok && strings.HasPrefix(want[i], got[i])
		}
		if ok {
			return text
		}
	}
	return ""
}
