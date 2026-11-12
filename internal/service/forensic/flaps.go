package forensic

import (
	"context"
	"fmt"
	"strings"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/logintel"
	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// sections devuelve las salidas válidas de un comando (sin argumentos extra) de un trabajo,
// filtradas por equipo.
func sections(b *analyze.Bundle, device string, cmds ...string) []analyze.Section {
	var out []analyze.Section
	for _, sec := range b.Sections {
		c := strings.ToLower(strings.Join(strings.Fields(sec.Command), " "))
		if sec.Invalid || !contains(cmds, c) {
			continue
		}
		if d := strings.ToLower(device); d != "" && !strings.Contains(strings.ToLower(sec.Device), d) {
			continue
		}
		out = append(out, sec)
	}
	return out
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// counterSamples saca de los show interfaces del trabajo los contadores que importan para el
// flapping. Un contador entra solo si el equipo lo imprime.
func counterSamples(b *analyze.Bundle, device string) (ss []logintel.CounterSample, warns []string) {
	for _, sec := range sections(b, device, "show interfaces", "show interface") {
		ifs, ok := iosxe.ParseInterfaces(sec.Text)
		if !ok {
			warns = append(warns, fmt.Sprintf("%s ronda %d: show interfaces con un formato que no se reconoce", sec.Device, sec.Round))
			continue
		}
		for _, i := range ifs {
			c := map[string]int64{}
			if _, ok := i.Evidence["resets"]; ok {
				c["interface resets"] = i.Resets
			}
			if _, ok := i.Evidence["lost_carrier"]; ok {
				c["lost carrier"], c["no carrier"] = i.LostCarrier, i.NoCarrier
			}
			if _, ok := i.Evidence["carrier_transitions"]; ok {
				c["carrier transitions"] = i.CarrierTransitions
			}
			ss = append(ss, logintel.CounterSample{Host: sec.Device, Round: sec.Round, At: sec.At, Interface: i.Name, Counters: c})
		}
	}
	return ss, warns
}

func (s *forensicSvc) Flapping(_ context.Context, r *v1.FlappingRequest) (*v1.FlappingResponse, error) {
	s.d.MarkActive()
	l, err := s.loadLogs(r.Source)
	if err != nil {
		return nil, err
	}
	rep := logintel.Flaps(l.entries, logintel.FlapOptions{Count: int(min(r.Count, 1000)), Window: time.Duration(min(r.WindowSeconds, 86400)) * time.Second})
	jumps := []logintel.CounterJump{}
	extra := append([]string{}, l.warnings...) // los avisos del informe ya van en su texto
	jtxt := ""
	if l.bundle != nil {
		ss, warns := counterSamples(l.bundle, r.Source.GetDevice())
		extra = append(extra, warns...)
		if len(ss) == 0 {
			extra = append(extra, "el trabajo no tiene show interfaces: agrégalo al playbook para comparar contadores entre rondas")
		} else {
			jumps = logintel.CounterJumps(ss, int64(min(r.MinDelta, 1<<20)))
			jtxt = "\n\nContadores entre rondas:\n" + logintel.JumpsText(jumps)
		}
	}
	s.d.Audit("forensic.flapping", l.source, fmt.Sprintf("mensajes=%d flaps=%d saltos=%d", len(l.entries), len(rep.Flaps), len(jumps)))
	return &v1.FlappingResponse{Report: s.fitReport(len(rep.Flaps), func(n int, warn string) (any, string) {
		fr := rep
		fr.Flaps = rep.Flaps[:n]
		if warn != "" {
			fr.Warnings = append(fr.Warnings[:len(fr.Warnings):len(fr.Warnings)], warn)
		}
		out := struct {
			logintel.FlapReport
			Source       string                 `json:"source"`
			CounterJumps []logintel.CounterJump `json:"counter_jumps"`
			Stats        logintel.Stats         `json:"stats"`
		}{FlapReport: fr, Source: l.source, CounterJumps: jumps, Stats: l.stats}
		txt := "Fuente: " + l.source + "\n" + fr.Text() + jtxt
		for _, w := range extra {
			txt += "\nAviso: " + w
		}
		out.Warnings = append(append([]string{}, extra...), fr.Warnings...)
		return out, txt
	})}, nil
}
