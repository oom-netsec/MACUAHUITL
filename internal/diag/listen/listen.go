// Package listen reúne las reglas comunes de las escuchas que abre la app
// (traps SNMP, flujos): IP explícita, puerto cualquiera (el bind decide, ADR 0004 enmienda 2026-11-16) y nada
// de todas las interfaces salvo que se pida.
package listen

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ValidateAddr exige host:puerto con IP local explícita y puerto (0 = el que asigne el sistema; los bajos los decide el kernel al abrir, ver Bind).
func ValidateAddr(addr string, allowAny bool) error {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return i18n.New("ingest.invalid.listen.parse", i18n.A("addr", addr, "detail", err))
	}
	_, err = strconv.ParseUint(p, 10, 16)
	if err != nil {
		return i18n.New("ingest.invalid.listen.port", i18n.A("port", p))
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return i18n.New("ingest.invalid.listen.host", i18n.A("host", h))
	}
	if ip.IsUnspecified() && !allowAny {
		return i18n.New("ingest.invalid.listen.any", nil)
	}
	return nil
}
