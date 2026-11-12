// Package listen reúne las reglas comunes de las escuchas que abre la app
// (traps SNMP, flujos): IP explícita, puerto no privilegiado (ADR 0004) y nada
// de todas las interfaces salvo que se pida.
package listen

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ValidateAddr exige host:puerto con IP local explícita y puerto ≥ 1024 (0 = el que asigne el sistema).
func ValidateAddr(addr string, allowAny bool) error {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return i18n.New("ingest.invalid.listen.parse", i18n.A("addr", addr, "detail", err))
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return i18n.New("ingest.invalid.listen.port", i18n.A("port", p))
	}
	if port != 0 && port < 1024 {
		return i18n.New("ingest.invalid.listen.privileged", i18n.A("port", port))
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
