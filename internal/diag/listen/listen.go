// Package listen reúne las reglas comunes de las escuchas que abre la app
// (traps SNMP, flujos): IP explícita, puerto no privilegiado (ADR 0004) y nada
// de todas las interfaces salvo que se pida.
package listen

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// ValidateAddr exige host:puerto con IP local explícita y puerto ≥ 1024 (0 = el que asigne el sistema).
func ValidateAddr(addr string, allowAny bool) error {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("dirección de escucha inválida %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return fmt.Errorf("puerto inválido %q", p)
	}
	if port != 0 && port < 1024 {
		return fmt.Errorf("el puerto %d es privilegiado; escucha en uno alto y, si el equipo no permite cambiar el destino, redirige con nftables (docs/plans/2026-11-04-fase-12-visibilidad.md)", port)
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return fmt.Errorf("el host debe ser una IP local, no %q", h)
	}
	if ip.IsUnspecified() && !allowAny {
		return errors.New("escuchar en todas las interfaces requiere pedirlo explícitamente")
	}
	return nil
}
