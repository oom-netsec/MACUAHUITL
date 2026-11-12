package ifaces

import (
	"net"
	"sort"
)

// Interface es una interfaz local tal como la ve el sistema.
type Interface struct {
	Name         string
	Up, Loopback bool
	Addresses    []string // CIDR
	HardwareAddr string
}

// List lista las interfaces locales ordenadas por nombre. Solo lee: no envía nada a la red.
func List() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]Interface, 0, len(ifs))
	for _, i := range ifs {
		n := Interface{Name: i.Name, Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0, HardwareAddr: i.HardwareAddr.String()}
		addrs, _ := i.Addrs() // una interfaz sin direcciones legibles se lista igual
		for _, a := range addrs {
			n.Addresses = append(n.Addresses, a.String())
		}
		out = append(out, n)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}
