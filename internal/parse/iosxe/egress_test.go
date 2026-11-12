package iosxe

import (
	"slices"
	"testing"
)

// Fixtures en el formato de la documentación de Cisco (IOS 15.2E clásico e IOS-XE): sin validar en laboratorio.
func TestParseEgress(t *testing.T) {
	for name, tc := range map[string]struct {
		want []string
		ok   bool
	}{
		"ios152_show-ip-cef-host":       {[]string{"Vlan10"}, true},
		"ios152_show-ip-cef-attached":   {[]string{"Vlan99"}, true},
		"iosxe_show-ip-cef-host":        {[]string{"Vlan10"}, true},
		"iosxe_show-ip-cef-ecmp":        {[]string{"Vlan10", "Gi1/0/47"}, true},
		"iosxe_show-ip-cef-attached":    {[]string{"Vlan99"}, true},
		"ios152_show-ip-route-host":     {[]string{"Vlan10"}, true},
		"iosxe_show-ip-route-connected": {[]string{"Vlan99"}, true},
		// Lo que no da la salida con certeza: recursivo sin interfaz, Null0, sin tabla, vacío.
		"ios152_show-ip-cef-recursive":  {nil, false},
		"iosxe_show-ip-route-recursive": {nil, false},
		"iosxe_show-ip-cef-null":        {nil, false},
		"ios152_show-ip-route-missing":  {nil, false},
		// IPv6 (show ipv6 cef / show ipv6 route): sin validar en laboratorio.
		"ios15_show-ipv6-cef-host":        {[]string{"Vlan10"}, true},
		"ios15_show-ipv6-cef-attached":    {[]string{"Vlan99"}, true},
		"ios15_show-ipv6-cef-ecmp":        {[]string{"Vlan10", "Gi1/0/47"}, true},
		"ios15_show-ipv6-route-host":      {[]string{"Vlan10"}, true},
		"ios15_show-ipv6-route-connected": {[]string{"Vlan99"}, true},
		"ios15_show-ipv6-route-recursive": {nil, false},
		"ios15_show-ipv6-route-missing":   {nil, false},
	} {
		got, ok := ParseEgress(fx(t, name))
		if ok != tc.ok || !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v %v, quería %v %v", name, got, ok, tc.want, tc.ok)
		}
	}
	for _, junk := range []string{"", "\n", "algo que no es una tabla\n", "% IPv4 CEF not enabled\n"} {
		if got, ok := ParseEgress(junk); ok || got != nil {
			t.Errorf("%q = %v %v", junk, got, ok)
		}
	}
	// Una salida mixta con un salto sin interfaz no es cierta aunque otro la tenga.
	if _, ok := ParseEgress("198.51.100.0/24\n  nexthop 10.10.0.2 Vlan10\n  nexthop 10.20.0.2\n"); ok {
		t.Error("un nexthop sin interfaz deja la salida sin certeza")
	}
	if _, ok := ParseEgress("Routing paths:\n    FE80::1, Vlan10\n    2001:DB8:FF::1\n"); ok {
		t.Error("un salto IPv6 sin interfaz deja la salida sin certeza")
	}
	if _, ok := ParseEgress("198.51.100.0/24\n  via 10.10.0.2, Vlan10, 0 dependencies\n  via 10.255.0.254, 0 dependencies, recursive\n"); ok {
		t.Error("un salto recursivo deja la salida sin certeza aunque otro tenga interfaz")
	}
}

func TestRoutingOff(t *testing.T) {
	for name, want := range map[string]bool{
		"ios152_show-ip-route-l2":        true,
		"ios152_show-ip-route-norouting": true,
		"ios152_show-ip-route-host":      false,
		"iosxe_show-ip-route-connected":  false,
		"iosxe_show-ip-cef-host":         false,
		"ios152_show-ip-route-missing":   false,
	} {
		if got := RoutingOff(fx(t, name)); got != want {
			t.Errorf("%s = %v, quería %v", name, got, want)
		}
	}
	if RoutingOff("") {
		t.Error("vacío no dice nada")
	}
}
