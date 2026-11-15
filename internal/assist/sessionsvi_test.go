package assist

import (
	"errors"
	"strings"
	"testing"
)

// show users con la sesión SSH viniendo de 10.20.0.50.
const sviUsers = "    Line       User       Host(s)              Idle       Location\n   0 con 0                idle                 00:00:00\n*  2 vty 0     admin      idle                 00:00:00 10.20.0.50\n"

func TestSVIPlanRefusesSubnetOfTheSession(t *testing.T) {
	brief := "Vlan1                  unassigned      YES unset  up                    down\n"
	mk := func() map[string]string {
		o := sviOuts(noIface, brief)
		o[showUsersCmd] = sviUsers
		return o
	}
	// La sesión viene de 10.20.0.50: una SVI cuya subred la contiene se traga el regreso.
	_, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.20.0.1", Mask: "255.255.255.0"}, mk())
	if !errors.Is(err, ErrSnippetRefused) || !strings.Contains(err.Error(), "10.20.0.0/24") {
		t.Errorf("subred de la sesión: %v", err)
	}
	if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.30.0.1", Mask: "255.255.255.0"}, mk()); err != nil {
		t.Errorf("otra subred: %v", err)
	}
	// Una más ancha que la contiene también se rechaza.
	if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.20.1.1", Mask: "255.255.0.0"}, mk()); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("/16: %v", err)
	}
	// Una SVI que ya tiene IP (el cambio de IP de la SVI de gestión) no la toca esta plantilla.
	cur := cfgOf("Vlan99", "ip address 10.20.0.1 255.255.255.0")
	o := sviOuts(cur, "Vlan99                 10.20.0.1       YES manual up                    up\n")
	o[showCfg("Vlan99")] = cur
	o[showUsersCmd] = sviUsers
	if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.20.0.9", Mask: "255.255.255.0"}, o); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("SVI con IP: %v", err)
	}
	// Sin show users no se supone el origen.
	o = sviOuts(noIface, brief)
	delete(o, showUsersCmd)
	if _, err := SVIPlan("SW1", SVIChange{VlanID: 99, Address: "10.30.0.1", Mask: "255.255.255.0"}, o); !errors.Is(err, ErrSnippetRefused) {
		t.Errorf("sin show users: %v", err)
	}
}
