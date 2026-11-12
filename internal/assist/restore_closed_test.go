package assist

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Escenarios de la revisión independiente de restore-diff: cada uno es un cambio del respaldo que la lista cerrada debe rechazar.

const reviewRunning = `Building configuration...

Current configuration : 4321 bytes
!
version 15.2
hostname SW1
!
ntp server 10.0.0.1
logging host 10.0.0.9
snmp-server location Lab
ip default-gateway 192.0.2.1
ip route 0.0.0.0 0.0.0.0 192.0.2.1
ip route 10.9.0.0 255.255.0.0 192.0.2.1
ip route vrf Mgmt 10.8.0.0 255.255.0.0 192.0.2.1
ipv6 route 2001:DB8:9::/48 2001:DB8::1
access-list 10 permit 10.0.0.0 0.0.0.255
access-list 10 permit 10.1.0.0 0.0.0.255
!
vrf definition Mgmt
 address-family ipv4
 exit-address-family
!
router bgp 65000
 neighbor 10.1.1.1 remote-as 65001
!
ip access-list extended EDGE
 permit tcp any any eq 22
!
route-map RM1 permit 10
 set metric 5
!
vlan 10
 name VENTAS
!
interface GigabitEthernet1/0/1
 description PC-ventas
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/2
 description libre
 switchport access vlan 10
 switchport mode access
 shutdown
!
interface GigabitEthernet1/0/3
 no switchport
 vrf forwarding Mgmt
 ip address 10.5.5.1 255.255.255.0
!
interface GigabitEthernet1/0/4
 switchport access vlan 10
 switchport mode access
!
interface GigabitEthernet1/0/5
 description sin-modo
!
interface GigabitEthernet1/0/22
 switchport mode trunk
 channel-group 1 mode active
!
interface GigabitEthernet1/0/23
 switchport trunk allowed vlan 1,99
 switchport mode trunk
!
interface GigabitEthernet1/0/24
 description UPLINK
 switchport access vlan 99
 switchport mode access
!
interface Port-channel1
 switchport mode trunk
!
interface Vlan10
 ip address 10.10.0.1 255.255.255.0
 ip access-group EDGE in
 standby 1 ip 10.10.0.254
!
interface Vlan99
 ip address 192.0.2.10 255.255.255.0
!
line vty 0 4
 access-class 10 in
 transport input ssh
!
end
`

const l2Route = "Default gateway is 192.0.2.254\n\nHost               Gateway           Last Use    Total Uses  Interface\nICMP redirect cache is empty\n"

// reviewOuts son las lecturas de Pre: la sesión del núcleo (192.0.2.9) entra por 192.0.2.10, la IP de Vlan99.
func reviewOuts(running string) map[string]string {
	return map[string]string{
		"show running-config": running,
		"show users": "    Line       User       Host(s)              Idle       Location\n" +
			"*  2 vty 0     admin      idle                 00:00:00 192.0.2.9\n",
		"show tcp brief": "TCB       Local Address               Foreign Address             (state)\n" +
			"7F1A2B3C  192.0.2.10.22               192.0.2.9.51234             ESTAB\n",
		"show version": "Processor board ID FOC0001A0AA\n",
		// Un switch con el enrutamiento apagado (sin `ip routing`) contesta así: no hay salida que proteger además de la IP local.
		"show ip route 192.0.2.9": l2Route,
		"show vlan brief": "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -----\n" +
			"1    default                          active    \n10   VENTAS                           active    \n20   VOZ                              active    \n99   GESTION                          active    \n",
	}
}

func reviewPlan(t *testing.T, backup string, mod func(*RestoreChange)) (RestorePlan, error) {
	t.Helper()
	c := RestoreChange{Backup: backup, BackupSerial: "FOC0001A0AA"}
	if mod != nil {
		mod(&c)
	}
	return RestoreDiffPlan("SW1", c, reviewOuts(reviewRunning))
}

func rep(s, old, new string) string {
	if !strings.Contains(s, old) {
		panic("el fixture no contiene " + old)
	}
	return strings.Replace(s, old, new, 1)
}

func closedCases() []struct{ name, backup, want string } {
	b := reviewRunning
	return []struct{ name, backup, want string }{
		{"uplink con la VLAN de gestión (apagar)", rep(b, "description UPLINK\n", "description UPLINK\n shutdown\n"), "gestión"},
		{"uplink con la VLAN de gestión (descripción)", rep(b, "description UPLINK", "description OTRO"), "gestión"},
		{"puerto que pasa a la VLAN de gestión", rep(b, "description PC-ventas\n switchport access vlan 10", "description PC-ventas\n switchport access vlan 99"), "gestión"},
		{"access-class de la vty", rep(b, "access-class 10 in", "access-class 11 in"), "line"},
		{"ip access-group de la SVI", rep(b, "ip access-group EDGE in", "ip access-group OTRA in"), "SVI"},
		{"no ip route", rep(b, "ip route 10.9.0.0 255.255.0.0 192.0.2.1\n", ""), "ruta"},
		{"no ip route vrf", rep(b, "ip route vrf Mgmt 10.8.0.0 255.255.0.0 192.0.2.1\n", ""), "ruta"},
		{"no ipv6 route", rep(b, "ipv6 route 2001:DB8:9::/48 2001:DB8::1\n", ""), "ruta"},
		{"ruta por omisión partida", rep(b, "ip route 0.0.0.0 0.0.0.0 192.0.2.1\n", "ip route 0.0.0.0 128.0.0.0 192.0.2.1\nip route 128.0.0.0 128.0.0.0 192.0.2.1\n"), "ruta"},
		{"cambio de vrf forwarding", rep(b, "vrf forwarding Mgmt", "vrf forwarding Otra"), "físico de acceso"},
		{"quitar una entrada de access-list N", rep(b, "access-list 10 permit 10.1.0.0 0.0.0.255\n", ""), "access-list"},
		{"cambio de remote-as", rep(b, "remote-as 65001", "remote-as 65002"), "router"},
		{"no switchport", rep(b, "interface GigabitEthernet1/0/4\n switchport access vlan 10\n switchport mode access", "interface GigabitEthernet1/0/4\n no switchport"), "físico de acceso"},
		{"standby authentication", rep(b, "standby 1 ip 10.10.0.254", "standby 1 ip 10.10.0.254\n standby 1 authentication LAB"), "standby"},
		{"abreviatura no ip rout", rep(b, "hostname SW1\n", "hostname SW1\nno ip rout 10.9.0.0 255.255.0.0\n"), "ruta"},
		{"abreviatura ip default-g", rep(b, "ip default-gateway 192.0.2.1", "ip default-g 192.0.2.77"), "ruta"},
		{"abreviatura ip ss ver 1", rep(b, "hostname SW1\n", "hostname SW1\nip ss ver 1\n"), "ip ssh"},
		{"abreviatura snmp-s comm", rep(b, "hostname SW1\n", "hostname SW1\nsnmp-s comm PUBLICA RO\n"), "secreto"},
		{"abreviatura lin vty", rep(b, "hostname SW1\n", "hostname SW1\nlin vty 5 15\n transport input all\n"), "line"},
		{"ACL extendida", rep(b, "permit tcp any any eq 22", "permit tcp any any eq 23"), "ACL"},
		{"route-map", rep(b, "set metric 5", "set metric 6"), "route-map"},
		{"nopassword", rep(b, "access-class 10 in", "access-class 10 in\n no password"), "line"},
		{"authentication", rep(b, "hostname SW1\n", "hostname SW1\nip ospf authentication message-digest\n"), "cambia cómo entra"},
		{"puerto sin switchport mode access", rep(b, "description sin-modo", "description otra"), "físico de acceso"},
		{"reload", rep(b, "hostname SW1\n", "hostname SW1\nreload\n"), "prohibido"},
	}
}

func TestRestoreClosedListRejectsEveryReviewerScenario(t *testing.T) {
	for _, tc := range closedCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, err := reviewPlan(t, tc.backup, nil)
			if !errors.Is(err, ErrRestoreRefused) {
				t.Fatalf("debía rechazarse: err=%v apply=%q", err, p.Device.Apply)
			}
			var all []string
			for _, r := range p.Refused {
				all = append(all, strings.ToLower(r.Path+" | "+r.Line+" | "+r.Why))
			}
			if len(all) == 0 || !strings.Contains(strings.Join(all, "\n"), strings.ToLower(tc.want)) {
				t.Errorf("la lista %q debía mencionar %q", all, tc.want)
			}
			// En parcial tampoco se aplica nada de eso.
			pp, err := reviewPlan(t, tc.backup, func(c *RestoreChange) { c.Partial = true })
			if err == nil && len(pp.Device.Apply) > 0 {
				t.Errorf("en parcial no debe quedar nada aplicable: %q", pp.Device.Apply)
			}
		})
	}
}

func TestRestoreSameHostnameOnAnotherDeviceIsRefused(t *testing.T) {
	b := rep(reviewRunning, "description PC-ventas", "description PC-otro")
	if _, err := reviewPlan(t, b, nil); err != nil {
		t.Fatalf("el mismo equipo debe poder restaurarse: %v", err)
	}
	for name, mod := range map[string]func(*RestoreChange){
		"otra serie":      func(c *RestoreChange) { c.BackupSerial = "FOC9999Z9ZZ" },
		"ficha sin serie": func(c *RestoreChange) { c.BackupSerial = "" },
	} {
		if _, err := reviewPlan(t, b, mod); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "serie") {
			t.Errorf("%s: mismo hostname no basta, la serie debe coincidir: %v", name, err)
		}
	}
}

func TestRestoreBackupMustBeCompleteAndEndWithEnd(t *testing.T) {
	b := rep(reviewRunning, "description PC-ventas", "description PC-otro")
	cut := strings.TrimSuffix(b, "end\n")
	if _, err := reviewPlan(t, cut, nil); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "end") {
		t.Fatalf("un respaldo sin end está cortado: %v", err)
	}
	if _, err := reviewPlan(t, b, func(c *RestoreChange) { c.BackupTruncated = true }); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "recortado") {
		t.Fatalf("un respaldo marcado como recortado se rechaza: %v", err)
	}
	// Las cabeceras de IOS no son configuración: con ellas el plan sale igual que sin ellas.
	with := "Using 4321 out of 524288 bytes\n" + b
	p1, e1 := reviewPlan(t, with, nil)
	p2, e2 := reviewPlan(t, b, nil)
	if e1 != nil || e2 != nil || !slices.Equal(p1.Device.Apply, p2.Device.Apply) {
		t.Fatalf("las cabeceras se ignoran: %v %v %q %q", e1, e2, p1.Device.Apply, p2.Device.Apply)
	}
}
