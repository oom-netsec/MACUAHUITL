package iosconf

import (
	"strings"
	"testing"
)

const sample = `Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:15:32 UTC Tue Nov 3 2026 by admin
!
version 17.9
service password-encryption
hostname SW-LAB-01
!
interface GigabitEthernet1/0/1
 description enlace  a  core
 switchport mode trunk
!
interface Vlan10
 ip address 192.0.2.1 255.255.255.0
 standby 10 ip 192.0.2.3
!
router ospf 1
 router-id 192.0.2.1
 address-family ipv4
  network 192.0.2.0 0.0.0.255 area 0
 exit-address-family
!
banner motd ^C
Acceso solo autorizado.
line vty 0 15
^C
macro name ACCESO
switchport mode access
spanning-tree portfast
@
line vty 0 15
 exec-timeout 5 0
 transport input ssh
!
end
`

func TestParseHierarchy(t *testing.T) {
	root := Parse(sample)
	var top []string
	for _, n := range root.Children {
		top = append(top, n.Line)
	}
	want := []string{"version 17.9", "service password-encryption", "hostname SW-LAB-01", "interface GigabitEthernet1/0/1",
		"interface Vlan10", "router ospf 1", "banner motd ^C", "macro name ACCESO", "line vty 0 15"}
	if strings.Join(top, "|") != strings.Join(want, "|") {
		t.Fatalf("top = %q", top)
	}
	gi := root.Find(`interface GigabitEthernet1/0/1`)
	if len(gi) != 1 || len(gi[0].Children) != 2 || gi[0].Children[0].Line != "description enlace a core" {
		t.Fatalf("gi = %+v", gi)
	}
	ospf := root.Find(`router ospf \d+`)[0]
	af := ospf.Find(`address-family ipv4`)
	if len(af) != 1 || len(af[0].Children) != 1 || af[0].Children[0].Line != "network 192.0.2.0 0.0.0.255 area 0" {
		t.Fatalf("af = %+v", af)
	}
	if af[0].Parent != ospf || ospf.Parent != root {
		t.Fatal("parents")
	}
	if gi[0].Num != 11 {
		t.Fatalf("line number = %d", gi[0].Num)
	}
}

func TestBannerAndMacroBodiesAreOpaque(t *testing.T) {
	root := Parse(sample)
	b := root.Find(`banner motd .*`)
	if len(b) != 1 || !strings.Contains(b[0].Body, "Acceso solo autorizado.") || len(b[0].Children) != 0 {
		t.Fatalf("banner = %+v", b)
	}
	// La línea "line vty 0 15" dentro del banner no es una sección.
	if n := len(root.Find(`line vty 0 15`)); n != 1 {
		t.Fatalf("line vty sections = %d", n)
	}
	m := root.Find(`macro name ACCESO`)
	if len(m) != 1 || !strings.Contains(m[0].Body, "spanning-tree portfast") {
		t.Fatalf("macro = %+v", m)
	}
	if len(root.Find(`spanning-tree portfast`)) != 0 {
		t.Fatal("macro body leaked")
	}
}

func TestSingleLineBannerAndUnterminated(t *testing.T) {
	root := Parse("banner login #Solo personal#\nhostname X\nbanner exec ^C\nsin cierre\n")
	if len(root.Children) != 3 || root.Children[1].Line != "hostname X" {
		t.Fatalf("children = %+v", root.Children)
	}
	if !strings.Contains(root.Children[2].Body, "sin cierre") {
		t.Fatalf("unterminated banner = %+v", root.Children[2])
	}
}

func TestFindAnchorsAndWalk(t *testing.T) {
	root := Parse("ip http server\nip http secure-server\nno ip http server\n")
	if n := len(root.Find(`ip http server`)); n != 1 {
		t.Fatalf("anchored find = %d", n)
	}
	if n := len(root.Find(`(no )?ip http server`)); n != 2 {
		t.Fatalf("find = %d", n)
	}
	count := 0
	Parse(sample).Walk(func(*Node) { count++ })
	if count < 15 {
		t.Fatalf("walk visited %d", count)
	}
}

func TestDedentToSiblingOfAncestor(t *testing.T) {
	root := Parse("a\n b\n  c\n d\ne\n")
	if len(root.Children) != 2 || len(root.Children[0].Children) != 2 || root.Children[0].Children[1].Line != "d" {
		t.Fatalf("tree = %s", root.String())
	}
}

func TestCRLFAndTabs(t *testing.T) {
	root := Parse("interface Gi1\r\n\tshutdown\r\n")
	if len(root.Children) != 1 || len(root.Children[0].Children) != 1 || root.Children[0].Children[0].Line != "shutdown" {
		t.Fatalf("tree = %s", root.String())
	}
}

func TestPathAndBadPattern(t *testing.T) {
	root := Parse(sample)
	n := root.Find(`router ospf 1`)[0].Find(`address-family ipv4`)[0].Children[0]
	if got := n.Path(); got != "router ospf 1 > address-family ipv4 > network 192.0.2.0 0.0.0.255 area 0" {
		t.Fatalf("path = %q", got)
	}
	if _, err := Compile("("); err == nil {
		t.Fatal("bad regexp accepted")
	}
}
