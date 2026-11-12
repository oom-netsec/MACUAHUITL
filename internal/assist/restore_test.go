package assist

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func mustPlan(t *testing.T, backup string, mod func(*RestoreChange)) RestorePlan {
	t.Helper()
	p, err := reviewPlan(t, backup, mod)
	if err != nil {
		t.Fatalf("el plan debía armarse: %v (rechazado: %v)", err, p.Refused)
	}
	return p
}

// changedBackup difiere del running en: logging host (quitado), ntp server (otro), descripción y VLAN de Gi1/0/1, y Gi1/0/2 sin shutdown.
func changedBackup() string {
	b := rep(reviewRunning, "logging host 10.0.0.9\n", "")
	b = rep(b, "ntp server 10.0.0.1", "ntp server 10.0.0.2")
	b = rep(b, "description PC-ventas\n switchport access vlan 10", "description PC-contabilidad\n switchport access vlan 20")
	return rep(b, " switchport mode access\n shutdown\n", " switchport mode access\n")
}

func TestRestoreDiffBuildsApplyAndInverseRollback(t *testing.T) {
	p := mustPlan(t, changedBackup(), nil)
	// Agrega antes de quitar, una línea de un solo valor sin `no` previo, shutdown primero y no shutdown al final.
	wantApply := []string{
		"ntp server 10.0.0.2", "no ntp server 10.0.0.1", "no logging host 10.0.0.9",
		"interface GigabitEthernet1/0/1", "description PC-contabilidad", "switchport access vlan 20",
		"interface GigabitEthernet1/0/2", "no shutdown",
	}
	wantRoll := []string{
		"ntp server 10.0.0.1", "logging host 10.0.0.9", "no ntp server 10.0.0.2",
		"interface GigabitEthernet1/0/1", "description PC-ventas", "switchport access vlan 10",
		"interface GigabitEthernet1/0/2", "shutdown",
	}
	if !slices.Equal(p.Device.Apply, wantApply) {
		t.Errorf("Apply = %q\nquería %q", p.Device.Apply, wantApply)
	}
	if !slices.Equal(p.Device.Rollback, wantRoll) {
		t.Errorf("Rollback = %q\nquería %q", p.Device.Rollback, wantRoll)
	}
	if !slices.Equal(p.Device.Pre, RestoreDiffPre()) || !slices.Equal(p.Device.Post, []string{"show running-config"}) {
		t.Errorf("Pre/Post = %q / %q", p.Device.Pre, p.Device.Post)
	}
	if p.Device.Baseline["show running-config"] != reviewRunning {
		t.Error("la línea base debe ser el running-config capturado")
	}
	if err := Validate(Plan{Function: p.Fn.Name, Devices: []DevicePlan{p.Device}}, p.Fn); err != nil {
		t.Errorf("el plan armado debe validar: %v", err)
	}
}

func TestRestoreOrderShutdownFirstNoShutdownLastAndNoNoForSingles(t *testing.T) {
	// Gi1/0/1 se apaga y cambia de descripción y VLAN; Gi1/0/2 se enciende y cambia la descripción.
	b := rep(reviewRunning, "description PC-ventas\n switchport access vlan 10", "description otra\n switchport access vlan 20\n shutdown")
	b = rep(b, "description libre\n switchport access vlan 10\n switchport mode access\n shutdown", "description nueva\n switchport access vlan 10\n switchport mode access")
	p := mustPlan(t, b, nil)
	i := slices.Index(p.Device.Apply, "interface GigabitEthernet1/0/1")
	if got := p.Device.Apply[i : i+5]; !slices.Equal(got, []string{"interface GigabitEthernet1/0/1", "shutdown", "description otra", "switchport access vlan 20", "interface GigabitEthernet1/0/2"}) {
		t.Errorf("shutdown va primero: %q", p.Device.Apply)
	}
	if got := p.Device.Apply[len(p.Device.Apply)-2:]; !slices.Equal(got, []string{"description nueva", "no shutdown"}) {
		t.Errorf("no shutdown va al final de su interfaz: %q", p.Device.Apply)
	}
	for _, l := range append(slices.Clone(p.Device.Apply), p.Device.Rollback...) {
		if strings.HasPrefix(l, "no description") || strings.HasPrefix(l, "no switchport access vlan") {
			t.Errorf("la sustitución de un valor no pasa por %q", l)
		}
	}
}

func TestRestoreRejectsMaskedBackup(t *testing.T) {
	_, err := reviewPlan(t, changedBackup(), func(c *RestoreChange) { c.BackupMasked = true })
	if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "enmascar") {
		t.Fatalf("un respaldo enmascarado se rechaza con un mensaje claro: %v", err)
	}
	// Aunque la ficha diga que no, un texto con marcas de enmascarado tampoco sirve.
	masked := rep(changedBackup(), "set metric 5", "set metric <MASKED:x>")
	if _, err := reviewPlan(t, masked, nil); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "enmascar") {
		t.Fatalf("el texto con <MASKED:...> se rechaza: %v", err)
	}
}

func TestRestoreRefusesOtherDevicesBackup(t *testing.T) {
	other := rep(changedBackup(), "hostname SW1", "hostname SW2")
	if _, err := reviewPlan(t, other, nil); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "SW2") {
		t.Fatalf("un respaldo de otro equipo se rechaza: %v", err)
	}
	if _, err := reviewPlan(t, rep(changedBackup(), "hostname SW1", "hostname sw1"), nil); !errors.Is(err, ErrRestoreRefused) {
		t.Fatalf("el hostname es el mismo solo si es idéntico: %v", err)
	}
	if _, err := reviewPlan(t, rep(changedBackup(), "hostname SW1\n", ""), nil); !errors.Is(err, ErrRestoreRefused) {
		t.Fatalf("sin hostname no se puede comprobar que sea el mismo equipo: %v", err)
	}
}

func TestRestoreNoDifference(t *testing.T) {
	if _, err := reviewPlan(t, reviewRunning, nil); !errors.Is(err, ErrNoDifference) {
		t.Fatalf("sin diferencias = ErrNoDifference: %v", err)
	}
}

// refusalCases: cada cambio del diff que la lista cerrada rechaza, con el texto que lo provoca.
func refusalCases() []struct{ name, backup, want string } {
	g := func(line string) string { return rep(reviewRunning, "hostname SW1\n", "hostname SW1\n"+line+"\n") }
	return []struct{ name, backup, want string }{
		{"crypto", g("crypto key generate rsa"), "crypto"},
		{"crypto pki", g("crypto pki trustpoint T1\n enrollment selfsigned"), "crypto"},
		{"username nuevo", g("username tech privilege 1 secret 9 $9$qqq"), "username"},
		{"enable secret", g("enable secret 9 $9$ppp"), "enable"},
		{"aaa", g("aaa new-model"), "aaa"},
		{"boot", g("boot system flash:c3560cx.bin"), "boot"},
		{"config-register", g("config-register 0x2102"), "config-register"},
		{"license", g("license boot level ipservices"), "license"},
		{"banner", g("banner motd ^C\nSolo personal autorizado\n^C"), "banner"},
		{"vtp", g("vtp mode client"), "vtp"},
		{"ip ssh", g("ip ssh version 1"), "ip ssh"},
		{"ruta por omisión en vrf", g("ip route vrf Mgmt 0.0.0.0 0.0.0.0 192.0.2.1"), "ruta"},
		{"snmp community", g("snmp-server community SECRETA RO"), "secreto"},
		{"tacacs key", g("tacacs-server key 7 0822455D0A16"), "secreto"},
		{"router nuevo", g("router ospf 1\n network 10.0.0.0 0.0.0.255 area 0"), "router"},
		{"interfaz nueva", g("interface Loopback9\n ip address 9.9.9.9 255.255.255.255"), "interfaz"},
		{"vlan que el respaldo no tiene", rep(reviewRunning, "vlan 10\n name VENTAS\n!\n", ""), "vlan"},
		{"vlan nueva", g("vlan 50\n name NUEVA"), "vlan"},
		{"no ascii", rep(changedBackup(), "PC-contabilidad", "PC-contabilidad-Ñ"), "ASCII"},
		{"ntp con vrf", rep(changedBackup(), "ntp server 10.0.0.2", "ntp server vrf Mgmt 10.0.0.2"), "vrf"},
		{"logging source-interface inexistente", g("logging source-interface Vlan77"), "interfaz"},
		{"voz en una VLAN que no existe", rep(reviewRunning, "description PC-ventas", "description PC-ventas\n switchport voice vlan 77"), "VLAN"},
		{"puerto de acceso a una VLAN que no existe", rep(reviewRunning, "description PC-ventas\n switchport access vlan 10", "description PC-ventas\n switchport access vlan 77"), "VLAN"},
		{"spanning-tree mode con no", g("no spanning-tree mode"), "spanning-tree"},
		{"spanning-tree mode (reconverge todo, el uplink incluido)", g("spanning-tree mode rapid-pvst"), "reconverge"},
		{"spanning-tree mode mst", g("spanning-tree mode mst"), "reconverge"},
		{"spanning-tree extend system-id", g("spanning-tree extend system-id"), "reconverge"},
		{"abreviatura de lo permitido", g("logg host 10.9.9.9"), "abreviatura"},
		{"global que no está en la lista", g("ip http server"), "lista cerrada"},
		{"línea de interfaz que no está en la lista", rep(changedBackup(), "description PC-contabilidad", "description PC-contabilidad\n switchport port-security maximum 3"), "lista cerrada"},
		{"name-server con vrf", g("ip name-server vrf Mgmt 10.1.1.1"), "nombra una vrf"},
	}
}

func TestRestoreRefusalListRejectsThePlan(t *testing.T) {
	for _, tc := range refusalCases() {
		t.Run(tc.name, func(t *testing.T) {
			p, err := reviewPlan(t, tc.backup, nil)
			if !errors.Is(err, ErrRestoreRefused) {
				t.Fatalf("debía rechazarse: err=%v apply=%q", err, p.Device.Apply)
			}
			var all []string
			for _, r := range p.Refused {
				all = append(all, strings.ToLower(r.Path+" | "+r.Line+" | "+r.Why))
			}
			if !strings.Contains(strings.Join(all, "\n"), strings.ToLower(tc.want)) {
				t.Errorf("la lista %q debía mencionar %q", all, tc.want)
			}
		})
	}
}

func TestRestoreRefusedLinesNeverCarrySecrets(t *testing.T) {
	b := rep(reviewRunning, "hostname SW1\n", "hostname SW1\nusername tech privilege 1 secret 9 $9$qqqSECRETO\nsnmp-server community COMUNIDAD42 RO\ntacacs-server key 7 0822455D0A16\nntp authentication-key 1 md5 CLAVENTP\n")
	p, err := reviewPlan(t, b, nil)
	if !errors.Is(err, ErrRestoreRefused) || len(p.Refused) < 4 {
		t.Fatalf("%v %v", err, p.Refused)
	}
	for _, r := range p.Refused {
		for _, s := range []string{"qqqSECRETO", "COMUNIDAD42", "0822455D0A16", "CLAVENTP"} {
			if strings.Contains(r.Path+r.Line+r.Why, s) {
				t.Errorf("lo rechazado lleva un secreto (%s): %+v", s, r)
			}
		}
	}
}

func TestRestorePartialAppliesOnlyWhatIsAllowed(t *testing.T) {
	// Un cambio permitido y, mezclados, una ACL, un route-map y una interfaz con la VLAN de gestión.
	b := rep(changedBackup(), "permit tcp any any eq 22", "permit tcp any any eq 23")
	b = rep(b, "set metric 5", "set metric 6")
	b = rep(b, "description UPLINK", "description UPLINK2")
	p, err := reviewPlan(t, b, func(c *RestoreChange) { c.Partial = true })
	if err != nil {
		t.Fatalf("en modo parcial el resto se arma: %v", err)
	}
	var refused []string
	for _, r := range p.Refused {
		refused = append(refused, r.Path+" | "+r.Line)
	}
	for _, want := range []string{"ip access-list extended EDGE", "route-map RM1 permit 10", "GigabitEthernet1/0/24"} {
		if !strings.Contains(strings.Join(refused, "\n"), want) {
			t.Errorf("lo rechazado debe listar %q: %q", want, refused)
		}
	}
	for _, l := range p.Device.Apply {
		if strings.Contains(l, "EDGE") || strings.Contains(l, "metric") || strings.Contains(l, "UPLINK") || strings.Contains(l, "1/0/24") {
			t.Errorf("lo rechazado no debe estar en el Apply: %q", l)
		}
	}
	if !slices.Contains(p.Device.Apply, "ntp server 10.0.0.2") {
		t.Errorf("lo permitido sí se aplica: %q", p.Device.Apply)
	}
}

func TestRestorePartialRejectsAllowedLinesThatNameSomethingRejected(t *testing.T) {
	// La VLAN 50 solo está en el respaldo (sección rechazada) y Gi1/0/1 pasa a ella: la línea es de un puerto de acceso, pero nombra algo rechazado.
	b := rep(changedBackup(), "vlan 10\n name VENTAS\n!", "vlan 10\n name VENTAS\n!\nvlan 50\n name NUEVA\n!")
	b = rep(b, "switchport access vlan 20", "switchport access vlan 50")
	c := RestoreChange{Backup: b, BackupSerial: "FOC0001A0AA", Partial: true}
	outs := reviewOuts(reviewRunning)
	outs["show vlan brief"] += "50   NUEVA                            active    \n" // el equipo ya la tiene activa, pero su sección es lo rechazado
	p, err := RestoreDiffPlan("SW1", c, outs)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Contains(p.Device.Apply, "switchport access vlan 50") {
		t.Errorf("no debe nombrar la VLAN rechazada: %q", p.Device.Apply)
	}
	if !strings.Contains(fmtRefused(p), "vlan 50") {
		t.Errorf("la VLAN 50 se lista: %v", p.Refused)
	}
}

func fmtRefused(p RestorePlan) string {
	var b strings.Builder
	for _, r := range p.Refused {
		b.WriteString(r.Path + " | " + r.Line + " | " + r.Why + "\n")
	}
	return b.String()
}

func TestRestoreManagementIsIdentifiedFromTheSessionAndNeverTouched(t *testing.T) {
	run := func(mod func(map[string]string), c func(*RestoreChange)) error {
		outs := reviewOuts(reviewRunning)
		if mod != nil {
			mod(outs)
		}
		ch := RestoreChange{Backup: changedBackup(), BackupSerial: "FOC0001A0AA"}
		if c != nil {
			c(&ch)
		}
		_, err := RestoreDiffPlan("SW1", ch, outs)
		return err
	}
	if err := run(nil, nil); err != nil {
		t.Fatalf("la sesión identifica Vlan99: %v", err)
	}
	// Sin sesión identificable, o con varias IP locales, no se restaura nada sin --mgmt-if.
	for name, mod := range map[string]func(map[string]string){
		"sin show users":     func(o map[string]string) { o["show users"] = "" },
		"sin show tcp brief": func(o map[string]string) { o["show tcp brief"] = "" },
		"origen que no se ve": func(o map[string]string) {
			o["show tcp brief"] = "TCB Local Foreign (state)\n7F 192.0.2.10.22 198.51.100.1.4000 ESTAB\n"
		},
		"dos IP locales": func(o map[string]string) { o["show tcp brief"] += "7F2  10.10.0.1.23  192.0.2.9.40000 ESTAB\n" },
		"IP que ninguna lleva": func(o map[string]string) {
			o["show tcp brief"] = strings.Replace(o["show tcp brief"], "192.0.2.10.22", "203.0.113.7.22", 1)
		},
	} {
		if err := run(mod, nil); !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "gestión") {
			t.Errorf("%s: sin saber por dónde estás conectado no se restaura nada: %v", name, err)
		}
	}
	// Indicada a mano.
	if err := run(func(o map[string]string) { o["show users"] = "" }, func(c *RestoreChange) { c.Management = "vlan99" }); err != nil {
		t.Errorf("--mgmt-if basta: %v", err)
	}
	if err := run(nil, func(c *RestoreChange) { c.Management = "Vlan77" }); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("una interfaz que no existe: %v", err)
	}
	// El puerto indicado y la VLAN que lleva también son intocables.
	b := rep(changedBackup(), "description UPLINK", "description OTRO")
	for _, mg := range []string{"", "gi1/0/24"} {
		_, err := reviewPlan(t, b, func(c *RestoreChange) { c.Management = mg })
		if !errors.Is(err, ErrRestoreRefused) {
			t.Errorf("el puerto con la VLAN de gestión no se toca (mgmt-if=%q): %v", mg, err)
		}
	}
}

func TestRestoreLineCap(t *testing.T) {
	_, err := reviewPlan(t, changedBackup(), func(c *RestoreChange) { c.MaxLines = 5 })
	if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(err.Error(), "tope") {
		t.Fatalf("más líneas que el tope = rechazo: %v", err)
	}
	if _, err := reviewPlan(t, changedBackup(), func(c *RestoreChange) { c.MaxLines = 6 }); err != nil {
		t.Errorf("justo en el tope pasa: %v", err)
	}
	if _, err := reviewPlan(t, changedBackup(), func(c *RestoreChange) { c.MaxLines = MaxRestoreLines + 1 }); !errors.Is(err, ErrRestoreRefused) {
		t.Errorf("el tope pedido tiene un máximo: %v", err)
	}
}

// forged valida un plan armado a mano sobre la línea base del fixture.
func forged(t *testing.T, apply, rollback []string, expect []Expect) error {
	t.Helper()
	p := mustPlan(t, changedBackup(), nil)
	d := p.Device
	d.Apply, d.Rollback = apply, rollback
	if expect != nil {
		d.Expect = expect
	}
	return Validate(Plan{Function: p.Fn.Name, Devices: []DevicePlan{d}}, p.Fn)
}

func TestRestoreCheckDeviceRejectsEverythingOutsideTheClosedList(t *testing.T) {
	p := mustPlan(t, changedBackup(), nil)
	// Un plan que llegue por otro camino (sin pasar por el diff) se rechaza línea por línea: cada una es una fuga que halló la revisión.
	for name, apply := range map[string][]string{
		"shutdown del uplink con la VLAN de gestión": {"interface GigabitEthernet1/0/24", "shutdown"},
		"SVI de gestión":              {"interface Vlan99", "shutdown"},
		"SVI con ip access-group":     {"interface Vlan10", "no ip access-group EDGE in"},
		"access-class de la vty":      {"line vty 0 4", "no access-class 10 in"},
		"no ip route":                 {"no ip route 10.9.0.0 255.255.0.0 192.0.2.1"},
		"no ip route abreviado":       {"no ip rout 10.9.0.0 255.255.0.0 192.0.2.1"},
		"ruta por omisión abreviada":  {"no ip default-g 192.0.2.1"},
		"no ipv6 route":               {"no ipv6 route 2001:DB8:9::/48 2001:DB8::1"},
		"entrada de access-list":      {"no access-list 10 permit 10.1.0.0 0.0.0.255"},
		"remote-as":                   {"router bgp 65000", "no neighbor 10.1.1.1 remote-as 65001"},
		"no switchport":               {"interface GigabitEthernet1/0/4", "no switchport"},
		"vrf forwarding":              {"interface GigabitEthernet1/0/3", "no vrf forwarding Mgmt"},
		"trunk":                       {"interface GigabitEthernet1/0/23", "switchport trunk allowed vlan 1"},
		"channel-group":               {"interface GigabitEthernet1/0/22", "no channel-group 1 mode active"},
		"puerto a la VLAN de gestión": {"interface GigabitEthernet1/0/4", "switchport access vlan 99"},
		"hostname con no":             {"no hostname SW1"},
		"reload":                      {"reload"},
		"spanning-tree mode":          {"spanning-tree mode mst"},
		"extend system-id":            {"spanning-tree extend system-id"},
		"interfaz completa":           {"no interface GigabitEthernet1/0/9"},
	} {
		if err := forged(t, apply, p.Device.Rollback, nil); err == nil {
			t.Errorf("%s: %q debía rechazarse", name, apply)
		}
	}
	// Y la reversa también.
	if err := forged(t, p.Device.Apply, []string{"interface GigabitEthernet1/0/24", "shutdown"}, nil); err == nil {
		t.Error("una reversa que toca el uplink de gestión tampoco")
	}
}

func TestRestoreCheckDeviceDemandsExactInverseAndAFullPostCheck(t *testing.T) {
	p := mustPlan(t, changedBackup(), nil)
	if err := forged(t, p.Device.Apply, p.Device.Rollback[:len(p.Device.Rollback)-1], nil); err == nil {
		t.Error("una reversa a la que le falta una línea no devuelve el equipo a su estado")
	}
	if err := forged(t, p.Device.Apply, append(slices.Clone(p.Device.Rollback[:1]), "logging host 10.9.9.9"), nil); err == nil {
		t.Error("una reversa con otra línea tampoco")
	}
	// Sin la comparación de sección completa el post-check queda corto.
	short := slices.DeleteFunc(slices.Clone(p.Device.Expect), func(e Expect) bool { return e.Column == "section-hash" })
	if err := forged(t, p.Device.Apply, p.Device.Rollback, short); err == nil || !strings.Contains(err.Error(), "completa") {
		t.Errorf("el Expect debe comparar cada sección tocada completa: %v", err)
	}
	// Un apply que repite una línea no cambia nada, y el aviso lo explica.
	err := forged(t, []string{"ntp server 10.0.0.1", "ntp server 10.0.0.1"}, []string{"ntp server 10.0.0.1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "repite") {
		t.Errorf("el aviso debe explicar la línea repetida: %v", err)
	}
	// El tope también lo exige la función del plan, no solo quien lo arma.
	rc := &rctx{mgIfaces: map[string]bool{"vlan99": true}, mgVlans: map[string]bool{"99": true}, live: map[string]bool{"10": true, "20": true}, ifs: map[string]bool{}, max: 3}
	if err := Validate(Plan{Function: RestoreDiff, Devices: []DevicePlan{p.Device}}, restoreFn(rc)); err == nil || !strings.Contains(err.Error(), "tope") {
		t.Errorf("un plan más largo que el tope de su función no valida: %v", err)
	}
	// El motor ya no tiene un «acepta todo»: la función tiene lista de prefijos.
	if len(p.Fn.Allowed) == 0 || !p.Fn.Scrub {
		t.Errorf("la función lleva su lista cerrada y Scrub: %+v", p.Fn.Allowed)
	}
}

func TestRestoreExpectComparesTheWholeSection(t *testing.T) {
	p := mustPlan(t, changedBackup(), nil)
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": changedBackup()}); len(f) != 0 {
		t.Errorf("el running igual al respaldo cumple lo esperado: %v", f)
	}
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": reviewRunning}); len(f) == 0 {
		t.Error("el running sin cambiar no cumple")
	}
	// Una línea sin aplicar en el diff falla, y el motivo dice dónde.
	partial := rep(changedBackup(), "description PC-contabilidad", "description PC-ventas")
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": partial}); len(f) == 0 || !strings.Contains(strings.Join(f, ";"), "GigabitEthernet1/0/1") {
		t.Errorf("fallos = %v", f)
	}
	// Una línea EXTRA en una sección tocada, que no es del diff, también falla (IOS agregó algo, o el apply arrastró otra cosa).
	extra := rep(changedBackup(), "description PC-contabilidad\n", "description PC-contabilidad\n storm-control broadcast level 50\n")
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": extra}); len(f) == 0 || !strings.Contains(strings.Join(f, ";"), "GigabitEthernet1/0/1") {
		t.Errorf("una línea de más en la sección tocada debe fallar: %v", f)
	}
	// Lo mismo con la sección global: una línea suya que cambió sola.
	glob := rep(changedBackup(), "snmp-server location Lab", "snmp-server location Otro")
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": glob}); len(f) == 0 || !strings.Contains(strings.Join(f, ";"), "global") {
		t.Errorf("la sección global se compara completa: %v", f)
	}
	// Una sección que el plan no toca no afecta (Gi1/0/4 cambió sola): el plan no responde por ella.
	other := rep(changedBackup(), "interface GigabitEthernet1/0/4\n switchport access vlan 10", "interface GigabitEthernet1/0/4\n switchport access vlan 20")
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": other}); len(f) != 0 {
		t.Errorf("secciones no tocadas no cuentan: %v", f)
	}
	// Los comentarios, el reloj de NTP y la cabecera de tamaño no cuentan.
	noisy := "Using 4000 out of 524288 bytes\n! Last configuration change at 10:00\n" + rep(changedBackup(), "ntp server 10.0.0.2", "ntp server 10.0.0.2\nntp clock-period 17179869")
	if f := EvalExpect(p.Device.Expect, map[string]string{"show running-config": noisy}); len(f) != 0 {
		t.Errorf("el ruido que cambia solo no debe fallar: %v", f)
	}
}

func TestRestoreExpectForNegatedLines(t *testing.T) {
	// IOS conserva `no service timestamps debug ...` en el running (la familia es de un solo valor con forma `no`): el cambio entre las dos formas
	// se manda sin pasar por un `no` de más y el Expect distingue la línea negada de la positiva.
	const pos, neg = "service timestamps debug datetime msec", "no service timestamps debug datetime msec"
	run := rep(reviewRunning, "ntp server 10.0.0.1\n", "ntp server 10.0.0.1\n"+neg+"\n")
	back := rep(reviewRunning, "ntp server 10.0.0.1\n", "ntp server 10.0.0.1\n"+pos+"\n")
	p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, reviewOuts(run))
	if err != nil {
		t.Fatal(err)
	}
	// La línea `no ...` se quita al mandar la positiva, y se espera que `no ...` ya no esté (no que la positiva esté ausente).
	if !slices.Equal(p.Device.Apply, []string{pos}) {
		t.Fatalf("Apply = %q", p.Device.Apply)
	}
	for _, e := range p.Device.Expect {
		if e.Column == "section-line" && e.Line == pos && !e.Present {
			t.Errorf("no se debe esperar la ausencia de la línea positiva: %+v", e)
		}
	}
	if !slices.ContainsFunc(p.Device.Expect, func(e Expect) bool { return e.Column == "section-line" && e.Line == neg && !e.Present }) {
		t.Errorf("debe esperar que `%s` ya no esté: %+v", neg, p.Device.Expect)
	}
	// Al revés: el respaldo trae la forma `no`; se espera la línea negada presente y la positiva ausente.
	p, err = RestoreDiffPlan("SW1", RestoreChange{Backup: run, BackupSerial: "FOC0001A0AA"}, reviewOuts(back))
	if err != nil {
		t.Fatal(err)
	}
	var present, absent bool
	for _, e := range p.Device.Expect {
		present = present || e.Column == "section-line" && e.Line == neg && e.Present
		absent = absent || e.Column == "section-line" && e.Line == pos && !e.Present
	}
	if !present || !absent {
		t.Errorf("Expect de una línea `no X` agregada: presente=%v ausente=%v %+v", present, absent, p.Device.Expect)
	}
}

func TestRestoreSimulationRoundTripsEveryPlan(t *testing.T) {
	// Para cada respaldo posible armado quitando una línea del fixture, o el plan se rechaza o la reversa deja el running como estaba.
	lines := strings.Split(changedBackup(), "\n")
	base := stateOf(parseCfg(reviewRunning))
	for i := range lines {
		back := strings.Join(append(slices.Clone(lines[:i]), lines[i+1:]...), "\n")
		p, err := reviewPlan(t, back, func(c *RestoreChange) { c.Partial = true })
		if err != nil {
			continue
		}
		after, _, e1 := simulate(base, p.Device.Apply)
		back2, _, e2 := simulate(after, p.Device.Rollback)
		if e1 != nil || e2 != nil || back2.canon() != base.canon() {
			t.Errorf("sin la línea %d (%q) la reversa no es exacta: %v %v\napply=%q\nrollback=%q", i, lines[i], e1, e2, p.Device.Apply, p.Device.Rollback)
		}
	}
}

func TestRestoreAccessPortWithoutVlanLineIsInTheDefaultVlan(t *testing.T) {
	// La gestión es Vlan1 y Gi1/0/1 no imprime `switchport access vlan`: está en la VLAN 1, la de gestión.
	run := rep(reviewRunning, "interface Vlan99\n ip address 192.0.2.10", "interface Vlan1\n ip address 192.0.2.10")
	run = rep(run, "description PC-ventas\n switchport access vlan 10\n", "description PC-ventas\n")
	back := rep(run, "description PC-ventas", "description PC-otro")
	p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, reviewOuts(run))
	if !errors.Is(err, ErrRestoreRefused) || !strings.Contains(fmtRefused(p), "gestión") {
		t.Fatalf("un puerto en la VLAN por omisión es de la VLAN de gestión 1: %v %s", err, fmtRefused(p))
	}
}

// Las líneas rechazadas con un secreto salen cortadas en la palabra del secreto, sin depender del enmascarado: solo los tokens anteriores y <oculto>.
func TestRestoreRefusedLinesAreCutAtTheSecretWord(t *testing.T) {
	secrets := "tacacs server T1\n address ipv4 10.1.1.1\n key 7 0822455D0A16\n!\n" +
		"radius server R1\n address ipv4 10.2.2.2 auth-port 1812\n key 0 RADIUSKEY\n!\n" +
		"crypto keyring KR1\n pre-shared-key address 10.3.3.3 key KEYRINGSECRET\n!\n"
	run := rep(reviewRunning, "vlan 10\n", secrets+"vlan 10\n")
	back := strings.NewReplacer("0822455D0A16", "NEWTACACS", "RADIUSKEY", "NEWRADIUS", "KEYRINGSECRET", "NEWKEYRING").Replace(run)
	back = rep(back, "hostname SW1\n", "hostname SW1\nusername tech privilege 1 secret 9 $9$qqqSECRETO\nenable secret 9 $9$ppp\nsnmp-server community COMUNIDAD42 RO\n"+
		"crypto isakmp key CLAVEISAKMP address 1.1.1.1\nntp authentication-key 1 md5 CLAVENTP\n")
	p, err := RestoreDiffPlan("SW1", RestoreChange{Backup: back, BackupSerial: "FOC0001A0AA"}, reviewOuts(run))
	if !errors.Is(err, ErrRestoreRefused) {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, r := range p.Refused {
		got[r.Path+" | "+r.Line] = true
		for _, s := range []string{"0822455D0A16", "NEWTACACS", "RADIUSKEY", "NEWRADIUS", "KEYRINGSECRET", "NEWKEYRING", "qqqSECRETO", "$9$", "COMUNIDAD42", "CLAVEISAKMP", "CLAVENTP"} {
			if strings.Contains(r.Path+r.Line+r.Why, s) {
				t.Errorf("lo rechazado lleva un secreto (%s): %+v", s, r)
			}
		}
	}
	for _, want := range []string{
		"tacacs server T1 | <oculto>", "radius server R1 | <oculto>", "crypto keyring KR1 | <oculto>",
		" | username tech privilege 1 <oculto>", " | enable <oculto>", " | snmp-server community <oculto>",
		" | crypto isakmp <oculto>", " | ntp <oculto>",
	} {
		if !got[want] {
			t.Errorf("faltaba %q en %v", want, got)
		}
	}
}
