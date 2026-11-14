package iosxe

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const bogus = "% Invalid input detected at '^' marker."

func cfgSim(rec *simulator.Recorder, errs map[string]string) simulator.Config {
	return simulator.Config{
		Interfaces:   map[string][]string{"GigabitEthernet1/0/1": {"switchport access vlan 10", "description viejo"}},
		ConfigErrors: errs,
		Recorder:     rec,
	}
}

func TestConfigureSendsLinesAndLeavesWithEnd(t *testing.T) {
	rec := &simulator.Recorder{}
	d, err := open(t, cfgSim(rec, nil), "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"interface GigabitEthernet1/0/1", "switchport access vlan 20", "description nuevo"}
	res, err := d.Configure(context.Background(), lines, 5*time.Second)
	if err != nil || res.Failed || len(res.Lines) != 3 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := rec.Lines(); !reflect.DeepEqual(got, append(lines, "end")) {
		t.Fatalf("el equipo recibió %q", got)
	}
	// Tras "end" el driver vuelve a exec: Run funciona y ve el cambio.
	out, err := d.Run(context.Background(), "show running-config interface GigabitEthernet1/0/1", 5*time.Second)
	if err != nil || !strings.Contains(out.Text, " switchport access vlan 20") || strings.Contains(out.Text, "vlan 10") {
		t.Fatalf("out=%q err=%v", out.Text, err)
	}
}

func TestConfigureStopsAtFirstError(t *testing.T) {
	for _, e := range []string{bogus, "% Incomplete command.", "% Ambiguous command: \"sw\"", "% Error: algo"} {
		rec := &simulator.Recorder{}
		d, err := open(t, cfgSim(rec, map[string]string{"switchport access vlan 20": e}), "en", context.Background())
		if err != nil {
			t.Fatal(err)
		}
		lines := []string{"interface GigabitEthernet1/0/1", "switchport access vlan 20", "description nuevo"}
		res, err := d.Configure(context.Background(), lines, 5*time.Second)
		if err != nil || !res.Failed || len(res.Lines) != 2 || !res.Lines[1].Failed {
			t.Fatalf("%q: res=%+v err=%v", e, res, err)
		}
		// La tercera línea nunca llegó al equipo, y se salió con end.
		if got := rec.Lines(); !reflect.DeepEqual(got, []string{lines[0], lines[1], "end"}) {
			t.Fatalf("%q: el equipo recibió %q", e, got)
		}
		if _, err := d.Run(context.Background(), "show version", 5*time.Second); err != nil {
			t.Fatalf("el driver quedó fuera de exec: %v", err)
		}
	}
}

func TestConfigureRecognizesConfigPrompts(t *testing.T) {
	rec := &simulator.Recorder{}
	d, err := open(t, cfgSim(rec, nil), "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"interface range GigabitEthernet1/0/1, GigabitEthernet1/0/2", "shutdown"} {
		if res, err := d.Configure(context.Background(), []string{l}, 5*time.Second); err != nil || res.Failed {
			t.Fatalf("%q: %+v %v", l, res, err)
		}
	}
}

func TestConfigureRefusesModeChangingLines(t *testing.T) {
	rec := &simulator.Recorder{}
	d, err := open(t, cfgSim(rec, nil), "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"end", "exit", "do reload", "write memory", "a\nreload", "description ¿qué?",
		"en", "ex", "exi", "wr", "conf t", "conf", "cop flash:a b", "rel", "d show version", "e"} { // IOS ejecuta cualquier prefijo único
		_, err := d.Configure(context.Background(), []string{"interface GigabitEthernet1/0/1", l}, 5*time.Second)
		if !errors.Is(err, platform.ErrConfigLine) {
			t.Errorf("%q: err=%v", l, err)
		}
	}
	if got := rec.Lines(); len(got) != 0 {
		t.Fatalf("no debía mandarse nada, llegó %q", got)
	}
}

func TestConfigureRefusesNonASCII(t *testing.T) {
	rec := &simulator.Recorder{}
	d, err := open(t, cfgSim(rec, nil), "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range []string{"description cafÍ", "description xÊ", "description ñ", "description x\ty"} {
		if _, err := d.Configure(context.Background(), []string{l}, 5*time.Second); !errors.Is(err, platform.ErrConfigLine) {
			t.Errorf("%q: err = %v", l, err)
		}
	}
	if len(rec.Lines()) != 0 {
		t.Fatalf("llegó %q", rec.Lines())
	}
}

// Err detecta un cierre que llegó con el driver ocioso (exec-timeout del equipo).
func TestErrDetectsSessionClosedWhileIdle(t *testing.T) {
	c := cfgSim(&simulator.Recorder{}, nil)
	c.IdleTimeout = 150 * time.Millisecond
	d, err := open(t, c, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Err(); err != nil {
		t.Fatalf("recién abierta: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if err := d.Err(); !errors.Is(err, platform.ErrClosed) {
		t.Fatalf("Err = %v", err)
	}
	if _, err := d.Configure(context.Background(), []string{"interface GigabitEthernet1/0/1"}, time.Second); err == nil {
		t.Fatal("Configure sobre una sesión muerta")
	}
}

// Hallazgo 5: IOS aplica la línea pero avisa que creó la VLAN; es un fallo que detiene la configuración.
func TestConfigureStopsWhenIOSCreatesAVlan(t *testing.T) {
	rec := &simulator.Recorder{}
	c := cfgSim(rec, nil)
	c.Vlans = []int{1, 10}
	d, err := open(t, c, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"interface GigabitEthernet1/0/1", "switchport access vlan 99", "description nuevo"}
	res, err := d.Configure(context.Background(), lines, 5*time.Second)
	if err != nil || !res.Failed || len(res.Lines) != 2 || !strings.Contains(res.Lines[1].Output, "Creating vlan 99") {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got := rec.Lines(); !reflect.DeepEqual(got, []string{lines[0], lines[1], "end"}) {
		t.Fatalf("el equipo recibió %q", got)
	}
}

// Hallazgo 9: IOS acorta el hostname en el prompt de configuración (16 caracteres, como Netmiko).
func TestConfigureWithLongHostname(t *testing.T) {
	rec := &simulator.Recorder{}
	c := cfgSim(rec, nil)
	c.Hostname = "CAMPUS-DISTRIBUTION-SW01"
	d, err := open(t, c, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"interface GigabitEthernet1/0/1", "switchport access vlan 20"}
	res, err := d.Configure(context.Background(), lines, 3*time.Second)
	if err != nil || res.Failed || len(res.Lines) != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// Hallazgo 9: si una línea no termina a tiempo, se intenta "end" igual para no dejar el equipo en configuración.
func TestConfigureTriesEndAfterLineTimeout(t *testing.T) {
	rec := &simulator.Recorder{}
	c := cfgSim(rec, nil)
	c.SlowConfigLine, c.SlowDelay = "description nuevo", 800*time.Millisecond
	d, err := open(t, c, "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{"interface GigabitEthernet1/0/1", "description nuevo", "shutdown"}
	res, err := d.Configure(context.Background(), lines, 400*time.Millisecond)
	if !errors.Is(err, platform.ErrPromptTimeout) || len(res.Lines) != 2 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	time.Sleep(1200 * time.Millisecond)
	if got := rec.Lines(); !reflect.DeepEqual(got, []string{lines[0], lines[1], "end"}) {
		t.Fatalf("el equipo recibió %q", got)
	}
}

// Hallazgo 9: si no se pudo ni entrar a configuración, ninguna línea cuenta como enviada.
func TestConfigureFailBeforeFirstLineReportsNoLines(t *testing.T) {
	d, err := open(t, cfgSim(&simulator.Recorder{}, nil), "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	d.Close()
	res, err := d.Configure(context.Background(), []string{"interface GigabitEthernet1/0/1"}, time.Second)
	if err == nil || len(res.Lines) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
}

// Qué avisos de IOS en modo configuración detienen la ejecución y cuáles son solo informativos (registrados en la bitácora con la respuesta).
func TestCfgErrorDecidesWhichPercentLinesStop(t *testing.T) {
	for msg, stops := range map[string]bool{
		"% Invalid input detected at '^' marker.":                                        true,
		"% Incomplete command.":                                                          true,
		"% Ambiguous command:  \"ip r\"":                                                 true,
		"% Interface Port-channel1 removed":                                              true, // `no interface` borró una interfaz: nadie lo pidió
		"% Specify remote-as or peer-group commands first":                               true, // el neighbor ya no existe
		"% Creating vlan 99":                                                             true,
		"Command rejected: Conflict with the port-security configuration.":               true, // IOS lo da sin % (p. ej. switchport mode dynamic con port-security)
		"% Command rejected: Interface is not a switchport.":                             true,
		"%Warning: portfast should only be enabled on ports connected to a single host.": false, // informativo de spanning-tree portfast
		"%Portfast has been configured on GigabitEthernet1/0/1 but will only have effect when the interface is in a non-trunking mode.": false,
		"% Not all config may be removed and may reappear after reactivating the logical-interface/sub-interfaces":                      false,
		"%LINK-5-CHANGED: Interface GigabitEthernet1/0/1, changed state to administratively down":                                       false,
	} {
		if got := cfgError(msg + "\n"); got != stops {
			t.Errorf("cfgError(%q) = %v, debía ser %v", msg, got, stops)
		}
	}
}

// Los rechazos propios del driver salen en el idioma pedido; con es, el texto de siempre.
func TestErroresDriverEsYEn(t *testing.T) {
	d, err := open(t, cfgSim(&simulator.Recorder{}, nil), "en", context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, e1 := d.Configure(context.Background(), []string{"end"}, 5*time.Second)
	_, e2 := d.Configure(context.Background(), []string{""}, 5*time.Second)
	_, e3 := d.Configure(context.Background(), []string{"description ñ"}, 5*time.Second)
	_, e4 := d.Run(context.Background(), "show\nversion", time.Second)
	for i, w := range []struct {
		err    error
		es, en string
	}{
		{e1, `platform: línea de configuración no permitida: "end" cambia de modo o ejecuta fuera de la configuración`, `platform: configuration line not allowed: "end" changes mode or runs outside configuration`},
		{e2, "platform: línea de configuración no permitida: línea vacía", "platform: configuration line not allowed: empty line"},
		{e3, `platform: línea de configuración no permitida: "description ñ" tiene caracteres fuera de ASCII imprimible o '?'`, `platform: configuration line not allowed: "description ñ" has characters outside printable ASCII or '?'`},
		{e4, `platform: el comando "show\nversion" tiene saltos de línea`, `platform: the command "show\nversion" contains line breaks`},
	} {
		if w.err == nil || w.err.Error() != w.es || i18n.In("en", w.err) != w.en {
			t.Errorf("%d: es %q en %q, quería %q / %q", i, w.err, i18n.In("en", w.err), w.es, w.en)
		}
	}
	if !errors.Is(e1, platform.ErrConfigLine) {
		t.Error("ya no es ErrConfigLine")
	}
}
