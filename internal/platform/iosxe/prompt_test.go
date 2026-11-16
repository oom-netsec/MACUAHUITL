package iosxe

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

func TestParsePromptCombinaciones(t *testing.T) {
	casos := map[string]platform.Prompt{
		"asa#":                          {Host: "asa"},
		"asa>":                          {Host: "asa"},
		"asa/ctx1#":                     {Host: "asa", Context: "ctx1"},
		"asa/admin>":                    {Host: "asa", Context: "admin"},
		"fw-a/pri/act#":                 {Host: "fw-a", Priority: "pri", State: "act"},
		"fw-b/sec/stby#":                {Host: "fw-b", Priority: "sec", State: "stby"},
		"fw-a/ctx1/pri/act#":            {Host: "fw-a", Context: "ctx1", Priority: "pri", State: "act"},
		"fw-a/pri/stby/ctx1#":           {Host: "fw-a", Context: "ctx1", Priority: "pri", State: "stby"},
		"fw-b/sec/act/ctx1#":            {Host: "fw-b", Context: "ctx1", Priority: "sec", State: "act"},
		"fw-a/pri/actNoFailover#":       {Host: "fw-a", Priority: "pri", State: "actNoFailover"},
		"fw-a/pri/stbyNoFailover#":      {Host: "fw-a", Priority: "pri", State: "stbyNoFailover"},
		"asa/unit-1-1/control#":         {Host: "asa", Unit: "unit-1-1", Cluster: "control"},
		"asa/unit-1-2/data#":            {Host: "asa", Unit: "unit-1-2", Cluster: "data"},
		"asa/unit-1-1/master#":          {Host: "asa", Unit: "unit-1-1", Cluster: "master"},
		"asa/unit-1-2/slave#":           {Host: "asa", Unit: "unit-1-2", Cluster: "slave"},
		"asa/ctx1/unit-1-2/data#":       {Host: "asa", Context: "ctx1", Unit: "unit-1-2", Cluster: "data"},
		"asa/control/unit-1-1/ctx1#":    {Host: "asa", Context: "ctx1", Unit: "unit-1-1", Cluster: "control"},
		"asa/example.com/pri/act#":      {Host: "asa", Domain: "example.com", Priority: "pri", State: "act"},
		"asa/lab.example.com/sec/stby#": {Host: "asa", Domain: "lab.example.com", Priority: "sec", State: "stby"},
		"asa/ctx1/example.com/pri/act#": {Host: "asa", Context: "ctx1", Domain: "example.com", Priority: "pri", State: "act"},
		"asa/ctx1/pri/act# ":            {Host: "asa", Context: "ctx1", Priority: "pri", State: "act"},
	}
	for in, want := range casos {
		got, err := ParsePrompt(in)
		if err != nil || got != want {
			t.Errorf("%q = %+v, %v; quería %+v", in, got, err, want)
		}
	}
}

func TestParsePromptConfigEsErrConfigPrompt(t *testing.T) {
	for _, in := range []string{"asa(config)#", "asa/ctx1(config)#", "fw-a/ctx1/pri/act(config)#", "asa/admin(config-if)#", "asa/unit-1-1/control(config-cluster)#",
		"asa/pri/act(config)# ", "asa/a-very-long-context-name-of-32-chars/example.com/pri/act(config)#"} {
		if _, err := ParsePrompt(in); !errors.Is(err, platform.ErrConfigPrompt) {
			t.Errorf("%q: err = %v, quería ErrConfigPrompt", in, err)
		}
	}
}

func TestParsePromptNegativos(t *testing.T) {
	for _, in := range []string{"", "#", "asa", "asa/data node#", "asa/ctx 1#", "asa//ctx1#", "asa/ctx1/#", "/ctx1#", "asa/pri/act/ctx1/otro#",
		"asa/ctx1/ctx2#", "asa/pri/pri/ctx1/x#", "asa/a.com/b.com#", "asa(foo)#", "asa/ctx1(config#", "asa/ctx1 (config)#", "asa\tx#", "asa#x", "asa/ctx1/unit-1-1/x/control#"} {
		if p, err := ParsePrompt(in); err == nil || errors.Is(err, platform.ErrConfigPrompt) {
			t.Errorf("%q = %+v, %v; debía rechazarse", in, p, err)
		}
	}
}

// Todas las líneas de prompts.txt: sin (config) se reconocen y con (config…) dan ErrConfigPrompt.
func TestParsePromptArchivoDeCisco(t *testing.T) {
	f, err := os.Open("../../parse/asa/testdata/prompts.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		n++
		_, err := ParsePrompt(l)
		if strings.Contains(l, "(config") != errors.Is(err, platform.ErrConfigPrompt) || (!strings.Contains(l, "(config") && err != nil) {
			t.Errorf("%q: err = %v", l, err)
		}
	}
	if n < 30 {
		t.Fatalf("solo %d prompts", n)
	}
}

// Open con el prompt de configuración de un ASA: ErrConfigPrompt, no espera hasta el timeout.
func TestOpenPromptDeConfiguracionASA(t *testing.T) {
	for _, p := range []string{"asa/ctx1(config)#", "asa/ctx1/pri/act(config)#", "asa/admin/pri/act(config-if)#"} {
		_, r, w := startFake(t, p+" ", p+" ", func(string) (string, string) { return "", "" })
		d := New().(*driver)
		start := time.Now()
		if err := d.Open(context.Background(), r, w, secret.New(nil)); !errors.Is(err, platform.ErrConfigPrompt) || time.Since(start) > 5*time.Second {
			t.Fatalf("%s: err = %v tras %v", p, err, time.Since(start))
		}
	}
}

// Un hostname de 63 + contexto de 32 + /pri/act pasa de 63 caracteres y debe seguir siendo un prompt (no ErrFirstLogin).
func TestOpenPromptLargoASA(t *testing.T) {
	p := strings.Repeat("h", 63) + "/" + strings.Repeat("c", 32) + "/pri/act"
	_, r, w := startFake(t, p+"# ", p+"# ", func(string) (string, string) { return "", "" })
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
}

// El rol cambia a mitad de la corrida (failover): el prompt estable sigue valiendo y el rol nuevo se informa.
func TestASACambioDeRolAMitadDeCorrida(t *testing.T) {
	cur := "fw-a/ctx1/pri/act# "
	_, r, w := startFake(t, cur, cur, func(line string) (string, string) {
		switch line {
		case "show version":
			return "Cisco Adaptive Security Appliance Software Version 9.22(1)\r\n", ""
		case "show failover":
			return "x\r\n", "fw-a/ctx1/pri/stby# " // el prompt cambia con la salida
		}
		return "", ""
	})
	d := New().(*driver)
	ctx := context.Background()
	if err := d.Open(ctx, r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if p, err := d.Detect(ctx); err != nil || p != "asa" || d.Hostname() != "fw-a/ctx1" || d.Prompt().State != "act" {
		t.Fatalf("detect = %q, %v; host %q; %+v", p, err, d.Hostname(), d.Prompt())
	}
	start := time.Now()
	if _, err := d.Run(ctx, "show failover", 5*time.Second); err != nil || time.Since(start) > 3*time.Second {
		t.Fatalf("run = %v tras %v", err, time.Since(start))
	}
	if _, err := d.Run(ctx, "show clock", 5*time.Second); err != nil || d.Prompt().State != "stby" || d.Prompt().Priority != "pri" {
		t.Fatalf("tras el cambio: %v %+v", err, d.Prompt())
	}
}

// El prompt estable no acepta otro contexto: en un ASA, «fw/ctx2#» no es el prompt de fw/ctx1.
func TestASAOtroContextoNoEsElPrompt(t *testing.T) {
	d := &driver{asa: true, hostname: "fw/ctx1", pr: platform.Prompt{Host: "fw", Context: "ctx1"}}
	for in, want := range map[string]bool{"fw/ctx1/pri/act#": true, "fw/ctx1>": true, "fw/ctx2#": false, "fw#": false, "fw/ctx1(config)#": false, "x\nfw/ctx1#": true} {
		if got := d.atPrompt(in); got != want {
			t.Errorf("atPrompt(%q) = %v", in, got)
		}
	}
}

func TestASAConfigPromptSinRecortar(t *testing.T) {
	long := "asa-with-a-very-long-hostname"
	d := &driver{asa: true, hostname: long + "/admin", pr: platform.Prompt{Host: long, Context: "admin"}}
	if !d.atConfigPrompt(long + "/admin/pri/act(config)#") {
		t.Fatal("el prompt de configuración del ASA no se reconoció")
	}
	if d.atConfigPrompt(long[:16] + "/admin(config)#") {
		t.Fatal("el ASA no recorta el hostname")
	}
}

// ChangeTo contra un equipo falso: éxito, prompt que no coincide, nombre inválido y plataforma sin soporte.
func TestChangeTo(t *testing.T) {
	prompt := "asa/admin# "
	dev := func(land string) (*driver, *fakeDev) {
		prompt = "asa/admin# "
		f, r, w := startFake(t, prompt, prompt, func(line string) (string, string) {
			switch {
			case line == "show version":
				return "Cisco Adaptive Security Appliance Software Version 9.22(1)\r\n", ""
			case strings.HasPrefix(line, "changeto"):
				return "", land
			}
			return "", ""
		})
		d := New().(*driver)
		ctx := context.Background()
		if err := d.Open(ctx, r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Detect(ctx); err != nil {
			t.Fatal(err)
		}
		return d, f
	}
	ctx := context.Background()
	d, f := dev("asa# ")
	if err := d.ChangeTo(ctx, "system", 5*time.Second); err != nil || d.Prompt().Context != "" || d.Hostname() != "asa" {
		t.Fatalf("system: %v %+v", err, d.Prompt())
	}
	if _, err := d.Run(ctx, "show clock", 5*time.Second); err != nil {
		t.Fatalf("Run tras changeto: %v", err)
	}
	if !strings.Contains(f.written(), "changeto system\n") {
		t.Fatalf("no mandó changeto: %q", f.written())
	}
	// Aterriza en otro contexto del pedido: falla y la sesión queda inservible.
	d, _ = dev("asa/ctx9# ")
	if err := d.ChangeTo(ctx, "ctx1", 5*time.Second); err == nil || !strings.Contains(err.Error(), "ctx9") || d.Err() == nil {
		t.Fatalf("mismatch: %v, Err = %v", err, d.Err())
	}
	// Otro hostname.
	d, _ = dev("otro/ctx1# ")
	if err := d.ChangeTo(ctx, "ctx1", 5*time.Second); err == nil {
		t.Fatal("otro hostname debía fallar")
	}
	// Nombres inválidos: no se manda nada.
	d, f = dev("asa/ctx1# ")
	for _, n := range []string{"", "ctx1; reload", "a b", "../x", "SYSTEM x", strings.Repeat("a", 33), "-x"} {
		if err := d.ChangeTo(ctx, n, time.Second); err == nil {
			t.Fatalf("%q debía rechazarse", n)
		}
	}
	if strings.Contains(f.written(), "changeto") {
		t.Fatalf("se mandó algo con un nombre inválido: %q", f.written())
	}
	// Sin Detect de ASA no hay changeto.
	_, r, w := startFake(t, "SW1# ", "SW1# ", func(string) (string, string) { return "", "" })
	d2 := New().(*driver)
	if err := d2.Open(ctx, r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	if err := d2.ChangeTo(ctx, "system", time.Second); !errors.Is(err, platform.ErrChangetoUnsupported) {
		t.Fatalf("err = %v", err)
	}
}

// Un banner de IOS cuya última línea mide 70 caracteres y termina en «#» no es un prompt: el prompt real llega en
// otro paquete. Sin «/» el tope sigue siendo 63 (igual que en main).
func TestOpenBannerLargoQueTerminaEnAlmohadilla(t *testing.T) {
	devR, drvW := io.Pipe()
	drvR, devW := io.Pipe()
	go func() {
		io.WriteString(devW, "Banner-"+strings.Repeat("x", 62)+"#") // 70 caracteres sin espacios
		time.Sleep(300 * time.Millisecond)
		io.WriteString(devW, "\r\nSW1# ")
		buf := bufio.NewReader(devR)
		for {
			l, err := buf.ReadString('\n')
			if err != nil {
				return
			}
			io.WriteString(devW, l[:len(l)-1]+"\r\nSW1# ")
		}
	}()
	t.Cleanup(func() { drvW.Close(); devW.Close() })
	d := New().(*driver)
	if err := d.Open(context.Background(), drvR, drvW, secret.New(nil)); err != nil || d.Hostname() != "SW1" {
		t.Fatalf("err = %v, hostname = %q", err, d.Hostname())
	}
}

// El prompt de ASA más largo posible: host 63, contexto 32, dominio 63 y /sec/stbyNoFailover (179 caracteres).
func TestOpenPromptASAMaximo(t *testing.T) {
	p := strings.Repeat("h", 63) + "/" + strings.Repeat("c", 32) + "/" + strings.Repeat("d", 59) + ".com/sec/stbyNoFailover"
	if len(p) != 63+1+32+1+63+len("/sec/stbyNoFailover") {
		t.Fatalf("len = %d", len(p))
	}
	_, r, w := startFake(t, p+"# ", p+"# ", func(string) (string, string) { return "", "" })
	if err := New().(*driver).Open(context.Background(), r, w, secret.New(nil)); err != nil {
		t.Fatal(err)
	}
	_, r, w = startFake(t, p+"(config)# ", p+"# ", func(string) (string, string) { return "", "" })
	if err := New().(*driver).Open(context.Background(), r, w, secret.New(nil)); !errors.Is(err, platform.ErrConfigPrompt) {
		t.Fatalf("config: %v", err)
	}
}

// ChangeTo compara también el dominio y la unidad, y no admite texto del equipo entre el eco y el prompt.
func TestChangeToVerificaDominioUnidadYSalida(t *testing.T) {
	ctx := context.Background()
	open := func(first, land, out string) *driver {
		_, r, w := startFake(t, first, first, func(line string) (string, string) {
			switch {
			case line == "show version":
				return "Cisco Adaptive Security Appliance Software Version 9.22(1)\r\n", ""
			case strings.HasPrefix(line, "changeto"):
				return out, land
			}
			return "", ""
		})
		d := New().(*driver)
		if err := d.Open(ctx, r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Detect(ctx); err != nil {
			t.Fatal(err)
		}
		return d
	}
	for _, c := range []struct {
		name, first, land, out, to string
		ok                         bool
	}{
		{"dominio distinto", "asa/admin# ", "asa/ctx1/example.com# ", "", "ctx1", false},
		{"mismo dominio", "asa/admin/example.com# ", "asa/ctx1/example.com# ", "", "ctx1", true},
		{"unidad distinta", "asa/unit-1-1/control# ", "asa/ctx1/unit-1-2/data# ", "", "ctx1", false},
		{"misma unidad, otro rol", "asa/unit-1-1/control# ", "asa/ctx1/unit-1-1/data# ", "", "ctx1", true},
		{"error entre el eco y el prompt", "asa/admin# ", "asa/ctx1# ", "ERROR: algo salio mal\r\n", "ctx1", false},
		{"syslog entre el eco y el prompt", "asa/admin# ", "asa/ctx1# ", "%ASA-6-302013: Built inbound TCP connection\r\n", "ctx1", true},
	} {
		d := open(c.first, c.land, c.out)
		if err := d.ChangeTo(ctx, c.to, 5*time.Second); (err == nil) != c.ok {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}
