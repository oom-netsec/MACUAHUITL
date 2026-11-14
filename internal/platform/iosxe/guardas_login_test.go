package iosxe

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/platform"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// fastSettle baja las calmas del driver para que las pruebas no esperen tiempo real; las pausas de cada prueba se miden en múltiplos de ellas.
func fastSettle(t *testing.T) {
	t.Helper()
	s, c := ftdSettle, ftdConfirmSettle
	ftdSettle, ftdConfirmSettle = 80*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { ftdSettle, ftdConfirmSettle = s, c })
}

var prompts = map[string]string{"ios": "Router#", "asa": "asa# ", "nxos": "nx1# "}

const abre = "terminal length 0|terminal width 0"

// openBanner arma un equipo que imprime chunks con pausas (en ms) entre ellos y luego su prompt; devuelve el error de Open y lo escrito.
func openBanner(t *testing.T, prompt string, cred bool, chunks ...any) (error, string) {
	t.Helper()
	fastSettle(t)
	r, w, lg := scriptedDevLog(t, func(out func(string)) {
		for _, c := range chunks {
			switch v := c.(type) {
			case string:
				out(v)
			case time.Duration:
				time.Sleep(v)
			}
		}
	}, func(line string, out func(string)) { out(line + "\r\n" + prompt) })
	d := New().(*driver)
	if cred {
		d.SetLogin("admin", secret.New([]byte("s3cret")))
	}
	err := d.Open(context.Background(), r, w, secret.New(nil))
	time.Sleep(20 * time.Millisecond)
	return err, strings.Join(lg.get(), "|")
}

// MEDIO-1: un «User:» de banner sin el nombre del controlador en la línea anterior no recibe usuario, aunque el prompt tarde más que ftdSettle.
func TestBannerUserLentoSinNombreNoEscribe(t *testing.T) {
	for _, banner := range []string{
		"\r\n*** Acceso ***\r\nUser:", "\r\n*** Acceso ***\r\nUser: ", "\r\nCisco Controller\r\nUser: ", "\r\n(sin cierre\r\nUser: ", "\r\n(Router) >\r\nUser: ",
	} {
		for name, p := range prompts {
			err, got := openBanner(t, p, true, banner, 2*ftdSettle, "\r\n"+p)
			if err != nil || got != abre {
				t.Fatalf("%s %q: Open = %v, escrito %q", name, banner, err, got)
			}
		}
	}
}

// Un IOS sin plataforma marcada con un banner que imita el login («(X)» y «User:») puede recibir el usuario, pero nunca la clave: sin «Password:» antes del primer prompt no sale.
func TestBannerImitaLoginRecibeSoloElUsuario(t *testing.T) {
	err, got := openBanner(t, "Router#", true, "\r\n(X)\r\nUser:", 2*ftdSettle, "\r\nRouter#")
	if !errors.Is(err, platform.ErrLoginFailed) || got != "admin" {
		t.Fatalf("Open = %v, escrito %q", err, got)
	}
}

func TestAireCueTabla(t *testing.T) {
	for s, want := range map[string]bool{
		"(Cisco Controller)\nUser: ": true, "(Cisco Controller) \nUser:": true, "x\n(WLC-1)\nUser:": true,
		"x\nUser:": false, "x(X)\nUser:": false, "(X) >\nUser:": false, "Router#\nUser:": false, "(X)\n\nUser:": false, "(X)User:": false, "": false,
	} {
		if aireCue.MatchString(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
	for s, want := range map[string]bool{"\nAdminUser: ": false, "xUser:": false, "\nUser: ": true} {
		if aireUser.MatchString(s) != want {
			t.Errorf("aireUser %q: %v", s, !want)
		}
	}
}

// Tras el usuario, si no llega «Password:» (llega «User:», un prompt o texto) la clave no se escribe.
func TestAireLoginSinPasswordNoEscribeLaClave(t *testing.T) {
	fastSettle(t)
	for name, reply := range map[string]string{"user otra vez": "User: ", "prompt": "\r\n(Cisco Controller) >", "texto": "hola\r\n"} {
		r, w, lg := scriptedDevLog(t, func(out func(string)) { out("(Cisco Controller)\r\nUser: ") },
			func(line string, out func(string)) { out(line + "\r\n" + reply) })
		d := New().(*driver)
		d.SetLogin("admin", secret.New([]byte("s3cret")))
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		err := d.Open(ctx, r, w, secret.New(nil))
		cancel()
		time.Sleep(20 * time.Millisecond)
		if err == nil || strings.Join(lg.get(), "|") != "admin" {
			t.Fatalf("%s: Open = %v, escrito %q", name, err, lg.get())
		}
		if name != "texto" && !errors.Is(err, platform.ErrLoginFailed) {
			t.Fatalf("%s: Open = %v", name, err)
		}
	}
}

// Un salto de línea en el usuario o en la clave no se escribe nunca.
func TestAireLoginRechazaSaltosEnLaCredencial(t *testing.T) {
	fastSettle(t)
	for _, c := range [][2]string{{"ad\nmin", "x"}, {"ad\rmin", "x"}, {"admin", "s3\ncret"}, {"admin", "s3\rcret"}} {
		r, w, lg := scriptedDevLog(t, func(out func(string)) { out("(Cisco Controller)\r\nUser: ") }, func(string, func(string)) {})
		d := New().(*driver)
		d.SetLogin(c[0], secret.New([]byte(c[1])))
		err := d.Open(context.Background(), r, w, secret.New(nil))
		time.Sleep(20 * time.Millisecond)
		if !errors.Is(err, platform.ErrLoginFailed) || len(lg.get()) != 0 {
			t.Fatalf("%q: Open = %v, escrito %q", c, err, lg.get())
		}
	}
}

// El login de AireOS con nombre sin espacio ni «Cisco» también funciona.
func TestAireLoginNombreDelControlador(t *testing.T) {
	fastSettle(t)
	r, w, lg := scriptedDevLog(t, func(out func(string)) { out("\r\n(WLC-1)\r\nUser: ") }, func(line string, out func(string)) {
		switch line {
		case "admin":
			out("Password: ")
		case "s3cret":
			out("(WLC-1) >")
		}
	})
	d := New().(*driver)
	d.SetLogin("admin", secret.New([]byte("s3cret")))
	if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil || d.Hostname() != "WLC-1" {
		t.Fatalf("Open = %v, host %q", err, d.Hostname())
	}
	if got := strings.Join(lg.get(), "|"); got != "admin|s3cret" {
		t.Fatalf("escrito %q", got)
	}
}

// MEDIO-2: un MOTD con una frase de primer login cortada entre lecturas no es un primer login: llega más texto y luego el prompt.
func TestMOTDCortadoNoEsPrimerLogin(t *testing.T) {
	for _, c := range [][2]string{
		{"You must change your password", " every 90 days.\r\n"},
		{"You must change your password every 90 days.\r", "\nBienvenido\r\n"},
		{"To agree to the EULA", ", ver el contrato.\r\n"},
		{"Enter new password:\r", "\nno aplica\r\n"},
		{"Enter new password:", " texto\r\n"},
		{"Confirm new password:\r", "\nx\r\n"},
		{"Press <ENTER> to display the EULA", ".\r\n"},
		{"Note: unix password:\r", "\nx\r\n"},
	} {
		for name, p := range prompts {
			err, got := openBanner(t, p, false, "\r\n"+c[0], ftdSettle/8, c[1], ftdSettle/8, "\r\n"+p)
			if err != nil || got != abre {
				t.Fatalf("%s %q: Open = %v, escrito %q", name, c, err, got)
			}
		}
	}
}

// BAJO-1: una línea de banner «(Cisco Controller) >» al final de un pedazo no hace pasar el equipo por AireOS si llega más.
func TestBannerConPromptDeAireOSNoEsAireOS(t *testing.T) {
	for name, p := range prompts {
		err, got := openBanner(t, p, false, "\r\n(Cisco Controller) >", ftdSettle/8, "\r\n"+p)
		if err != nil || got != abre {
			t.Fatalf("%s: Open = %v, escrito %q", name, err, got)
		}
	}
}

func TestFirstLoginAnclasYAlternativas(t *testing.T) {
	ftd := []string{"you must change your password", "you must accept the eula", "press <enter> to display the eula", "enter new password:",
		"confirm new password:", "unix password:", "to agree to the eula", "please enter 'yes'"}
	ise := []string{"password expired", "must change your password", "required to change the password", "changing password for",
		"(y/n)", "[yes/no]", "your password has expired"}
	for _, c := range []struct {
		name string
		alts []string
		re   interface{ MatchString(string) bool }
	}{{"ftd", ftd, ftdFirstLogin}, {"ise", ise, iseFirstLogin}} {
		for _, a := range c.alts {
			if !c.re.MatchString("banner\n"+strings.ToUpper(a[:1])+a[1:]) || !c.re.MatchString("banner\n"+a+" ") {
				t.Errorf("%s: %q al final no cuenta", c.name, a)
			}
			if c.re.MatchString("banner\n" + a + " y sigue la línea") {
				t.Errorf("%s: %q seguido de texto cuenta", c.name, a)
			}
		}
	}
}

// ASA: «The enable password is not set» basta por sí solo (aunque el prompt sea un «Password:» pelón): no se manda el secreto.
func TestASAEnableNoFijadaBastaPorSiSola(t *testing.T) {
	f, r, w := startFake(t, "asa> ", "asa> ", func(line string) (string, string) {
		if line == "enable" {
			return "The enable password is not set.\r\nPassword: ", "-"
		}
		return "", ""
	})
	d := New().(*driver)
	if err := d.Open(context.Background(), r, w, secret.New([]byte("en"))); !errors.Is(err, platform.ErrEnableFailed) || f.written() != "enable\n" {
		t.Fatalf("Open = %v, escrito %q", err, f.written())
	}
}

// AireOS: la pregunta partida en dos pedazos con menos de 150 ms entre ellos, o seguida de más texto en la línea, no es pregunta.
func TestAireOSPreguntaNoSiguePorVenir(t *testing.T) {
	fastSettle(t)
	for name, chunks := range map[string][]any{
		"partida":   {"Reset (y/n)", ftdConfirmSettle / 5, " listo\r\n"},
		"misma lín": {"Valor (y/n) mostrado aq", 4 * ftdConfirmSettle, "uí\r\n"},
		"sin signo": {"Are you sure\r\n", "Proceed", 4 * ftdConfirmSettle, "\r\n"},
	} {
		r, w := scriptedDev(t, func(out func(string)) { out(aireP) }, func(line string, out func(string)) {
			out(line + "\r\n")
			for _, c := range chunks {
				switch v := c.(type) {
				case string:
					out(v)
				case time.Duration:
					time.Sleep(v)
				}
			}
			out(aireP)
		})
		d := New().(*driver)
		if err := d.Open(context.Background(), r, w, secret.New(nil)); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Run(context.Background(), "show x", 2*time.Second); err != nil {
			t.Fatalf("%s: Run = %v", name, err)
		}
	}
}

// «are you sure …?» y «proceed?» son preguntas por separado.
func TestAireOSPreguntasSeparadas(t *testing.T) {
	for _, q := range []string{"Are you sure you want to reset the AP? ", "Do you want to proceed?", "Are you sure?"} {
		_, d, err := openAire(t, aireP, func(l string) (string, string) { return "\r\n" + q, "-" }, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.Run(context.Background(), "show x", 2*time.Second); !errors.Is(err, platform.ErrConfirmPrompt) {
			t.Fatalf("%q: Run = %v", q, err)
		}
	}
}

func TestBareConfirmedYEchoFirst(t *testing.T) {
	for s, want := range map[string]bool{"foo>\n> ": false, "foo>\n>": false, "x\n>\n> ": true, "x\n> \r\n> ": true, ">\n> ": true, "\n> ": false, "> ": false, "x\n>\n>> ": false} {
		if bareConfirmed([]byte(s)) != want {
			t.Errorf("bareConfirmed %q: %v", s, !want)
		}
	}
	for _, c := range []struct {
		text, cmd string
		want      bool
	}{
		{"show a\n> ", "show a", true}, {"sho\n> ", "show a", true}, {"zzz\n> ", "show a", false}, {"\nfoo\n> ", "show a", false},
		{"\r\n\nfoo", "show a", false}, {"w interface eth0 detail\n", "show interface eth0 detail", true}, {"short\n", "show a short", false},
	} {
		if echoFirst(c.text, c.cmd) != c.want {
			t.Errorf("echoFirst(%q, %q) = %v", c.text, c.cmd, !c.want)
		}
	}
}

// La rama FTD de atPrompt (hostname vacío) solo acepta «>» solo.
func TestAtPromptFTD(t *testing.T) {
	d := &driver{}
	for s, want := range map[string]bool{"x\n> ": true, "x\n>": true, "x\nfoo>": false, "x\nR#": false} {
		if d.atPrompt(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

func TestAnclasDeInicioDeLineaDeAireOS(t *testing.T) {
	for s, want := range map[string]bool{"x(Cisco Controller) >": false, "\n(X) >": true, "(X) >": true} {
		if airePrompt.MatchString(s) != want {
			t.Errorf("airePrompt %q: %v", s, !want)
		}
	}
	if aireConfig.MatchString("x(X) config>") || !aireConfig.MatchString("\n(X) config>") {
		t.Error("aireConfig sin ancla de inicio de línea")
	}
}

// En AireOS atPrompt acepta solo «(Nombre) >» del controlador, no cualquier línea que termine en «>».
func TestAtPromptAireOS(t *testing.T) {
	d := &driver{aire: true, hostname: "Cisco Controller"}
	for s, want := range map[string]bool{
		"x\n(Cisco Controller) >": true, "x\n(Cisco Controller)>": true, "x\n(Cisco Controller) > ": true,
		"x\nfoo>": false, "x\n(Otro) >": false, "x\nCisco Controller >": false, "x\n> ": false, "x\nRouter#": false,
	} {
		if d.atPrompt(s) != want {
			t.Errorf("%q: %v", s, !want)
		}
	}
}

// «(X)» + «User:» seguido enseguida (menos de la calma) del prompt de un IOS no recibe ni el usuario.
func TestBannerImitaLoginConPromptRapido(t *testing.T) {
	err, got := openBanner(t, "Router#", true, "\r\n(X)\r\nUser:", ftdSettle/8, "\r\nRouter#")
	if err != nil || got != abre {
		t.Fatalf("Open = %v, escrito %q", err, got)
	}
}

// «(Nombre) config>» de un banner tampoco se toma de golpe por el prompt de configuración de AireOS.
func TestBannerConPromptDeConfigDeAireOS(t *testing.T) {
	err, got := openBanner(t, "Router#", false, "\r\n(Cisco Controller) config>", ftdSettle/8, "\r\nRouter#")
	if err != nil || got != abre {
		t.Fatalf("Open = %v, escrito %q", err, got)
	}
}

// El Run de AireOS no espera la calma de moreComing (solo existe al abrir).
func TestRunDeAireOSNoEsperaLaCalma(t *testing.T) {
	_, d, err := openAire(t, aireP, aireReply, "", "")
	if err != nil {
		t.Fatal(err)
	}
	ftdSettle = 3 * time.Second // fastSettle restaura el valor al terminar
	t0 := time.Now()
	if _, err := d.Run(context.Background(), "show x", 5*time.Second); err != nil || time.Since(t0) > time.Second {
		t.Fatalf("Run = %v en %v", err, time.Since(t0))
	}
}

// «User:» o «Password:» a mitad de un comando (Detect incluido) no es un rechazo de credencial.
func TestUserOPasswordEnDetectNoEsRechazo(t *testing.T) {
	for _, q := range []string{"User: ", "Password: "} {
		_, d, err := openAire(t, aireP, func(l string) (string, string) { return "", q }, "admin", "s3cret")
		if err != nil {
			t.Fatal(err)
		}
		_, err = d.Detect(context.Background())
		if !errors.Is(err, platform.ErrUnexpectedPrompt) || errors.Is(err, platform.ErrLoginFailed) {
			t.Fatalf("%q: Detect = %v", q, err)
		}
	}
}
