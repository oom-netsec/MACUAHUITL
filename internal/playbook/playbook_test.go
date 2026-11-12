package playbook

import (
	"errors"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/oom-netsec/MACUAHUITL/playbooks"
)

func TestLoadEmbedded(t *testing.T) {
	pbs, err := Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]Playbook{}
	for _, p := range pbs {
		ids[p.ID] = p
		for _, c := range append(append([]string(nil), p.Pre...), cmds(p)...) {
			if strings.HasPrefix(c, "terminal ") {
				continue
			}
			if err := CheckDenied(p.Platform, c); err != nil {
				t.Errorf("%s: %v", p.ID, err)
			}
		}
	}
	for _, id := range []string{"ios-xe/tac-baseline", "ios-xe/cpu-alta", "ios-xe/errores-interfaz", "ios-xe/upgrade-check", "ios-xe/pre-post", "ios-xe/topologia", "ios-xe/flota", "ios-xe/metricas"} {
		if _, ok := ids[id]; !ok {
			t.Errorf("missing %s (have %v)", id, keys(ids))
		}
	}
	tb := ids["ios-xe/tac-baseline"]
	for _, want := range []string{"show version", "show running-config", "show tech-support"} {
		if !contains(cmds(tb), want) {
			t.Errorf("tac-baseline lacks %q", want)
		}
	}
	for _, c := range tb.Commands {
		if c.Text == "show tech-support" && (c.Timeout != 600*time.Second || !c.MaySecrets) {
			t.Errorf("show tech-support = %+v", c)
		}
	}
}

func TestInvalidYAMLNamed(t *testing.T) {
	for name, body := range map[string]string{
		"cisco/ios-xe/malo.yaml":   "id: x\nplatform: ios-xe\nname: x\ncommands: [{cmd: show clock, timeout: nada}]\n",
		"cisco/ios-xe/extra.yaml":  "id: x\nplatform: ios-xe\nname: x\nbogus: 1\ncommands: [{cmd: show clock}]\n",
		"cisco/ios-xe/vacio.yaml":  "id: x\nplatform: ios-xe\nname: x\ncommands: []\n",
		"cisco/ios-xe/config.yaml": "id: x\nplatform: ios-xe\nname: x\ncommands: [{cmd: conf t}]\n",
	} {
		_, err := Load(fstest.MapFS{name: {Data: []byte(body)}})
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v, want error naming the file", name, err)
		}
	}
}

func TestDefaultTimeout(t *testing.T) {
	pbs, err := Load(fstest.MapFS{"cisco/ios-xe/a.yaml": {Data: []byte("id: a\nplatform: ios-xe\nname: a\ncommands: [{cmd: show clock}]\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if pbs[0].Commands[0].Timeout != 60*time.Second || pbs[0].ID != "ios-xe/a" {
		t.Fatalf("got %+v", pbs[0])
	}
}

func TestEphemeralID(t *testing.T) {
	text := "show clock\n\n! comentario\n  show version  \n"
	a, err := Ephemeral("ios-xe", text)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Ephemeral("ios-xe", text)
	if a.ID != b.ID || !strings.HasPrefix(a.ID, "custom-") || len(a.ID) != len("custom-")+12 {
		t.Fatalf("ids %q %q", a.ID, b.ID)
	}
	if got := cmds(a); len(got) != 2 || got[0] != "show clock" || got[1] != "show version" {
		t.Fatalf("commands = %v", got)
	}
	if _, err := Ephemeral("ios-xe", "show clock\nwr mem\n"); !errors.Is(err, ErrDenied) {
		t.Fatalf("denied command accepted: %v", err)
	}
	if _, err := Ephemeral("ios-xe", "\n! nada\n"); err == nil {
		t.Fatal("empty ephemeral accepted")
	}
}

func TestDenyVariants(t *testing.T) {
	for _, c := range []string{"conf t", "  CONF T", "configure terminal", "config t", "wr", "write mem", "copy run start", "copy tftp: flash:",
		"reload in 5", "clear counters", "debug ip packet", "undebug all", "delete flash:x", "erase startup-config", "format flash:",
		"test cable-diagnostics tdr int gi1/0/1", "install add file x", "request platform software", "license boot level", "Reload"} {
		if err := CheckDenied("ios-xe", c); !errors.Is(err, ErrDenied) {
			t.Errorf("%q not denied", c)
		}
	}
	for _, c := range []string{"show running-config", "show clock", "show configuration", "dir flash:", "show debug", "show license"} {
		if err := CheckDenied("ios-xe", c); err != nil {
			t.Errorf("%q denied: %v", c, err)
		}
	}
}

func cmds(p Playbook) []string {
	var out []string
	for _, c := range p.Commands {
		out = append(out, c.Text)
	}
	return out
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func keys(m map[string]Playbook) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
