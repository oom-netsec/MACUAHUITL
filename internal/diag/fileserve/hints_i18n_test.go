package fileserve

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// hintsEs arma todas las instrucciones en español (las de siempre) para fijarlas con un golden.
func hintsEs() map[string]string {
	out := map[string]string{}
	r := Ready{Addr: "10.0.0.5:2121", User: "mac", Pass: "pw123", Fingerprints: []string{"SHA256:aa", "SHA256:bb"}}
	for _, proto := range []string{"tftp", "ftp", "scp", "sftp", "http"} {
		for _, w := range []string{"ro", "rw"} {
			out[proto+"-"+w] = ServerHint(Config{Proto: proto, Write: w == "rw"}, r, []string{"a.bin", "b.bin"})
		}
		out[proto+"-redirect"] = RedirectHint(proto, "10.0.0.5", 2121)
		out[proto+"-redirect6"] = RedirectHint(proto, "fe80::1", 2121)
		out[proto+"-cleanup"] = RedirectCleanup(proto, "10.0.0.5", 2121)
	}
	out["scp-any"] = ServerHint(Config{Proto: "scp"}, Ready{Addr: "0.0.0.0:2222"}, []string{"a"})
	out["hint-tftp"] = Hint("tftp", "10.0.0.5:6969", []string{"/x/a.bin"})
	out["hint-http"] = Hint("http", "0.0.0.0:8080", []string{"/x/a.bin", "/x/b.bin"})
	out["hint-tftp6"] = Hint("tftp", "[fe80::1]:6969", []string{"/x/a.bin"})
	out["setcap"] = SetcapHint("RUTA")
	return out
}

func TestHintsEspanolRegresion(t *testing.T) {
	got := hintsEs()
	const file = "testdata/hints_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	json.Unmarshal(raw, &want)
	for n, g := range got {
		if g != want[n] {
			t.Errorf("%s cambió:\n got: %s\nwant: %s", n, g, want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("%d casos, golden %d", len(got), len(want))
	}
}

// Con en, las instrucciones salen en inglés y los comandos (copy, nft, setcap) no cambian.
func TestHintsEnIngles(t *testing.T) {
	r := Ready{Addr: "0.0.0.0:2121", User: "mac", Pass: "pw123", Fingerprints: []string{"SHA256:aa"}}
	for _, proto := range []string{"tftp", "ftp", "scp", "sftp", "http"} {
		es := ServerHint(Config{Proto: proto, Write: true}, r, []string{"a.bin"})
		en := ServerHintIn("en", Config{Proto: proto, Write: true}, r, []string{"a.bin"})
		if es == en || strings.Contains(en, "En el equipo") || strings.Contains(en, "IP-DE-ESTA") || strings.Contains(en, "contraseña") || strings.Contains(en, "quitar") || strings.Contains(en, "redirección") {
			t.Errorf("%s sin traducir:\n%s", proto, en)
		}
		if !strings.Contains(en, "On the device:") {
			t.Errorf("%s: %s", proto, en)
		}
	}
	if h := HintIn("en", "tftp", "10.0.0.5:6969", []string{"/x/a.bin"}); !strings.Contains(h, "IOS always uses port 69") || strings.Contains(h, "quitar") || !strings.Contains(h, "copy tftp://10.0.0.5/a.bin flash:") {
		t.Error(h)
	}
	if h := SetcapHintIn("en", "RUTA"); !strings.Contains(h, "sudo setcap cap_net_bind_service=+ep RUTA") || !strings.Contains(h, "WARNING") {
		t.Error(h)
	}
}
