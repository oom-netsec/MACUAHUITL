package upgrade

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
)

type golden struct{ JSON, Text string }

func gold(v any, text string) golden {
	b, _ := json.Marshal(v)
	return golden{string(b), text}
}

// regCases arma informes que recorren cada punto de la verificación; solo usa lo que ya existía antes de la fase 30c.
func regCases(t *testing.T) (map[string]golden, map[string]any) {
	t.Helper()
	out, ptrs := map[string]golden{}, map[string]any{}
	run := func(name string, o map[string]string, img Image, verify string) {
		r, err := Check(o, img, verify)
		if err != nil {
			out[name] = gold(struct{ Err string }{err.Error()}, err.Error())
			return
		}
		out[name], ptrs[name] = gold(r, r.Text()), &r
	}
	base := outputs(t, "c9600-install-sso.txt")
	bundle := outputs(t, "isr4451-bundle.txt")
	with := func(m map[string]string, k, v string) map[string]string {
		c := map[string]string{}
		for a, b := range m {
			c[a] = b
		}
		if v == "" {
			delete(c, capture.Key(k))
		} else {
			c[capture.Key(k)] = v
		}
		return c
	}
	img := Image{File: c9kImg, Size: 1197445748, MD5: c9kMD5}
	verifyOK := "verify /md5 bootflash:" + c9kImg + " " + c9kMD5 + "\n....Done!\nVerified (bootflash:" + c9kImg + ") = " + c9kMD5 + "\n"
	run("c9600-ok", base, Image{File: c9kImg, Size: 1197445748, MD5: strings.ToUpper(c9kMD5)}, verifyOK)
	run("c9600-sin-verify", base, img, "")
	run("c9600-md5-mal", base, img, "%Error verifying bootflash:"+c9kImg+"\nComputed signature  = 11111111111111111111111111111111\nSubmitted signature = "+c9kMD5+"\n")
	run("c9600-sin-md5", base, Image{File: c9kImg, Size: 1197445748}, "")
	run("c9600-tamaño", base, Image{File: c9kImg, Size: 1197445749}, "")
	run("c9600-sin-tamaño", base, Image{File: c9kImg}, "")
	run("c9600-fs-prefijo", base, Image{File: "bootflash:" + c9kImg, Size: 1}, "")
	run("c9600-ausente", base, Image{File: "otra.bin", Size: 1 << 20}, "")
	run("c9600-sin-dir", with(base, "dir bootflash:", ""), img, "")
	run("c9600-sin-version", with(base, "show version", ""), img, "")
	run("c9600-sin-instalacion", with(base, "show install summary", ""), img, "")
	run("c9600-uncommitted", with(base, "show install summary", "Type  St   Filename/Version\nIMG   U    17.12.04.0.123\n"), img, "")
	run("c9600-inactivo", with(base, "show install summary", "Type  St   Filename/Version\nIMG   I    17.09.04a.0.1\nIMG   C    17.12.04.0.123\n"), img, "")
	run("c9600-manual-boot", with(base, "show boot", "BOOT variable = bootflash:packages.conf;\nMANUAL_BOOT variable = yes\n"), img, "")
	run("c9600-boot-vacio", with(base, "show boot", ""), img, "")
	run("c9600-boot-mal", with(base, "show boot", "BOOT variable = bootflash:cat9k_iosxe.17.09.04a.SPA.bin;\n"), img, "")
	run("c9600-standby-frio", with(base, "show redundancy", "Operating Redundancy Mode = sso\nPeer Processor Information :\nCurrent Software state = STANDBY COLD\n"), img, "")
	run("c9600-rpr", with(base, "show redundancy", "Operating Redundancy Mode = rpr\nPeer Processor Information :\nCurrent Software state = STANDBY HOT\n"), img, "")
	run("c9600-sin-redundancia", with(base, "show redundancy", ""), img, "")
	run("c9600-sin-cambios", with(base, "show running-config | include configuration change|NVRAM config", "! No configuration change since last restart\n"), img, "")
	run("c9600-sin-guardar", with(base, "show running-config | include configuration change|NVRAM config", "! Last configuration change at 09:40:11 UTC Tue Nov 3 2026 by admin\n"), img, "")
	run("c9600-fechas", with(base, "show running-config | include configuration change|NVRAM config", "! Last configuration change at hoy by admin\n! NVRAM config last updated at ayer by admin\n"), img, "")
	run("c9600-cabecera", with(base, "show running-config | include configuration change|NVRAM config", "nada\n"), img, "")
	run("c9600-guardada-antes", with(base, "show running-config | include configuration change|NVRAM config", "! Last configuration change at 11:40:11 UTC Tue Nov 3 2026 by admin\n! NVRAM config last updated at 09:41:02 UTC Tue Nov 3 2026 by admin\n"), img, "")
	run("c9600-poco-espacio", with(base, "dir bootflash:", strings.Replace(base["dir bootflash:"], "(8016261120 bytes free)", "(1000000000 bytes free)", 1)), img, "")
	for _, reg := range []string{"0x2102\n", "0x2142\n", "0x0\n", "sin registro\n"} {
		run("registro-"+strings.TrimSpace(reg), map[string]string{capture.Key("show version"): "Configuration register is " + reg}, Image{File: "isr4400-universalk9.17.09.04a.SPA.bin"}, "")
	}
	run("isr-bundle", bundle, Image{File: "bootflash:isr4400-universalk9.17.09.04a.SPA.bin", Size: 700000000, MD5: "0123456789abcdef0123456789abcdef"}, "")
	run("isr-bundle-boot-ok", with(bundle, "show boot", "BOOT variable = bootflash:isr4400-universalk9.17.09.04a.SPA.bin;\n"), Image{File: "isr4400-universalk9.17.09.04a.SPA.bin", Size: 1}, "")
	run("isr-sin-boot", with(with(bundle, "show boot", ""), "show bootvar", ""), Image{File: "isr4400-universalk9.17.09.04a.SPA.bin"}, "")
	run("modo-desconocido", map[string]string{capture.Key("show version"): "Cisco IOS XE Software, Version 17.9\n"}, Image{File: "x.bin"}, "")
	run("modo-desconocido-boot", map[string]string{capture.Key("show version"): "Cisco IOS XE Software, Version 17.9\n", capture.Key("show boot"): "BOOT variable = bootflash:x.bin;\n"}, Image{File: "x.bin"}, "")
	// entradas inválidas
	for i, im := range []Image{{}, {File: "a/b.bin"}, {File: "a b.bin"}, {File: "x.bin", MD5: "zz"}, {File: "x.bin", Size: -1}, {File: "bootflash:"}} {
		run("error-"+string(rune('0'+i)), map[string]string{}, im, "")
	}
	return out, ptrs
}

func TestRegresionEs(t *testing.T) {
	got, _ := regCases(t)
	const file = "testdata/regresion_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]golden
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(got))
	for n := range got {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		if got[n] != want[n] {
			t.Errorf("%s: el español cambió\n got: %+v\nwant: %+v", n, got[n], want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("casos: %d vs %d", len(got), len(want))
	}
}
