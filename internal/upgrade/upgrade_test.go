package upgrade

import (
	"os"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/capture"
)

func outputs(t *testing.T, name string) map[string]string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return capture.Split(string(b))
}

func items(r Report) map[string]Item {
	m := map[string]Item{}
	for _, i := range r.Items {
		m[i.ID] = i
	}
	return m
}

const (
	c9kImg = "cat9k_iosxe.17.12.04.SPA.bin"
	c9kMD5 = "7c2fe5e8a1f6a8e4ad3cd1c7a2d1b0e9"
)

func TestC9600InstallSSOAllPass(t *testing.T) {
	verify := "verify /md5 bootflash:" + c9kImg + " " + c9kMD5 + "\n....Done!\nVerified (bootflash:" + c9kImg + ") = " + c9kMD5 + "\n"
	r, err := Check(outputs(t, "c9600-install-sso.txt"), Image{File: c9kImg, Size: 1197445748, MD5: strings.ToUpper(c9kMD5)}, verify)
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != "install" || r.FileSystem != "bootflash:" || r.Hostname != "C9600-CORE-01" || r.Version != "17.09.04a" {
		t.Fatalf("report = %+v", r)
	}
	for _, i := range r.Items {
		if i.Status != Pass {
			t.Errorf("%s = %s: %s", i.ID, i.Status, i.Detail)
		}
	}
	if len(r.Items) != 9 {
		t.Fatalf("items = %d", len(r.Items))
	}
}

func TestISRBundleFailures(t *testing.T) {
	r, err := Check(outputs(t, "isr4451-bundle.txt"), Image{File: "bootflash:isr4400-universalk9.17.09.04a.SPA.bin", Size: 700000000, MD5: "0123456789abcdef0123456789abcdef"}, "")
	if err != nil {
		t.Fatal(err)
	}
	m := items(r)
	want := map[string]Status{"mode": Pass, "space": Fail, "image-present": Fail, "md5": Unknown, "boot": Fail,
		"install-state": NotApplicable, "config-saved": Fail, "redundancy": NotApplicable, "config-register": Pass}
	for id, st := range want {
		if m[id].Status != st {
			t.Errorf("%s = %s (%s), want %s", id, m[id].Status, m[id].Detail, st)
		}
	}
	if r.Mode != "bundle" || !strings.Contains(m["mode"].Detail, "bundle") {
		t.Errorf("mode = %q %+v", r.Mode, m["mode"])
	}
	if !strings.Contains(m["boot"].Detail, "isr4400-universalk9.16.12.04.SPA.bin") {
		t.Errorf("boot detail = %q", m["boot"].Detail)
	}
	if len(r.Commands) == 0 || r.Commands[0] != "verify /md5 bootflash:isr4400-universalk9.17.09.04a.SPA.bin 0123456789abcdef0123456789abcdef" {
		t.Errorf("commands = %q", r.Commands)
	}
	if !strings.Contains(r.Text(), "FALLA") || !strings.Contains(r.Note, "sin validar en laboratorio") {
		t.Errorf("text:\n%s", r.Text())
	}
}

func TestMD5Mismatch(t *testing.T) {
	verify := "%Error verifying bootflash:" + c9kImg + "\nComputed signature  = 11111111111111111111111111111111\nSubmitted signature = " + c9kMD5 + "\n"
	r, _ := Check(outputs(t, "c9600-install-sso.txt"), Image{File: c9kImg, Size: 1197445748, MD5: c9kMD5}, verify)
	if i := items(r)["md5"]; i.Status != Fail || !strings.Contains(i.Detail, "11111111") {
		t.Fatalf("md5 = %+v", i)
	}
}

func TestEdgeCases(t *testing.T) {
	base := outputs(t, "c9600-install-sso.txt")
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range base {
			m[a] = b
		}
		if v == "" {
			delete(m, capture.Key(k))
		} else {
			m[capture.Key(k)] = v
		}
		return m
	}
	img := Image{File: c9kImg, Size: 1197445748, MD5: c9kMD5}
	cases := []struct {
		name string
		out  map[string]string
		img  Image
		id   string
		want Status
	}{
		{"size mismatch", base, Image{File: c9kImg, Size: 1197445749}, "image-present", Fail},
		{"no size", base, Image{File: c9kImg}, "space", Unknown},
		{"no dir", with("dir bootflash:", ""), img, "space", Unknown},
		{"uncommitted", with("show install summary", "Type  St   Filename/Version\nIMG   U    17.12.04.0.123\n"), img, "install-state", Fail},
		{"manual boot", with("show boot", "BOOT variable = bootflash:packages.conf;\nMANUAL_BOOT variable = yes\n"), img, "boot", Fail},
		{"cat9300 boot format", with("show boot", "Current Boot Variables:\nBOOT variable = flash:old.bin;\n\nBoot Variables on next reload:\nBOOT variable = bootflash:packages.conf;\nManual Boot = no\n"), img, "boot", Pass},
		{"install boot wrong", with("show boot", "BOOT variable = bootflash:cat9k_iosxe.17.09.04a.SPA.bin;\n"), img, "boot", Fail},
		{"standby not hot", with("show redundancy", "Operating Redundancy Mode = sso\nPeer Processor Information :\nCurrent Software state = STANDBY COLD\n"), img, "redundancy", Fail},
		{"no change since restart", with("show running-config | include configuration change|NVRAM config", "! No configuration change since last restart\n"), img, "config-saved", Pass},
		{"never saved", with("show running-config | include configuration change|NVRAM config", "! Last configuration change at 09:40:11 UTC Tue Nov 3 2026 by admin\n"), img, "config-saved", Fail},
		{"install expansion", with("dir bootflash:", strings.Replace(base["dir bootflash:"], "(8016261120 bytes free)", "(1000000000 bytes free)", 1)), img, "space", Fail},
		{"no redundancy output", with("show redundancy", ""), img, "redundancy", Unknown},
	}
	for _, c := range cases {
		r, err := Check(c.out, c.img, "")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if i := items(r)[c.id]; i.Status != c.want {
			t.Errorf("%s: %s = %s (%s), want %s", c.name, c.id, i.Status, i.Detail, c.want)
		}
	}
}

func TestBadInput(t *testing.T) {
	for _, img := range []Image{{}, {File: "a/b.bin"}, {File: "x.bin", MD5: "zz"}, {File: "x.bin", Size: -1}} {
		if _, err := Check(map[string]string{}, img, ""); err == nil {
			t.Errorf("%+v accepted", img)
		}
	}
}

func TestConfigRegister(t *testing.T) {
	img := Image{File: "isr4400-universalk9.17.09.04a.SPA.bin"}
	for _, c := range []struct {
		ver  string
		want Status
	}{{"Configuration register is 0x2102\n", Pass}, {"Configuration register is 0x2142\n", Fail},
		{"Configuration register is 0x0\n", Fail}, {"sin registro\n", Unknown}} {
		o := map[string]string{capture.Key("show version"): c.ver}
		r, err := Check(o, img, "")
		if err != nil {
			t.Fatal(err)
		}
		if got := items(r)["config-register"]; got.Status != c.want {
			t.Errorf("%q = %s (%s), want %s", c.ver, got.Status, got.Detail, c.want)
		}
	}
}
