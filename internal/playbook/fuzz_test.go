package playbook

import (
	"strings"
	"testing"
)

var fuzzPlatforms = []string{"ios", "ios-xe", "nx-os", "asa", "ftd", "ise", "wlc-aireos", "wlc-9800", ""}

func FuzzCheckDenied(f *testing.F) {
	for _, c := range []string{
		"show version", "show running-config | include ^!", "show interfaces | section Gi1",
		"ping 10.0.0.1 repeat 3", "traceroute 10.0.0.1", "show version ; reload", "show x | redirect flash:x",
		"show version > flash:x", "show `id`", "show $(id)", "show x || y", "show x & y", "show ?",
		"show logging | include \"a|b\"", "show run | begin ^$", "terminal length 0", "show tech-support | exclude x",
		"show interface {interface}", "show x\x00", "copy run tftp:", "show file systems", "show x | grep 'a'",
		"show ip route *", "show x [a]", "show (x)", "dir bootflash:", "ping vrf mgmt 10.0.0.1 count 3",
	} {
		for p := range fuzzPlatforms {
			f.Add(byte(p), c)
		}
	}
	f.Fuzz(func(t *testing.T, p byte, cmd string) {
		plat := fuzzPlatforms[int(p)%len(fuzzPlatforms)]
		if CheckDenied(plat, cmd) != nil {
			return
		}
		if m := violation(plat, cmd); m != "" {
			t.Fatalf("SEGURIDAD: %q aceptó %q: %s", plat, cmd, m)
		}
	})
}

// violation dice qué carácter prohibido trae un comando que CheckDenied dejó pasar ("" = ninguno).
func violation(plat, cmd string) string {
	for _, r := range cmd {
		if r < 0x20 || r > 0x7e {
			return "byte fuera de 0x20-0x7e"
		}
	}
	bad := []string{";", "&", "<", ">", "`", "$(", "||", "?"}
	if plat == "nx-os" {
		bad = append(bad, "$", "!", `\`, "'", "(", ")")
	}
	for _, b := range bad {
		if strings.Contains(cmd, b) {
			return "contiene " + b
		}
	}
	if plat == "nx-os" {
		for i, in := 0, false; i < len(cmd); i++ {
			if cmd[i] == '"' {
				in = !in
			} else if !in && (cmd[i] == '*' || cmd[i] == '[') {
				return "contiene " + string(cmd[i]) + " fuera de comillas"
			}
		}
	}
	return ""
}

func FuzzExpand(f *testing.F) {
	f.Add(byte(0), byte(0), "aa:bb:cc:dd:ee:ff")
	f.Add(byte(1), byte(1), "ap-01")
	f.Add(byte(2), byte(2), "10")
	f.Add(byte(3), byte(3), "GigabitEthernet1/0/1")
	f.Add(byte(4), byte(4), "10.0.0.1")
	f.Add(byte(4), byte(4), "fe80::1%eth0")
	f.Add(byte(3), byte(2), "Gi1;reload")
	f.Fuzz(func(t *testing.T, k, p byte, v string) {
		kind := ParamKinds[int(k)%len(ParamKinds)]
		plat := fuzzPlatforms[int(p)%len(fuzzPlatforms)]
		if got, err := ValidateValue(kind, v); err == nil {
			for _, r := range got {
				if r < 0x21 || r > 0x7e || strings.ContainsRune(";|&<>`$?!\\'\"()*[]{}", r) {
					t.Fatalf("SEGURIDAD: ValidateValue(%q,%q) = %q con %q", kind, v, got, r)
				}
			}
		}
		pb := Playbook{
			ID: "x", Platform: plat, Params: []Param{{"v", kind}},
			Commands: []Command{{Text: "show wireless client {v} detail"}, {Text: "show interface {v} | include up"}},
		}
		cmds, err := pb.Expand(map[string]string{"v": v})
		if err != nil {
			return
		}
		got, verr := ValidateValue(kind, v)
		if verr != nil {
			t.Fatalf("Expand aceptó %q que ValidateValue rechaza (%q)", v, kind)
		}
		if kind == "mac" && plat == "wlc-aireos" { // AireOS pide aa:bb:cc:dd:ee:ff
			got = got[0:2] + ":" + got[2:4] + ":" + got[5:7] + ":" + got[7:9] + ":" + got[10:12] + ":" + got[12:14]
		}
		for _, c := range cmds {
			if m := violation(plat, c.Text); m != "" {
				t.Fatalf("SEGURIDAD: Expand dejó pasar %q (%s)", c.Text, m)
			}
			if !strings.Contains(c.Text, got) || strings.Contains(c.Text, "{v}") {
				t.Fatalf("el valor %q no aparece literal en %q", got, c.Text)
			}
		}
	})
}
