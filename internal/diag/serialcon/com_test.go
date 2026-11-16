package serialcon

import (
	"slices"
	"testing"
)

func TestComPath(t *testing.T) {
	for in, want := range map[string]string{
		"COM3": `\\.\COM3`, "com10": `\\.\COM10`, `\\.\COM12`: `\\.\COM12`, " COM1 ": `\\.\COM1`,
	} {
		if got, ok := comPath(in); !ok || got != want {
			t.Errorf("comPath(%q) = %q, %v; se esperaba %q", in, got, ok, want)
		}
	}
	for _, in := range []string{"", "COM", "COM0", "COM256", "COMx", "COM3x", `C:\x`, `\\.\C:`, `\\.\PhysicalDrive0`, `\\.\pipe\x`, "NUL", "COM-1", "COM+3", "../COM3", "/dev/ttyUSB0"} {
		if got, ok := comPath(in); ok {
			t.Errorf("comPath(%q) aceptó %q", in, got)
		}
	}
}

func TestListCOMOrdenaPorNumeroYFiltra(t *testing.T) {
	vals := []string{"COM10", "COM3", "basura", `\Device\x`, "COM2", "COM3", "com1", "COM300"}
	if got, want := listCOM(vals), []string{"COM1", "COM2", "COM3", "COM10"}; !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if got := listCOM(nil); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestDCBFlags(t *testing.T) {
	const (
		binario, paridad, outCTS = 1 << 0, 1 << 1, 1 << 2
		dtrOn                    = 1 << 4
		outX, inX                = 1 << 8, 1 << 9
		rtsOn, rtsHand           = 1 << 12, 2 << 12
	)
	for _, c := range []struct {
		cfg  Config
		want uint32
	}{
		{Config{Parity: "none", Flow: "none"}, binario | dtrOn | rtsOn},
		{Config{Parity: "even", Flow: "none"}, binario | paridad | dtrOn | rtsOn},
		{Config{Parity: "none", Flow: "rtscts"}, binario | dtrOn | outCTS | rtsHand},
		{Config{Parity: "odd", Flow: "xonxoff"}, binario | paridad | dtrOn | rtsOn | outX | inX},
	} {
		if got := dcbFlags(c.cfg); got != c.want {
			t.Errorf("%+v: %#x; se esperaba %#x", c.cfg, got, c.want)
		}
	}
}
