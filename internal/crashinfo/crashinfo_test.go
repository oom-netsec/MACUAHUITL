package crashinfo

import (
	"os"
	"strings"
	"testing"
)

func fx(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSegV(t *testing.T) {
	r, err := Parse(fx(t, "ios15_segv.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindCrashinfo || r.Binary {
		t.Fatalf("tipo %q binario %v", r.Kind, r.Binary)
	}
	if !strings.Contains(r.Reason, "SegV exception") || r.PC != "0x1A2B3C4" {
		t.Fatalf("motivo %q pc %q", r.Reason, r.PC)
	}
	if r.Process != "IP Input" || r.PID != 58 {
		t.Fatalf("proceso %q pid %d", r.Process, r.PID)
	}
	if len(r.Traceback) != 5 || r.Traceback[0] != "0x1A2B3C4" || r.Traceback[4] != "0x1C0FFEE" {
		t.Fatalf("traceback %v", r.Traceback)
	}
	if r.Version != "15.2(7)E3" || r.Model != "C3560CX" || r.Host != "sw-lab" {
		t.Fatalf("versión %q modelo %q host %q", r.Version, r.Model, r.Host)
	}
	if r.Uptime != "2 weeks, 3 days, 4 hours, 12 minutes" {
		t.Fatalf("uptime %q", r.Uptime)
	}
	if r.CPU == nil || r.CPU.FiveSec != 87 || r.CPU.FiveMin != 61 {
		t.Fatalf("cpu %+v", r.CPU)
	}
	if r.Memory == nil || r.Memory.Free != 1205384 || r.Memory.FreePct < 4.6 || r.Memory.FreePct > 4.7 {
		t.Fatalf("memoria %+v", r.Memory)
	}
	if len(r.Mnemonics) != 1 || r.Mnemonics[0] != "%SYS-2-MALLOCFAIL" {
		t.Fatalf("mnemónicos %v", r.Mnemonics)
	}
}

func TestSoftwareForced(t *testing.T) {
	r, _ := Parse(fx(t, "ios15_forced.txt"))
	if r.Reason != "Software-forced reload" || r.PC != "0x2C4D5E6" || r.Process != "Spanning Tree" || len(r.Traceback) != 3 {
		t.Fatalf("%+v", r)
	}
	if r.CPU != nil || r.Memory != nil {
		t.Fatal("inventó CPU o memoria que el archivo no trae")
	}
}

func TestIOSXE(t *testing.T) {
	r, _ := Parse(fx(t, "iosxe_pman.txt"))
	if !strings.Contains(r.Reason, "Critical process iosd fault") || r.Process != "iosd" || r.Version != "17.09.04a" {
		t.Fatalf("%+v", r)
	}
	if len(r.Mnemonics) != 2 {
		t.Fatalf("mnemónicos %v", r.Mnemonics)
	}
}

func TestBinarioSeIdentificaSinParsear(t *testing.T) {
	core := "\x7fELF\x02\x01\x01" + strings.Repeat("\x00", 100) + "Version 15.2(7)E3 SegV"
	r, err := Parse(core)
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != KindCore || !r.Binary || r.Reason != "" || !strings.Contains(r.Hint, "TAC") {
		t.Fatalf("%+v", r)
	}
	r2, _ := Parse(strings.Repeat("\x01\x02\xfe\xff", 500))
	if !r2.Binary {
		t.Fatal("no detectó un binario sin NUL")
	}
}

func TestDesconocidoYVacio(t *testing.T) {
	if _, err := Parse("  \n"); err == nil {
		t.Fatal("texto vacío aceptado")
	}
	r, err := Parse(fx(t, "not_crash.txt"))
	if err != nil || r.Kind != KindUnknown || len(r.Warnings) == 0 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestTopesDeEntrada(t *testing.T) {
	big := "System returned to ROM by bus error at PC 0x10, address 0x0\n" + strings.Repeat("x", MaxBytes)
	r, err := Parse(big)
	if err != nil || !r.Truncated || r.Reason == "" {
		t.Fatalf("truncado=%v err=%v", r.Truncated, err)
	}
	// Una línea gigante se recorta y no se pierde el resto.
	long := strings.Repeat("A", 1<<20) + "\nSystem returned to ROM by power-on\n"
	r, _ = Parse(long)
	if r.Reason != "power-on" {
		t.Fatalf("motivo tras línea gigante: %q", r.Reason)
	}
	if r, _ = Parse("System returned to ROM by " + strings.Repeat("B", 3*MaxLine) + "\n"); len(r.Reason) > MaxLine {
		t.Fatalf("línea sin recortar: %d", len(r.Reason))
	}
	if r, _ = Parse("texto normal\x00con un NUL\n"); !r.Binary {
		t.Fatal("un NUL debe tratarse como binario")
	}
	// Un traceback interminable se acota.
	tb := "-Traceback= " + strings.Repeat("0x1 ", 5000) + "\n"
	r, _ = Parse(tb)
	if len(r.Traceback) != MaxTraceback {
		t.Fatalf("traceback %d", len(r.Traceback))
	}
	var many strings.Builder
	for i := 0; i < 500; i++ {
		many.WriteString("%SYS-5-X" + strings.Repeat("A", i%7) + "-" + "1" + "-Y\n")
	}
	if r, _ = Parse(many.String()); len(r.Mnemonics) > MaxMnemonics {
		t.Fatalf("mnemónicos %d", len(r.Mnemonics))
	}
}

func FuzzParse(f *testing.F) {
	for _, n := range []string{"ios15_segv.txt", "ios15_forced.txt", "iosxe_pman.txt", "not_crash.txt"} {
		b, _ := os.ReadFile("testdata/" + n)
		f.Add(string(b))
	}
	f.Add("\x7fELF\x00\x00")
	f.Add("-Traceback= 0x -Process= \"\", ipl= , pid= ")
	f.Fuzz(func(t *testing.T, s string) {
		r, err := Parse(s)
		if err == nil && len(r.Traceback) > MaxTraceback {
			t.Fatal("traceback sin tope")
		}
	})
}

func TestText(t *testing.T) {
	r, _ := Parse(fx(t, "ios15_segv.txt"))
	out := r.Text()
	for _, w := range []string{"Motivo: error - a SegV exception", "Proceso: IP Input (pid 58)", "Versión: 15.2(7)E3", "Memoria al fallar: 4.7% libre", "Tiempo en línea antes de la falla: 2 weeks"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q en:\n%s", w, out)
		}
	}
}
