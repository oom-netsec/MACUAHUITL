package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/backup"
	"github.com/oom-netsec/MACUAHUITL/internal/core"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

const mctlRunning = "hostname SW1\n!\nntp server 10.0.0.1\n!\ninterface GigabitEthernet1/0/1\n description PC-ventas\n switchport access vlan 10\n switchport mode access\n!\ninterface Vlan1\n ip address 127.0.0.1 255.0.0.0\n!\nend\n"
const mctlBackup = "hostname SW1\n!\nntp server 10.0.0.2\n!\ninterface GigabitEthernet1/0/1\n description PC-contabilidad\n switchport access vlan 30\n switchport mode access\n!\ninterface Vlan1\n ip address 127.0.0.1 255.0.0.0\n!\nend\n"

type restoreEnv struct {
	addr, cred, fp, id string
	rec                *simulator.Recorder
	store              backup.Store
}

func restoreRig(t *testing.T, backupText string, masked bool) restoreEnv {
	t.Helper()
	// La bóveda se crea antes de arrancar el núcleo, con la llave que firma las fichas (una entrada reservada: por la CLI no se puede crear).
	var cred string
	var key []byte
	e := startCoreWith(t, func(p core.Paths) {
		vault.MinMemoryKiB = 8192
		if err := os.MkdirAll(p.Data, 0o700); err != nil {
			t.Fatal(err)
		}
		v, err := vault.Create(filepath.Join(p.Data, "vault.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
		if err != nil {
			t.Fatal(err)
		}
		if cred, err = v.Put(vault.Credential{Label: "lab", Username: "admin", Password: secret.New([]byte("pw-lab")), Enable: secret.New([]byte("en-lab"))}); err != nil {
			t.Fatal(err)
		}
		if key, err = service.BackupKey(v, true); err != nil {
			t.Fatal(err)
		}
		v.LockAll()
	})
	must(t, "maestra\n", "vault", "unlock")
	_, f, _, _ := runtime.Caller(0)
	rec := &simulator.Recorder{}
	addr, hk := simulator.Start(t, simulator.Config{Hostname: "SW1", Username: "admin", Password: "pw-lab", Enable: "en-lab", Running: mctlRunning, Recorder: rec, Vlans: []int{1, 10, 30},
		Commands: map[string]string{
			"show version":            "Cisco IOS Software, C3560CX Software, Version 15.2(7)E\nProcessor board ID FOC0001A0AA\n",
			"show users":              "*  2 vty 0     admin      idle                 00:00:00 127.0.0.1\n",
			"show tcp brief":          "TCB  Local Address  Foreign Address  (state)\n7F1A  127.0.0.1.22  127.0.0.1.51234  ESTAB\n",
			"show ip route 127.0.0.1": "Default gateway is 127.0.0.2\n\nHost               Gateway           Last Use    Total Uses  Interface\nICMP redirect cache is empty\n",
		},
		Transcripts: filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", "ios-xe")})
	st := backup.Store{Root: filepath.Join(e.out, "respaldos"), Key: key}
	ent, _, err := st.Save(backup.Entry{Device: "SW1_127.0.0.1", Kind: backup.Running, At: time.Unix(1_700_000_000, 0), Masked: masked, Serial: "FOC0001A0AA"}, backupText)
	if err != nil {
		t.Fatal(err)
	}
	return restoreEnv{addr: addr, cred: cred, fp: transport.Fingerprint(hk), id: ent.ID, rec: rec, store: st}
}

func (e restoreEnv) args(rest ...string) []string {
	return append([]string{"restore", "diff", e.addr, e.id, "--cred", e.cred, "--accept", e.fp}, rest...)
}

func TestRestoreDiffWithoutAsistidoOnlyPrintsPlanWithRollback(t *testing.T) {
	e := restoreRig(t, mctlBackup, false)
	out := must(t, "", e.args()...)
	for _, w := range []string{"Aplicar", "ntp server 10.0.0.2", "no ntp server 10.0.0.1", "description PC-contabilidad", "REVERSA", "description PC-ventas", "no se cambió nada"} {
		if !strings.Contains(out, w) {
			t.Errorf("falta %q:\n%s", w, out)
		}
	}
	if len(e.rec.Lines()) != 0 {
		t.Fatalf("sin --asistido llegó configuración: %q", e.rec.Lines())
	}
}

func TestRestoreDiffRefusesMaskedBackupAndListsRefusals(t *testing.T) {
	e := restoreRig(t, mctlBackup, true)
	if out, err := mctl(t, "", e.args()...); err == nil || !strings.Contains(err.Error(), "enmascarados") {
		t.Fatalf("un respaldo enmascarado se rechaza con mensaje claro: err=%v\n%s", err, out)
	}
	e = restoreRig(t, strings.Replace(mctlBackup, "ntp server", "vtp mode client\nntp server", 1), false)
	out, err := mctl(t, "", e.args()...)
	if err == nil || !strings.Contains(out, "PLAN RECHAZADO") || !strings.Contains(out, "vtp mode client") || !strings.Contains(out, "hazlo a mano") {
		t.Fatalf("err=%v\n%s", err, out)
	}
	out, err = mctl(t, "", e.args("--parcial")...)
	if err != nil || !strings.Contains(out, "No se restaura (plan parcial") || strings.Contains(strings.SplitN(out, "No se restaura", 2)[0], "vtp") {
		t.Fatalf("parcial: err=%v\n%s", err, out)
	}
	if len(e.rec.Lines()) != 0 {
		t.Fatal("nada se envía sin --asistido")
	}
}

func TestRestoreDiffAsistidoAsksPerStepAndApplies(t *testing.T) {
	e := restoreRig(t, mctlBackup, false)
	for _, in := range []string{"", "n\n"} {
		if _, err := mctl(t, in, e.args("--asistido")...); err == nil || len(e.rec.Lines()) != 0 {
			t.Fatalf("stdin %q: err=%v lines=%q", in, err, e.rec.Lines())
		}
	}
	out := must(t, "s\ns\n", e.args("--asistido")...)
	if !strings.Contains(out, "MODO ASISTIDO ACTIVO") || !strings.Contains(out, "Listo") {
		t.Fatalf("salida:\n%s", out)
	}
	want := "ntp server 10.0.0.2|no ntp server 10.0.0.1|interface GigabitEthernet1/0/1|description PC-contabilidad|switchport access vlan 30|end"
	if got := strings.Join(e.rec.Lines(), "|"); got != want {
		t.Fatalf("el equipo recibió %q", got)
	}
}

func TestRestoreDiffFlagsAreChecked(t *testing.T) {
	e := restoreRig(t, mctlBackup, false)
	for _, bad := range [][]string{{"--max-lines", "5000"}, {"--max-lines", "-1"}} {
		if out, err := mctl(t, "", e.args(bad...)...); err == nil {
			t.Errorf("%v aceptado:\n%s", bad, out)
		}
	}
	if _, err := mctl(t, "", "restore", "diff", e.addr, "--cred", e.cred); err == nil {
		t.Error("sin respaldo")
	}
	if out, err := mctl(t, "", e.args("--max-lines", "2")...); err == nil || !strings.Contains(err.Error(), "tope") {
		t.Errorf("tope: %v\n%s", err, out)
	}
}
