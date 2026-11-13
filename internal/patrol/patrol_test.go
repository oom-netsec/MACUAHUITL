package patrol

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
	"github.com/oom-netsec/MACUAHUITL/playbooks"
	"github.com/oom-netsec/MACUAHUITL/test/simulator"
)

func TestMain(m *testing.M) {
	vault.MinMemoryKiB = 8192
	os.Exit(m.Run())
}

func transcripts(p string) string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "test", "transcripts", p)
}

type env struct {
	d      Deps
	spec   Spec
	data   string
	simCfg simulator.Config
}

// newEnv levanta simulador + bóveda + auditoría y un Spec válido que apunta al simulador.
func newEnv(t *testing.T, c simulator.Config) *env {
	t.Helper()
	if c.Hostname == "" {
		c.Hostname = "SW-LAB-01"
	}
	c.Username = "admin"
	if c.Password == "" {
		c.Password = "MARKER-PW"
	}
	if c.Enable == "" {
		c.Enable = "MARKER-EN"
	}
	if c.Transcripts == "" {
		c.Transcripts = transcripts("ios-xe")
	}
	addr, _ := simulator.Start(t, c)
	ap := netip.MustParseAddrPort(addr)
	data := t.TempDir()
	v, err := vault.Create(filepath.Join(data, "vault.mcv"), []byte("maestra"), vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	credID, err := v.Put(vault.Credential{Username: "admin", Password: secret.New([]byte(c.Password)), Enable: secret.New([]byte(c.Enable))})
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(data, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hosts, _ := transport.OpenKnownHosts(filepath.Join(data, "known_hosts"))
	pbs, err := playbook.Load(playbooks.FS)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := playbook.Load(os.DirFS("../../packs/ios-xe/playbooks")) // los movidos al paquete oficial oom/ios-xe
	if err != nil {
		t.Fatal(err)
	}
	pbs = append(pbs, pack...)
	return &env{
		d: Deps{Guard: transport.NewGuard(nil, nil), Hosts: hosts, Vault: v, Audit: audit.New(db, time.Now), Now: time.Now, Playbooks: pbs},
		spec: Spec{
			Name: "caso-123", Targets: []Target{{Address: ap.Addr().String(), Port: ap.Port(), DeviceID: "sw1"}},
			DefaultCredentialID: credID, CustomCommands: "show version\nshow running-config\nshow ip interface brief\n",
			OutputDir: t.TempDir(), WindowHours: 1,
		},
		data: data, simCfg: c,
	}
}

// trust hace el Login Test interactivo y acepta la huella del simulador.
func (e *env) trust(t *testing.T) {
	t.Helper()
	r := LoginTest(context.Background(), e.d, "j", e.spec, true, nil)
	if len(r) != 1 || r[0].FailedStep != "host_key" || r[0].Fingerprint == "" {
		t.Fatalf("first login test = %+v", r)
	}
	r = LoginTest(context.Background(), e.d, "j", e.spec, true, map[string]bool{r[0].Fingerprint: true})
	if !r[0].Passed {
		t.Fatalf("login test after accepting = %+v", r)
	}
}

func TestValidateRejects(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	ro := t.TempDir()
	os.Chmod(ro, 0o500)
	t.Cleanup(func() { os.Chmod(ro, 0o700) })
	cases := map[string]func(*Spec){
		"targets":                func(s *Spec) { s.Targets = nil },
		"credential":             func(s *Spec) { s.DefaultCredentialID = "" },
		"window_hours":           func(s *Spec) { s.WindowHours = 0 },
		"window_hours>96":        func(s *Spec) { s.WindowHours = 97 },
		"output_dir":             func(s *Spec) { s.OutputDir = filepath.Join(ro, "no-existe") },
		"output_dir ro":          func(s *Spec) { s.OutputDir = ro },
		"custom_commands":        func(s *Spec) { s.CustomCommands = "show clock\nconf t\n" },
		"commands":               func(s *Spec) { s.CustomCommands = ""; s.PlaybookIDs = nil },
		"playbook_ids":           func(s *Spec) { s.PlaybookIDs = []string{"ios-xe/no-existe"} },
		"credential desconocida": func(s *Spec) { s.DefaultCredentialID = "00112233445566778899aabbccddeeff" },
		"overrides":              func(s *Spec) { s.Overrides = []Override{{DeviceID: "sw1", FallbackCredentialID: "no-existe"}} },
		"schedule cron":          func(s *Spec) { s.Schedule.Cron = "esto no" },
		"schedule ambos":         func(s *Spec) { s.Schedule = Schedule{IntervalSeconds: 60, Cron: "* * * * *"} },
		"schedule until":         func(s *Spec) { s.Schedule.Until = time.Now().Add(-time.Hour) },
	}
	if err := ValidateWith(e.spec, e.d.Playbooks, e.d.Vault, nil); err != nil {
		t.Fatalf("valid spec rejected: %v", err)
	}
	for name, mut := range cases {
		s := e.spec
		mut(&s)
		err := ValidateWith(s, e.d.Playbooks, e.d.Vault, nil)
		var fe *FieldError
		if !errors.As(err, &fe) || !strings.HasPrefix(name, fe.Field) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestLoginTestPasses(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	r := LoginTest(context.Background(), e.d, "j", e.spec, false, nil)
	if !r[0].Passed || r[0].Platform != "ios-xe" {
		t.Fatalf("got %+v", r)
	}
}

func TestLoginTestWrongPassword(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	bad, _ := e.d.Vault.Put(vault.Credential{Username: "admin", Password: secret.New([]byte("mala")), Enable: secret.New([]byte("x"))})
	e.spec.DefaultCredentialID = bad
	if r := LoginTest(context.Background(), e.d, "j", e.spec, false, nil); r[0].FailedStep != "auth" {
		t.Fatalf("got %+v", r)
	}
}

func TestLoginTestWrongEnable(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	bad, _ := e.d.Vault.Put(vault.Credential{Username: "admin", Password: secret.New([]byte("MARKER-PW")), Enable: secret.New([]byte("mala"))})
	e.spec.DefaultCredentialID = bad
	if r := LoginTest(context.Background(), e.d, "j", e.spec, false, nil); r[0].FailedStep != "privilege" {
		t.Fatalf("got %+v", r)
	}
}

func TestLoginTestUnreachable(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.spec.Targets = []Target{{Address: "127.0.0.1", Port: 1, DeviceID: "x"}}
	if r := LoginTest(context.Background(), e.d, "j", e.spec, true, nil); r[0].FailedStep != "tcp" {
		t.Fatalf("got %+v", r)
	}
}

func TestLoginTestChangedKeySilentSkips(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	// Se registra para ese host:puerto la llave de otro simulador: el equipo "cambió de llave".
	_, otherKey := simulator.Start(t, e.simCfg)
	hp := netip.AddrPortFrom(netip.MustParseAddr(e.spec.Targets[0].Address), e.spec.Targets[0].Port).String()
	if err := e.d.Hosts.Add(hp, otherKey); err != nil {
		t.Fatal(err)
	}
	r := LoginTest(context.Background(), e.d, "j", e.spec, false, nil)
	if r[0].Passed || r[0].FailedStep != "host_key" || !strings.Contains(r[0].Detail, "cambiada") {
		t.Fatalf("got %+v", r)
	}
}

func runJob(t *testing.T, e *env, rounds int) (string, Manifest) {
	t.Helper()
	e.trust(t)
	start := time.Now()
	w, err := NewWriter(e.spec.OutputDir, e.spec, start)
	if err != nil {
		t.Fatal(err)
	}
	var results []DeviceResult
	for r := 1; r <= rounds; r++ {
		for _, tg := range e.spec.Targets {
			res := RunDevice(context.Background(), e.d, "j", e.spec, w, r, tg, func(Progress) {})
			if res.State != "completed" {
				t.Fatalf("round %d: %+v", r, res)
			}
			results = append(results, res)
		}
	}
	m, err := Finish(context.Background(), e.d, w, e.spec, rounds, results)
	if err != nil {
		t.Fatal(err)
	}
	return w.Dir(), m
}

func TestPerRoundFiles(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	dir, _ := runJob(t, e, 2)
	files, _ := filepath.Glob(filepath.Join(dir, "SW-LAB-01_*", "r00*_*.txt"))
	if len(files) != 2 {
		t.Fatalf("files = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if !strings.Contains(string(b), "===== ") || !strings.Contains(string(b), "show version") || !strings.Contains(string(b), "Cisco IOS XE Software") {
		t.Fatalf("content:\n%s", b)
	}
}

func TestConsolidatedFile(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.spec.Split = SplitConsolidated
	dir, _ := runJob(t, e, 2)
	files, _ := filepath.Glob(filepath.Join(dir, "SW-LAB-01_*", "*.txt"))
	if len(files) != 1 {
		t.Fatalf("files = %v", files)
	}
	b, _ := os.ReadFile(files[0])
	if strings.Count(string(b), "===== ronda 1 ·") != 3 || strings.Count(string(b), "===== ronda 2 ·") != 3 {
		t.Fatalf("headers wrong:\n%s", b[:min(len(b), 400)])
	}
}

func TestMaskedOutputHasNoMarker(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	dir, m := runJob(t, e, 1)
	if grepDir(t, dir, "MARKER-SNMP") || !m.Masked {
		t.Fatalf("masked job leaked or manifest.masked=%v", m.Masked)
	}
	e2 := newEnv(t, simulator.Config{})
	e2.spec.DisableMasking = true
	dir2, m2 := runJob(t, e2, 1)
	if !grepDir(t, dir2, "MARKER-SNMP") || m2.Masked {
		t.Fatalf("unmasked job should keep the secret, manifest.masked=%v", m2.Masked)
	}
}

func TestManifestHashes(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	dir, m := runJob(t, e, 1)
	if len(m.Files) == 0 {
		t.Fatal("no files in manifest")
	}
	for _, f := range m.Files {
		b, err := os.ReadFile(filepath.Join(dir, f.Path))
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(b); hex.EncodeToString(sum[:]) != f.SHA256 {
			t.Errorf("hash mismatch for %s", f.Path)
		}
	}
	head, _ := e.d.Audit.Head(context.Background())
	if m.AuditHead != head {
		t.Fatalf("audit head %s != %s", m.AuditHead, head)
	}
	var onDisk Manifest
	b, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err := json.Unmarshal(b, &onDisk); err != nil || onDisk.AuditHead != head {
		t.Fatalf("manifest.json = %s (%v)", b, err)
	}
}

func TestZipContents(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.spec.DeleteLooseFiles = true
	dir, m := runJob(t, e, 1)
	zips, _ := filepath.Glob(filepath.Join(dir, "*.zip"))
	if len(zips) != 1 {
		t.Fatalf("zips = %v", zips)
	}
	zr, err := zip.OpenReader(zips[0])
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	names := map[string]bool{}
	for _, f := range zr.File {
		names[f.Name] = true
	}
	if !names["manifest.json"] {
		t.Fatalf("zip lacks manifest: %v", names)
	}
	for _, f := range m.Files {
		if !names[f.Path] {
			t.Errorf("zip lacks %s", f.Path)
		}
		if _, err := os.Stat(filepath.Join(dir, f.Path)); !os.IsNotExist(err) {
			t.Errorf("loose file %s not deleted", f.Path)
		}
	}
}

func TestNoLeakEndToEnd(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.spec.Zip = ZipAtEnd
	dir, _ := runJob(t, e, 2)
	for _, marker := range []string{"MARKER-PW", "MARKER-EN"} {
		for _, needle := range []string{marker, base64.StdEncoding.EncodeToString([]byte(marker)), hex.EncodeToString([]byte(marker))} {
			for _, root := range []string{dir, e.data} {
				if grepDir(t, root, needle) {
					t.Errorf("%q found under %s", needle, root)
				}
			}
		}
	}
}

// grepDir busca needle en todos los archivos bajo root, incluido el contenido descomprimido de los zip.
func grepDir(t *testing.T, root, needle string) bool {
	t.Helper()
	found := false
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || found {
			return err
		}
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(needle)) {
			found = true
		}
		if strings.HasSuffix(p, ".zip") {
			zr, err := zip.OpenReader(p)
			if err == nil {
				for _, f := range zr.File {
					rc, _ := f.Open()
					c, _ := io.ReadAll(rc)
					rc.Close()
					if bytes.Contains(c, []byte(needle)) {
						found = true
					}
				}
				zr.Close()
			}
		}
		return nil
	})
	return found
}

func TestZipPerRound(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	e.spec.Zip = ZipPerRound
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	for r := 1; r <= 2; r++ {
		RunDevice(context.Background(), e.d, "j", e.spec, w, r, e.spec.Targets[0], func(Progress) {})
		p, err := RoundDone(w, e.spec, r)
		if err != nil || p == "" {
			t.Fatalf("round %d zip: %q %v", r, p, err)
		}
		zr, err := zip.OpenReader(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(zr.File) != 1 || !strings.Contains(zr.File[0].Name, "r00") {
			t.Fatalf("round %d zip contents: %v", r, zr.File)
		}
		zr.Close()
	}
}

func TestFallbackCredential(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	good := e.spec.DefaultCredentialID
	bad, _ := e.d.Vault.Put(vault.Credential{Username: "admin", Password: secret.New([]byte("tacacs-caido")), Enable: secret.New([]byte("x"))})
	e.spec.DefaultCredentialID = bad
	e.spec.Overrides = []Override{{DeviceID: "sw1", FallbackCredentialID: good}}
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	// Sin Login Test previo exitoso de la principal, el rechazo es rechazo: no hay respaldo (spec §10.2).
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "failed" {
		t.Fatalf("fallback used after a plain password rejection: %+v", res)
	}
	e.d.PrimaryVerified = map[string]bool{hostport(e.spec.Targets[0]): true}
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "completed" {
		t.Fatalf("fallback not used after the primary had been verified: %+v", res)
	}
	var buf bytes.Buffer
	e.d.Audit.Export(context.Background(), &buf, time.Time{}, time.Now().Add(time.Hour))
	if !strings.Contains(buf.String(), `"action":"auth.fallback"`) {
		t.Fatal("fallback not audited")
	}
}

func TestChangedKeyAcceptedWhenAllowed(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	_, otherKey := simulator.Start(t, e.simCfg)
	e.d.Hosts.Add(hostport(e.spec.Targets[0]), otherKey)
	e.spec.AcceptChangedHostKeys = true
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {})
	if res.State != "completed" || res.ChangedHostKey == nil {
		t.Fatalf("got %+v", res)
	}
	m, _ := Finish(context.Background(), e.d, w, e.spec, 1, []DeviceResult{res})
	if len(m.ChangedHostKeys) != 1 {
		t.Fatalf("manifest changed keys = %v", m.ChangedHostKeys)
	}
}

func TestChangedKeySkippedByDefault(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	e.trust(t)
	_, otherKey := simulator.Start(t, e.simCfg)
	e.d.Hosts.Add(hostport(e.spec.Targets[0]), otherKey)
	w, _ := NewWriter(e.spec.OutputDir, e.spec, time.Now())
	if res := RunDevice(context.Background(), e.d, "j", e.spec, w, 1, e.spec.Targets[0], func(Progress) {}); res.State != "skipped" {
		t.Fatalf("got %+v", res)
	}
}

func TestLoginTestCorruptKnownHosts(t *testing.T) {
	e := newEnv(t, simulator.Config{})
	os.WriteFile(filepath.Join(e.data, "known_hosts"), []byte("basura\n"), 0o600)
	if r := LoginTest(context.Background(), e.d, "j", e.spec, true, nil); r[0].FailedStep != "host_key" || r[0].Fingerprint != "" {
		t.Fatalf("got %+v", r)
	}
}

func credential(pw string) vault.Credential {
	return vault.Credential{Username: "admin", Password: secret.New([]byte(pw)), Enable: secret.New([]byte("x"))}
}
