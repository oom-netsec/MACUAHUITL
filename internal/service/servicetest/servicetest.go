// Package servicetest da un service.Deps real y mínimo para probar un servicio sin el núcleo:
// bitácora y guard verdaderos, bóveda opcional, rutas temporales.
package servicetest

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/service"
	"github.com/oom-netsec/MACUAHUITL/internal/store"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// Deps implementa service.Deps. Job, Patrol y ValidateJob no están: son de Patrol.
type Deps struct {
	T       *testing.T
	Log     *audit.Log
	G       *transport.Guard
	V       *vault.Vault // nil hasta llamar a CreateVault
	Out     string
	Look    func(string) (string, error)
	H       *transport.KnownHosts
	S       *service.CoreSettings
	db      *sql.DB
	clock   func() time.Time
	closers []func()
}

// New arma las dependencias sobre carpetas temporales de t.
func New(t *testing.T) *Deps {
	t.Helper()
	vault.MinMemoryKiB = 8192 // las pruebas bajan el piso del KDF, como las del núcleo
	root := t.TempDir()
	db, err := store.Open(filepath.Join(root, "macuahuitl.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	// Las pruebas viven bajo /tmp (1777): sus ancestros se dan por seguros; la regla real la prueba prefs.
	old := service.AncestorInfo
	service.AncestorInfo = func(string) (os.FileMode, uint32, error) { return 0o755, uint32(os.Getuid()), nil }
	t.Cleanup(func() { service.AncestorInfo = old })
	d := &Deps{T: t, db: db, Out: filepath.Join(root, "o"), clock: time.Now}
	d.S = service.NewCoreSettings(d.Out, root, filepath.Join(root, "data"))
	if d.H, err = transport.OpenKnownHosts(filepath.Join(root, "known_hosts")); err != nil {
		t.Fatal(err)
	}
	d.Log = audit.New(db, d.clock)
	d.G = transport.NewGuard(nil, func(e audit.Entry) { d.Audit(e.Action, e.Target, e.Detail) })
	return d
}

// CreateVault crea una bóveda abierta con parámetros ligeros.
func (d *Deps) CreateVault() *vault.Vault {
	d.T.Helper()
	v, err := vault.Create(filepath.Join(d.T.TempDir(), "vault.mcv"), []byte("maestra"), d.SealParams())
	if err != nil {
		d.T.Fatal(err)
	}
	d.V = v
	d.T.Cleanup(v.LockAll) // suelta la DEK (memoria bloqueada); sin esto -count alto agota el límite de mlock
	return v
}

// AuditText exporta la bitácora completa (JSON por línea).
func (d *Deps) AuditText() string {
	var b bytes.Buffer
	if err := d.ExportAudit(context.Background(), &b, time.Time{}, time.Now().Add(24*time.Hour)); err != nil {
		d.T.Fatal(err)
	}
	return b.String()
}

func (d *Deps) Audit(action, target, detail string) {
	d.Log.Append(context.Background(), audit.Entry{Actor: "tester", Action: action, Target: target, Detail: detail})
}
func (d *Deps) ExportAudit(ctx context.Context, w io.Writer, from, to time.Time) error {
	return d.Log.Export(ctx, w, from, to)
}
func (d *Deps) MarkActive()             {}
func (d *Deps) Now() time.Time          { return d.clock() }
func (d *Deps) Guard() *transport.Guard { return d.G }
func (d *Deps) Vault() *vault.Vault     { return d.V }
func (d *Deps) SealParams() vault.Params {
	return vault.Params{MemoryKiB: 8192, Iterations: 1, Threads: 1}
}
func (d *Deps) DB() *sql.DB                                { return d.db }
func (d *Deps) Outputs() string                            { return d.S.Outputs() }
func (d *Deps) Settings() *service.CoreSettings            { return d.S }
func (d *Deps) DiagLookPath() func(string) (string, error) { return d.Look }
func (d *Deps) Hosts() *transport.KnownHosts               { return d.H }
func (d *Deps) OnClose(f func())                           { d.closers = append(d.closers, f) }

// CloseAll corre lo registrado con OnClose, en orden inverso, como el núcleo al cerrarse.
func (d *Deps) CloseAll() {
	for i := len(d.closers) - 1; i >= 0; i-- {
		d.closers[i]()
	}
	d.closers = nil
}
func (d *Deps) Patrol() v1.PatrolServiceServer { return v1.UnimplementedPatrolServiceServer{} }
func (d *Deps) ValidateJob(*v1.JobSpec) error  { return status.Error(codes.Unimplemented, "sin Patrol") }
func (d *Deps) Job(string) (service.JobInfo, error) {
	return service.JobInfo{}, status.Error(codes.NotFound, "sin Patrol")
}

var _ service.Deps = (*Deps)(nil)
