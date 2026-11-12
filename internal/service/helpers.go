package service

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

var toolRuns atomic.Uint64

// RunID da el identificador de una ejecución de herramienta; también nombra su autorización en el guard.
func RunID(kind string) string { return fmt.Sprintf("tools-%s-%d", kind, toolRuns.Add(1)) }

// Report empaqueta un resultado como JSON más texto legible (vacío = JSON indentado).
func Report(v any, text string) *v1.ToolReport {
	b, _ := json.Marshal(v)
	if text == "" {
		ib, _ := json.MarshalIndent(v, "", "  ")
		text = string(ib)
	}
	return &v1.ToolReport{Json: string(b), Text: text}
}

// MS convierte milisegundos de una petición en Duration; <=0 toma def.
func MS(v int32, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return time.Duration(v) * time.Millisecond
}

// SyslogDuration evita un socket olvidado escuchando para siempre: 1 h por defecto, 24 h máximo.
func SyslogDuration(secs int32) time.Duration {
	switch d := time.Duration(secs) * time.Second; {
	case secs <= 0:
		return time.Hour
	case d > 24*time.Hour:
		return 24 * time.Hour
	default:
		return d
	}
}

// BackupKeyLabel es la etiqueta de la entrada de la bóveda que guarda la llave HMAC con que se firman las fichas de los respaldos.
const BackupKeyLabel = "macuahuitl:llave-de-respaldos"

var backupKeyMu sync.Mutex

// BackupKey devuelve la llave (32 bytes) con que se firman y verifican las fichas de los respaldos. Vive en la bóveda abierta; con create se
// genera la primera vez. Sin bóveda abierta devuelve vault.ErrLocked; sin llave y sin create, vault.ErrNotFound.
func BackupKey(v *vault.Vault, create bool) ([]byte, error) {
	if v == nil || !v.Unlocked() {
		return nil, vault.ErrLocked
	}
	backupKeyMu.Lock()
	defer backupKeyMu.Unlock()
	switch c, err := v.GetReserved(BackupKeyLabel); {
	case err == nil:
		defer c.Password.Destroy()
		defer c.Enable.Destroy()
		defer c.SSHKey.Destroy()
		return slices.Clone(c.Password.Bytes()), nil
	case !errors.Is(err, vault.ErrNotFound):
		return nil, err
	}
	if !create {
		return nil, vault.ErrNotFound
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if _, err := v.Put(vault.Credential{Label: BackupKeyLabel, Username: "hmac", Password: secret.New(slices.Clone(key))}); err != nil {
		return nil, err
	}
	return key, nil
}

func inside(p, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), p)
	return err == nil && filepath.IsLocal(rel) || rel == "."
}

// JobOutputRoots son los output_dir absolutos de los trabajos guardados, distintos de Outputs():
// ahí caen las corridas cuando el ingeniero eligió otra carpeta. Un error de la base da lista vacía.
func JobOutputRoots(d Deps) []string {
	rows, err := d.DB().Query(`SELECT spec_json FROM jobs ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var raw string
		var sp struct{ OutputDir string }
		if rows.Scan(&raw) != nil || json.Unmarshal([]byte(raw), &sp) != nil || !filepath.IsAbs(sp.OutputDir) {
			continue
		}
		// Lo que cae dentro de outputs/ (p. ej. los lotes temporales de respaldos) ya lo cubre Outputs().
		if r := filepath.Clean(sp.OutputDir); !inside(r, d.Outputs()) && !slices.Contains(out, r) {
			out = append(out, r)
		}
	}
	return out
}
