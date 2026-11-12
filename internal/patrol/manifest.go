package patrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/version"
)

type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type PlaybookRef struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Name            string          `json:"name"`
	AppVersion      string          `json:"app_version"`
	StartedAt       time.Time       `json:"started_at"`
	EndedAt         time.Time       `json:"ended_at"`
	Playbooks       []PlaybookRef   `json:"playbooks"`
	CustomCommands  string          `json:"custom_commands_sha256,omitempty"`
	Devices         []DeviceResult  `json:"devices"`
	Rounds          int             `json:"rounds"`
	SkippedRounds   []int           `json:"skipped_rounds"`
	Masked          bool            `json:"masked"`
	MaskCounts      map[string]int  `json:"mask_counts"`
	Files           []FileRef       `json:"files"`
	ChangedHostKeys []HostKeyChange `json:"changed_host_keys"`
	// AuditHead ancla el log de auditoría en lo que se entrega (spec §11).
	AuditHead string `json:"audit_head"`
}

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fileSHA(p string) (string, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	return sha(b), nil
}

// RoundDone empaqueta los archivos de la ronda si el trabajo usa ZipPerRound.
func RoundDone(w *Writer, s Spec, round int) (string, error) {
	if s.Zip != ZipPerRound {
		return "", nil
	}
	// Con un archivo consolidado no se borran sueltos: la ronda siguiente sigue escribiendo en él.
	del := s.DeleteLooseFiles && s.Split == SplitPerRound
	return zipFiles(w.dir, fmt.Sprintf("%s_r%03d", filepath.Base(w.dir), round), w.roundFiles(round), del)
}

// Finish escribe manifest.json (con el hash de cabeza de la auditoría) y aplica la política de zip.
func Finish(ctx context.Context, d Deps, w *Writer, s Spec, rounds int, results []DeviceResult) (Manifest, error) {
	m := Manifest{
		Name: s.Name, AppVersion: version.Version, StartedAt: w.started, EndedAt: d.Now(),
		Devices: results, Rounds: rounds, Masked: !s.DisableMasking, MaskCounts: w.masks(),
		Files: []FileRef{}, ChangedHostKeys: []HostKeyChange{},
	}
	for _, id := range s.PlaybookIDs {
		if p := find(d.Playbooks, id); p != nil {
			var b strings.Builder
			for _, c := range p.Commands {
				b.WriteString(c.Text + "\n")
			}
			m.Playbooks = append(m.Playbooks, PlaybookRef{ID: id, SHA256: sha([]byte(b.String()))})
		}
	}
	if s.CustomCommands != "" {
		m.CustomCommands = sha([]byte(s.CustomCommands))
	}
	w.mu.Lock()
	m.ChangedHostKeys = append(m.ChangedHostKeys, w.hostKeys...)
	m.SkippedRounds = append([]int{}, w.skipped...)
	w.mu.Unlock()
	for _, r := range results {
		if r.ChangedHostKey != nil {
			m.ChangedHostKeys = append(m.ChangedHostKeys, *r.ChangedHostKey)
		}
	}
	var present []string
	for _, rel := range w.Files() {
		if _, err := os.Stat(filepath.Join(w.dir, rel)); err != nil {
			continue // ya empaquetado y borrado en su zip de ronda
		}
		present = append(present, rel)
		h, err := fileSHA(filepath.Join(w.dir, rel))
		if err != nil {
			return m, fmt.Errorf("patrol: %w", err)
		}
		m.Files = append(m.Files, FileRef{Path: rel, SHA256: h})
	}
	if _, err := d.Audit.Append(ctx, audit.Entry{Actor: "patrol", Action: "job.finish", Target: s.Name,
		Detail: fmt.Sprintf("rounds=%d files=%d masked=%v", rounds, len(m.Files), m.Masked)}); err != nil {
		return m, err
	}
	head, err := d.Audit.Head(ctx)
	if err != nil {
		return m, err
	}
	m.AuditHead = head
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(w.dir, "manifest.json"), b, 0o600); err != nil {
		return m, fmt.Errorf("patrol: %w", err)
	}
	switch s.Zip {
	case ZipAtEnd:
		if _, err := zipFiles(w.dir, filepath.Base(w.dir), append(present, "manifest.json"), s.DeleteLooseFiles); err != nil {
			return m, err
		}
	case ZipPerRound:
		// Los zips de ronda ya existen; este cierra con el manifest y lo que quede suelto.
		if _, err := zipFiles(w.dir, filepath.Base(w.dir)+"_final", append(present, "manifest.json"), false); err != nil {
			return m, err
		}
	}
	return m, nil
}
