package service

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Claves reservadas de preferences para las preferencias del núcleo (fase 29e). SetPreference
// genérico no puede escribir el prefijo CorePrefix.
const (
	CorePrefix   = "core."
	keyOutputs   = CorePrefix + "outputs_dir"
	keyRotateMB  = CorePrefix + "rotate_mb"
	keyRotateMin = CorePrefix + "rotate_minutes"
	keyMaxFiles  = CorePrefix + "max_files"
	keyIngestFmt = CorePrefix + "format"
)

// IngestDefaults son los defaults de archivo de syslog, traps y flujos cuando la petición no manda
// el campo. 0 o vacío = el de fábrica.
type IngestDefaults struct {
	RotateMB, RotateMinutes, MaxFiles int32
	Format                            string
}

// CoreSettings es el valor vigente de las preferencias del núcleo. Los servicios lo leen en cada
// operación (nunca lo guardan en caché), así que un cambio aplica a lo que empiece después.
type CoreSettings struct {
	mu         sync.RWMutex
	factory    string
	outputs    string // vacío = factory
	ingest     IngestDefaults
	issue      i18n.Text // por qué la carpeta guardada no rige (vacío = rige); mientras tanto vale la de fábrica
	issueAudit string    // el mismo aviso para la bitácora (en inglés)

	// Home es la carpeta personal y Inside las carpetas del núcleo (datos, configuración, estado):
	// la carpeta de salidas no puede ser Home ni estar dentro de ninguna de Inside.
	Home   string
	Inside []string
}

// NewCoreSettings arranca con la carpeta de salidas de fábrica y nada configurado.
func NewCoreSettings(factory, home string, inside ...string) *CoreSettings {
	return &CoreSettings{factory: factory, Home: home, Inside: inside}
}

// Outputs es la carpeta base de salidas vigente.
func (s *CoreSettings) Outputs() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.outputs != "" && s.issue.Empty() {
		return s.outputs
	}
	return s.factory
}

// Issue es el motivo por el que la carpeta guardada no rige, o "".
func (s *CoreSettings) Issue() string { return s.IssueIn(i18n.Es) }

// IssueIn es Issue en el idioma pedido.
func (s *CoreSettings) IssueIn(loc string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.issue.In(loc)
}

// IssueAudit es el mismo aviso para la auditoría (siempre en inglés, con la carpeta y el código del motivo).
func (s *CoreSettings) IssueAudit() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.issueAudit
}

// Mark anota que la carpeta guardada no rige (issue vacío la rehabilita); audit es su versión para la bitácora.
func (s *CoreSettings) Mark(issue i18n.Text, audit string) {
	s.mu.Lock()
	s.issue, s.issueAudit = issue, audit
	s.mu.Unlock()
}

// Factory es la carpeta de salidas de fábrica.
func (s *CoreSettings) Factory() string { return s.factory }

// Configured es lo guardado: vacío = la de fábrica.
func (s *CoreSettings) Configured() (outputs string, ing IngestDefaults) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.outputs, s.ingest
}

// Ingest son los defaults de archivo vigentes.
func (s *CoreSettings) Ingest() IngestDefaults {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ingest
}

// Apply deja vigentes estos valores.
func (s *CoreSettings) Apply(outputs string, ing IngestDefaults) {
	s.mu.Lock()
	s.outputs, s.ingest, s.issue = outputs, ing, i18n.Text{}
	s.mu.Unlock()
}

// Load lee lo guardado en preferences (al abrir el núcleo). Un valor ilegible se ignora: vale el de fábrica.
// Con check revalida la carpeta guardada: si ya no vale, rige la de fábrica y Issue dice por qué.
func (s *CoreSettings) Load(db *sql.DB, check func(dir string) error) error {
	rows, err := db.Query(`SELECT key, value FROM preferences WHERE key LIKE 'core.%'`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var out string
	var ing IngestDefaults
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return err
		}
		n, _ := strconv.ParseInt(v, 10, 32)
		switch k {
		case keyOutputs:
			out = v
		case keyRotateMB:
			ing.RotateMB = int32(n)
		case keyRotateMin:
			ing.RotateMinutes = int32(n)
		case keyMaxFiles:
			ing.MaxFiles = int32(n)
		case keyIngestFmt:
			ing.Format = v
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.Apply(out, ing)
	if out != "" && check != nil {
		if err := check(out); err != nil {
			s.Mark(OutputsIssue(out, err), OutputsIssueAudit(out, err))
		}
	}
	return nil
}

// SaveCoreSettings guarda los valores en una transacción; un valor vacío o 0 borra su clave (vuelve a fábrica).
func SaveCoreSettings(db *sql.DB, now time.Time, outputs string, ing IngestDefaults) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	at := now.UTC().Format(time.RFC3339)
	for _, kv := range [][2]string{
		{keyOutputs, outputs}, {keyRotateMB, itoa(ing.RotateMB)}, {keyRotateMin, itoa(ing.RotateMinutes)},
		{keyMaxFiles, itoa(ing.MaxFiles)}, {keyIngestFmt, ing.Format},
	} {
		if kv[1] == "" {
			_, err = tx.Exec(`DELETE FROM preferences WHERE key = ?`, kv[0])
		} else {
			_, err = tx.Exec(`INSERT INTO preferences(key,value,updated_at) VALUES(?,?,?)
				ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, kv[0], kv[1], at)
		}
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func itoa(n int32) string {
	if n == 0 {
		return ""
	}
	return strconv.Itoa(int(n))
}

// OutputsIssue es el aviso de que la carpeta de salidas guardada ya no vale y rige la de fábrica.
func OutputsIssue(dir string, reason error) i18n.Text {
	return i18n.Tx("prefs.outputs.issue", "dir", dir).With("reason", i18n.FromErr(reason))
}

// OutputsIssueAudit es OutputsIssue para la auditoría: la carpeta y el código del motivo (el prefijo prefs.outputs.X).
func OutputsIssueAudit(dir string, reason error) string {
	code := "unknown"
	if c, ok := strings.CutPrefix(reason.Error(), "prefs.outputs."); ok {
		code, _, _ = strings.Cut(c, ":")
	}
	return fmt.Sprintf("outputs_dir_invalid dir=%q reason=%s", dir, code)
}
