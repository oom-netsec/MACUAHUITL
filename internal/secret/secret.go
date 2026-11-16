// Package secret define el tipo Secret: memoria bloqueada, borrado explícito
// y redacción en todo formateador (String, Format, MarshalJSON, LogValue).
//
// No hace: persistir secretos; eso es de vault.
package secret

import (
	"fmt"
	"log/slog"

	"github.com/awnumar/memguard"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// memguard hace panic si VirtualLock falla, y en Windows el working set mínimo por omisión alcanza para unas 40
// páginas: se sube antes del primer buffer, en el núcleo, la UI y las pruebas. Si falla, Harden devuelve el mismo error
// y el núcleo no arranca. En Linux no hace nada.
func init() { _ = sys.EnsureLockQuota() }

// Redacted es lo único que un Secret imprime, serializa o registra.
const Redacted = "[REDACTED]"

// Secret guarda bytes sensibles en memoria bloqueada (mlock + páginas guardia).
type Secret struct {
	buf *memguard.LockedBuffer
}

// New copia b a memoria bloqueada y pone b en ceros.
func New(b []byte) *Secret {
	return &Secret{buf: memguard.NewBufferFromBytes(b)}
}

// Bytes devuelve una vista válida hasta Destroy; nil si está vacío o destruido.
func (s *Secret) Bytes() []byte {
	if s.Empty() {
		return nil
	}
	return s.buf.Bytes()
}

// Empty indica si no hay contenido (nil, vacío o destruido).
func (s *Secret) Empty() bool {
	return s == nil || s.buf == nil || !s.buf.IsAlive() || s.buf.Size() == 0
}

// Destroy borra y libera la memoria. Idempotente y seguro con nil.
func (s *Secret) Destroy() {
	if s != nil && s.buf != nil {
		s.buf.Destroy()
	}
}

func (s *Secret) String() string               { return Redacted }
func (s *Secret) GoString() string             { return Redacted }
func (s *Secret) Format(f fmt.State, _ rune)   { _, _ = f.Write([]byte(Redacted)) }
func (s *Secret) MarshalJSON() ([]byte, error) { return []byte(`"` + Redacted + `"`), nil }
func (s *Secret) MarshalText() ([]byte, error) { return []byte(Redacted), nil }
func (s *Secret) LogValue() slog.Value         { return slog.StringValue(Redacted) }
