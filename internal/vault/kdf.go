package vault

import (
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// Params son los parámetros de Argon2id guardados en el encabezado.
type Params struct {
	MemoryKiB  uint32
	Iterations uint32
	Threads    uint8
}

// DefaultParams es la base de spec §10.2: 256 MiB, 3 iteraciones, 4 hilos.
var DefaultParams = Params{MemoryKiB: 262144, Iterations: 3, Threads: 4}

// MinMemoryKiB es el piso de memoria aceptado; las pruebas lo bajan.
var MinMemoryKiB uint32 = 262144

func deriveKEK(master []byte, salt []byte, p Params) *secret.Secret {
	return secret.New(argon2.IDKey(master, salt, p.Iterations, p.MemoryKiB, p.Threads, 32))
}

// Calibrate sube las iteraciones desde DefaultParams hasta que una derivación
// tarde al menos target, con tope de 10.
func Calibrate(target time.Duration) Params {
	p := DefaultParams
	salt := make([]byte, 16)
	for ; p.Iterations < 10; p.Iterations++ {
		start := time.Now()
		k := deriveKEK([]byte("calibración"), salt, p)
		k.Destroy()
		if time.Since(start) >= target {
			break
		}
	}
	return p
}
