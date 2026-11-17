package vault

import (
	"encoding/binary"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// Texto en claro de una entrada: 6 campos "uint32 longitud ‖ bytes" en orden
// etiqueta, usuario, contraseña, enable, llave SSH, reservado.
const plainFields = 6

// MaxFieldBytes acota cada campo de una credencial que viene de fuera: un respaldo abierto con OpenBackup y la frontera del usuario
// (Put, PutBatch, PutUnlessKey y la importación). Cada secreto vive en memoria bloqueada (RLIMIT_MEMLOCK suele ser de pocos MiB) y
// memguard entra en pánico si no puede bloquearla. No aplica a la bóveda propia ni a las entradas reservadas (la reversa pendiente del
// asistente guarda el running-config entero): esas solo tienen el tope de cordura maxOwnFieldBytes.
const MaxFieldBytes = 64 << 10

// maxOwnFieldBytes es el tope de cordura de la bóveda propia (como ipc.MaxMsg): evita reservar memoria por un largo absurdo.
const maxOwnFieldBytes = 4 << 20

func encodePlain(c Credential) []byte {
	fields := [plainFields][]byte{[]byte(c.Label), []byte(c.Username), c.Password.Bytes(), c.Enable.Bytes(), c.SSHKey.Bytes(), nil}
	n := 0
	for _, f := range fields {
		n += 4 + len(f)
	}
	// Una sola asignación: si append creciera, dejaría copias con secretos sin borrar.
	b := make([]byte, 0, n)
	for _, f := range fields {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return b
}

// decodePlain copia los secretos a memoria bloqueada y pone b en ceros.
// max es el tope por campo; un campo mayor da ErrFieldTooLong y uno que no cabe en el texto, ErrCorrupt.
func decodePlain(b []byte, max uint32) (Credential, error) {
	defer wipe(b)
	var f [plainFields][]byte
	rest := b
	for i := range f {
		if len(rest) < 4 {
			return Credential{}, corrupt("texto en claro truncado")
		}
		l := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(l) > uint64(len(rest)) {
			return Credential{}, corrupt("campo %d excede el texto en claro", i)
		}
		if l > max {
			return Credential{}, ErrFieldTooLong
		}
		f[i], rest = rest[:l], rest[l:]
	}
	return Credential{
		Label:    string(f[0]),
		Username: string(f[1]),
		Password: secret.New(append([]byte(nil), f[2]...)),
		Enable:   secret.New(append([]byte(nil), f[3]...)),
		SSHKey:   secret.New(append([]byte(nil), f[4]...)),
	}, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
