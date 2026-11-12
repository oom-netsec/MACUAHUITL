package vault

import (
	"encoding/binary"

	"github.com/oom-netsec/MACUAHUITL/internal/secret"
)

// Texto en claro de una entrada: 6 campos "uint32 longitud ‖ bytes" en orden
// etiqueta, usuario, contraseña, enable, llave SSH, reservado.
const plainFields = 6

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
func decodePlain(b []byte) (Credential, error) {
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
