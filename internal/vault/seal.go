package vault

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// Sobre "MCK1": cifra un dato suelto (p. ej. una llave privada de la CA de
// laboratorio) con el mismo esquema que la DEK: Argon2id → KEK → AES-256-GCM.
//
//	"MCK1" ‖ memoria KiB (4) ‖ iteraciones (4) ‖ hilos (1) ‖ sal (16) ‖ nonce (12) ‖ cifrado+etiqueta
//
// Los datos asociados son los 29 bytes anteriores al nonce. Ver docs/security/CRYPTO.md.
const (
	sealMagic  = "MCK1"
	sealAADLen = 4 + 4 + 4 + 1 + 16
	sealMinLen = sealAADLen + 12 + 16
)

// Topes para sobres MCK1: llegan pegados por el usuario y no deben poder tumbar el
// núcleo pidiendo 4 GiB × 16 hilos antes de comprobar la contraseña. 1 GiB es 4× la
// base de la bóveda; las pruebas lo bajan.
var SealMaxMemoryKiB uint32 = 1 << 20

const sealMaxThreads = 8

// Seal no borra password; quien llama lo hace.
func Seal(password, plain []byte, p Params) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if p.MemoryKiB < MinMemoryKiB {
		return nil, ErrWeakParams
	}
	b := append([]byte(sealMagic), binary.BigEndian.AppendUint32(nil, p.MemoryKiB)...)
	b = append(binary.BigEndian.AppendUint32(b, p.Iterations), p.Threads)
	salt, nonce := make([]byte, 16), make([]byte, 12)
	for _, x := range [][]byte{salt, nonce} {
		if _, err := io.ReadFull(rand.Reader, x); err != nil {
			return nil, fmt.Errorf("vault: %w", err)
		}
	}
	b = append(b, salt...)
	kek := deriveKEK(password, salt, p)
	defer kek.Destroy()
	g, err := newAEAD(kek.Bytes())
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	return g.Seal(append(b, nonce...), nonce, plain, b), nil
}

// Unseal valida el encabezado antes de derivar. Quien llama borra el resultado.
func Unseal(password, blob []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrEmptyPassword
	}
	if len(blob) < sealMinLen || string(blob[:4]) != sealMagic {
		return nil, corrupt("sobre MCK1 inválido")
	}
	p := Params{MemoryKiB: binary.BigEndian.Uint32(blob[4:8]), Iterations: binary.BigEndian.Uint32(blob[8:12]), Threads: blob[12]}
	if p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > SealMaxMemoryKiB || p.Iterations < 1 || p.Iterations > 10 || p.Threads < 1 || p.Threads > sealMaxThreads {
		return nil, corrupt("sobre MCK1 con parámetros de Argon2id fuera de rango (máximo %d MiB, 10 iteraciones, %d hilos): %+v", SealMaxMemoryKiB/1024, sealMaxThreads, p)
	}
	kek := deriveKEK(password, blob[13:29], p)
	defer kek.Destroy()
	g, err := newAEAD(kek.Bytes())
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	plain, err := g.Open(nil, blob[sealAADLen:sealAADLen+12], blob[sealAADLen+12:], blob[:sealAADLen])
	if err != nil {
		return nil, ErrWrongPassword // también cubre un sobre alterado: GCM no distingue
	}
	return plain, nil
}
