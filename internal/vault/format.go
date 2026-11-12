package vault

import (
	"encoding/binary"
	"fmt"
)

// Formato de vault.mcv versión 1; ver docs/security/CRYPTO.md.
const (
	magic         = "MCV1"
	formatVersion = uint16(1)
	headerAADLen  = 47  // bytes 0–46: mágico..sal, datos asociados de la DEK cifrada
	headerLen     = 111 // hasta el contador de entradas inclusive
	maxMemoryKiB  = 4194304
	minEntryLen   = 16 + 12 + 4 + 16 // ID + nonce + longitud + etiqueta GCM
)

type header struct {
	VaultID   [16]byte
	Params    Params
	Salt      [16]byte
	DEKNonce  [12]byte
	DEKCipher [48]byte
}

type rawEntry struct {
	ID    [16]byte
	Nonce [12]byte
	CT    []byte // texto cifrado + etiqueta GCM
}

func (h header) aad() []byte {
	b := make([]byte, 0, headerAADLen)
	b = append(b, magic...)
	b = binary.BigEndian.AppendUint16(b, formatVersion)
	b = append(b, h.VaultID[:]...)
	b = binary.BigEndian.AppendUint32(b, h.Params.MemoryKiB)
	b = binary.BigEndian.AppendUint32(b, h.Params.Iterations)
	b = append(b, h.Params.Threads)
	return append(b, h.Salt[:]...)
}

func marshalFile(h header, entries []rawEntry) []byte {
	b := h.aad()
	b = append(b, h.DEKNonce[:]...)
	b = append(b, h.DEKCipher[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(entries)))
	for _, e := range entries {
		b = append(b, e.ID[:]...)
		b = append(b, e.Nonce[:]...)
		b = binary.BigEndian.AppendUint32(b, uint32(len(e.CT)))
		b = append(b, e.CT...)
	}
	return b
}

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCorrupt}, a...)...)
}

// parseFile valida todo antes de que alguien derive llaves con estos parámetros.
func parseFile(b []byte) (header, []rawEntry, error) {
	var h header
	if len(b) < headerLen {
		return h, nil, corrupt("archivo de %d bytes", len(b))
	}
	if string(b[0:4]) != magic {
		return h, nil, corrupt("identificador mágico inválido")
	}
	if v := binary.BigEndian.Uint16(b[4:6]); v != formatVersion {
		return h, nil, corrupt("versión de formato %d no soportada", v)
	}
	copy(h.VaultID[:], b[6:22])
	h.Params = Params{
		MemoryKiB:  binary.BigEndian.Uint32(b[22:26]),
		Iterations: binary.BigEndian.Uint32(b[26:30]),
		Threads:    b[30],
	}
	p := h.Params
	if p.MemoryKiB < MinMemoryKiB || p.MemoryKiB > maxMemoryKiB || p.Iterations < 1 || p.Iterations > 10 || p.Threads < 1 || p.Threads > 16 {
		return h, nil, corrupt("parámetros de Argon2id fuera de rango: %+v", p)
	}
	copy(h.Salt[:], b[31:47])
	copy(h.DEKNonce[:], b[47:59])
	copy(h.DEKCipher[:], b[59:107])
	n := binary.BigEndian.Uint32(b[107:111])
	rest := b[headerLen:]
	if uint64(n)*minEntryLen > uint64(len(rest)) {
		return h, nil, corrupt("%d entradas no caben en %d bytes", n, len(rest))
	}
	entries := make([]rawEntry, 0, n)
	for i := uint32(0); i < n; i++ {
		if len(rest) < 32 {
			return h, nil, corrupt("entrada %d truncada", i)
		}
		var e rawEntry
		copy(e.ID[:], rest[0:16])
		copy(e.Nonce[:], rest[16:28])
		l := binary.BigEndian.Uint32(rest[28:32])
		rest = rest[32:]
		if l < 16 || uint64(l) > uint64(len(rest)) {
			return h, nil, corrupt("entrada %d con longitud %d", i, l)
		}
		e.CT = append([]byte(nil), rest[:l]...)
		rest = rest[l:]
		entries = append(entries, e)
	}
	if len(rest) != 0 {
		return h, nil, corrupt("%d bytes sobrantes", len(rest))
	}
	return h, entries, nil
}
