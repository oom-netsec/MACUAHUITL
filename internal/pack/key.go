package pack

import (
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"strings"
)

//go:embed oom.pub
var oomPub string

// OfficialKeys son las llaves con las que se acepta la firma oficial. Hoy, solo la de oom.pub.
// shortcut: una sola llave; al rotarla se agrega la anterior aquí durante una versión (ADR 0010).
func OfficialKeys() []ed25519.PublicKey {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(oomPub))
	if err != nil || len(b) != ed25519.PublicKeySize {
		panic("pack: oom.pub inválida")
	}
	return []ed25519.PublicKey{b}
}
