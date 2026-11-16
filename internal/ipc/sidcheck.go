package ipc

import "strings"

// sameSID decide si el SID del otro extremo del pipe (servidor o cliente) es el del usuario que corre este proceso.
// Falla cerrado: un SID vacío (no se pudo leer) nunca coincide, ni siquiera con otro vacío. Es la decisión de Accept y
// de Dial en Windows; vive aquí, sin API del sistema, para probarla en Linux.
func sameSID(peer, own string) bool {
	return peer != "" && own != "" && strings.EqualFold(peer, own)
}
