package ipc

import (
	"errors"
	"strings"
)

// sameSID decide si el SID del otro extremo del pipe (servidor o cliente) es el del usuario que corre este proceso.
// Falla cerrado: un SID vacío (no se pudo leer) nunca coincide, ni siquiera con otro vacío. Es la decisión de Accept y
// de Dial en Windows; vive aquí, sin API del sistema, para probarla en Linux.
func sameSID(peer, own string) bool {
	return peer != "" && own != "" && strings.EqualFold(peer, own)
}

// checkServer decide si el servidor de un pipe es del usuario: el dueño del objeto pipe y el SID del proceso que lo creó
// (por su PID) deben ser los propios. Las dos comprobaciones juntas cierran el PID reutilizado (B1). Vacíos fallan.
func checkServer(owner, sid, own string) error {
	if !sameSID(owner, own) || !sameSID(sid, own) {
		return errors.New("el servidor del pipe no es de este usuario")
	}
	return nil
}
