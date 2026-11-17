package ipc

import (
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
		return i18n.New("ipc.err.server_not_user", nil)
	}
	return nil
}

// tokenFacts son los datos del token de un proceso que importan para confiar en el servidor de un pipe. Err != nil
// significa que no se pudieron leer (falla cerrado).
type tokenFacts struct {
	IL           uint32 // RID del nivel de integridad (0x1000 bajo, 0x2000 medio, 0x3000 alto, 0x4000 sistema)
	AppContainer bool
	Restricted   bool
	Err          error
}

// integridad media (RID 0x2000): la de un objeto sin etiqueta obligatoria.
const ilMedium = 0x2000

// serverTrusted decide si el servidor del pipe es tan confiable como el cliente: mismo usuario no basta, un proceso del
// mismo usuario con integridad baja, en AppContainer o con token restringido no debe recibir la contraseña maestra.
// label es el RID de la etiqueta de integridad del OBJETO pipe (0 = sin etiqueta, cuenta como medio): al ser del objeto
// no se puede reutilizar como el PID del creador (un proceso Low crea el pipe y muere, otro toma su PID). Exige
// label >= min(IL del cliente, medio): un cliente alto no rechaza al servidor normal, que crea el pipe sin etiqueta.
// server (token por PID) solo aporta AppContainer y token restringido. Decisión pura; Windows la alimenta con datos reales.
func serverTrusted(label uint32, server, client tokenFacts) error {
	if label == 0 {
		label = ilMedium
	}
	if server.Err != nil || client.Err != nil || client.IL == 0 ||
		server.AppContainer || server.Restricted || label < min(client.IL, ilMedium) {
		return i18n.New("ipc.err.server_low_integrity", nil)
	}
	return nil
}
