package power

// Valores de Win32; viven aquí (sin build tag) para probar el despacho en todos los sistemas.
const (
	wmPowerBroadcast = 0x0218
	pbtAPMSuspend    = 0x0004
	wmWTSSessionChg  = 0x02B1
	wtsSessionLock   = 0x7
)

// dispatch traduce un mensaje de la ventana oculta a onSleep/onLock; ignora el resto.
func dispatch(msg uint32, wparam uintptr, onSleep, onLock func()) {
	switch {
	case msg == wmPowerBroadcast && wparam == pbtAPMSuspend:
		onSleep()
	case msg == wmWTSSessionChg && wparam == wtsSessionLock:
		onLock()
	}
}
