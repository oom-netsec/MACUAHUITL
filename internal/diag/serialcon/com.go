package serialcon

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// Nombres COMn de Windows. Es lógica pura (sin API de Windows) para probarla en todos los sistemas.

// comNum devuelve n de "COMn" (con o sin el prefijo \\.\, sin distinguir mayúsculas); n va de 1 a 255.
func comNum(name string) (int, bool) {
	s := strings.ToUpper(strings.TrimSpace(name))
	s = strings.TrimPrefix(s, `\\.\`)
	d, ok := strings.CutPrefix(s, "COM")
	if !ok || d == "" || len(d) > 3 || strings.Trim(d, "0123456789") != "" {
		return 0, false
	}
	n, _ := strconv.Atoi(d)
	return n, n >= 1 && n <= 255
}

// comName devuelve el nombre corto COMn (COM3), el que usan el registro y los archivos de salida.
func comName(name string) (string, bool) {
	n, ok := comNum(name)
	return "COM" + strconv.Itoa(n), ok
}

// comPath normaliza COM3 a \\.\COM3 (COM10 en adelante exige el prefijo). Nunca acepta otra ruta.
func comPath(name string) (string, bool) {
	n, ok := comNum(name)
	if !ok {
		return "", false
	}
	return `\\.\COM` + strconv.Itoa(n), true
}

// listCOM filtra los valores de SERIALCOMM que son COMn, sin repetidos, ordenados por número.
func listCOM(vals []string) []string {
	var out []string
	for _, v := range vals {
		if n, ok := comNum(v); ok {
			out = append(out, "COM"+strconv.Itoa(n))
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		na, _ := comNum(a)
		nb, _ := comNum(b)
		return na - nb
	})
	return slices.Compact(out)
}

// dcbFlags arma el campo de bits de la DCB de Windows para la configuración (fBinary, fParity, DTR y RTS
// activos como en una consola Cisco, y el control de flujo pedido). Es pura para probarla en cualquier sistema.
func dcbFlags(c Config) uint32 {
	f := uint32(1<<0 | 1<<4) // fBinary, fDtrControl = DTR_CONTROL_ENABLE
	if c.Parity != "none" {
		f |= 1 << 1 // fParity
	}
	switch c.Flow {
	case "rtscts":
		f |= 1<<2 | 2<<12 // fOutxCtsFlow, fRtsControl = RTS_CONTROL_HANDSHAKE
	case "xonxoff":
		f |= 1<<12 | 1<<8 | 1<<9 // RTS_CONTROL_ENABLE, fOutX, fInX
	default:
		f |= 1 << 12 // RTS_CONTROL_ENABLE
	}
	return f
}

// dcbStopBits da el StopBits de la DCB: ONESTOPBIT 0, ONE5STOPBITS 1, TWOSTOPBITS 2. Windows exige 1.5
// bits de parada con 5 de datos (lo que Linux hace con CSTOPB), y no admite 2.
func dcbStopBits(c Config) uint8 {
	switch {
	case c.StopBits != 2:
		return 0
	case c.DataBits == 5:
		return 1
	}
	return 2
}

// emptyReadsMax lecturas vacías e instantáneas seguidas = puerto perdido.
const emptyReadsMax = 5

// emptyReads detecta un adaptador USB desconectado: algunos drivers devuelven 0 bytes con éxito al
// instante en vez de esperar el timeout, y el bucle de Read giraría al 100 % de CPU.
type emptyReads struct{ n int }

// lost registra una lectura (bytes leídos y lo que tardó) y dice si ya hay que darlo por perdido.
func (e *emptyReads) lost(got int, took, timeout time.Duration) bool {
	if got > 0 || took >= timeout/2 {
		e.n = 0
		return false
	}
	e.n++
	return e.n >= emptyReadsMax
}
