//go:build windows

package serialcon

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SIN VALIDAR EN HARDWARE: la apertura real (CreateFile, DCB, timeouts, BREAK) no se probó con un
// adaptador USB-serie; en CI no hay ninguno. Lo puro (nombres, flags de la DCB, listado) sí tiene pruebas.

const (
	readPoll     = 100 * time.Millisecond // lectura sin datos vuelve en este tiempo (ver Read)
	writeTimeout = 5000                   // ms; un cable sin flujo no cuelga la escritura para siempre
	maxDWORD     = 0xFFFFFFFF
)

type Port struct {
	h      windows.Handle
	mu     sync.RWMutex // Close toma el candado de escritura: espera las E/S en curso
	closed bool
	Cfg    Config
}

func validPath(p string) error {
	if _, ok := comPath(p); !ok {
		return i18n.New("serial.err.path_win", i18n.A("path", p))
	}
	return nil
}

func open(c Config) (*Port, error) {
	path, _ := comPath(c.Path) // validate ya lo aceptó
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, i18n.New("serial.err.path_win", i18n.A("path", c.Path))
	}
	// Modo compartido 0: acceso exclusivo, como TIOCEXCL en Linux.
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, openErr(c.Path, err)
	}
	var dcb windows.DCB
	if err := windows.GetCommState(h, &dcb); err != nil {
		windows.CloseHandle(h)
		return nil, i18n.Wrap("serial.err.not_serial", err, i18n.A("path", c.Path))
	}
	dcb.DCBlength = uint32(unsafe.Sizeof(dcb))
	dcb.BaudRate = uint32(c.Baud)
	dcb.ByteSize = uint8(c.DataBits)
	dcb.Flags = dcbFlags(c)
	dcb.Parity = map[string]uint8{"none": windows.NOPARITY, "odd": windows.ODDPARITY, "even": windows.EVENPARITY}[c.Parity]
	dcb.StopBits = windows.ONESTOPBIT
	if c.StopBits == 2 {
		dcb.StopBits = windows.TWOSTOPBITS
	}
	dcb.XonChar, dcb.XoffChar, dcb.XonLim, dcb.XoffLim = 0x11, 0x13, 2048, 512
	// Con ReadInterval=ReadMultiplier=MAXDWORD, un Read sin datos espera ReadConstant ms y vuelve con 0
	// bytes. Read lo reintenta mirando "closed", así Close desbloquea una lectura en curso con un
	// retraso máximo de readPoll (en Linux lo hace el poller de Go).
	to := windows.CommTimeouts{ReadIntervalTimeout: maxDWORD, ReadTotalTimeoutMultiplier: maxDWORD,
		ReadTotalTimeoutConstant: uint32(readPoll / time.Millisecond), WriteTotalTimeoutConstant: writeTimeout}
	if err := windows.SetCommState(h, &dcb); err != nil {
		windows.CloseHandle(h)
		return nil, i18n.Wrap("serial.err.configure", err, i18n.A("path", c.Path))
	}
	if err := windows.SetCommTimeouts(h, &to); err != nil {
		windows.CloseHandle(h)
		return nil, i18n.Wrap("serial.err.configure", err, i18n.A("path", c.Path))
	}
	windows.PurgeComm(h, windows.PURGE_RXCLEAR|windows.PURGE_TXCLEAR)
	return &Port{h: h, Cfg: c}, nil
}

// openErr: en Windows un puerto abierto por otro programa (PuTTY, Tera Term) da ACCESS_DENIED o
// SHARING_VIOLATION; se reporta como ErrPermission/permission_hint (su texto en Windows es el de «en uso»).
func openErr(path string, err error) error {
	switch {
	// Un COM abierto por otra app da ACCESS_DENIED o SHARING_VIOLATION: es «en uso» (como EBUSY en Linux), no un permiso
	// que dar (en Windows no hay grupo dialout). El texto de Windows sale de serial.err.busy.windows.
	case errors.Is(err, windows.ERROR_ACCESS_DENIED), errors.Is(err, windows.ERROR_SHARING_VIOLATION):
		return i18n.New("serial.err.busy", i18n.A("path", path))
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return i18n.New("serial.err.missing", i18n.A("path", path))
	}
	return fmt.Errorf("serialcon: %w", err)
}

func (p *Port) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	for {
		p.mu.RLock()
		if p.closed {
			p.mu.RUnlock()
			return 0, os.ErrClosed
		}
		var n uint32
		err := windows.ReadFile(p.h, b, &n, nil)
		p.mu.RUnlock()
		if err != nil || n > 0 {
			return int(n), err
		}
	}
}

func (p *Port) Write(b []byte) (int, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return 0, os.ErrClosed
	}
	var n uint32
	err := windows.WriteFile(p.h, b, &n, nil)
	return int(n), err
}

func (p *Port) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return os.ErrClosed
	}
	p.closed = true
	return windows.CloseHandle(p.h)
}

// Break envía BREAK 250 ms (SetCommBreak/ClearCommBreak): entra a ROMMON durante el arranque.
func (p *Port) Break() error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return os.ErrClosed
	}
	if err := windows.SetCommBreak(p.h); err != nil {
		return fmt.Errorf("serialcon: BREAK: %w", err)
	}
	time.Sleep(250 * time.Millisecond)
	if err := windows.ClearCommBreak(p.h); err != nil {
		return fmt.Errorf("serialcon: BREAK: %w", err)
	}
	return nil
}

// readSerialComm lee los valores de HKLM\HARDWARE\DEVICEMAP\SERIALCOMM (legible sin admin); se
// reemplaza en pruebas.
var readSerialComm = func() []string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DEVICEMAP\SERIALCOMM`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	var vals []string
	for _, n := range names {
		if v, _, err := k.GetStringValue(n); err == nil {
			vals = append(vals, v)
		}
	}
	return vals
}

// List devuelve los COMn presentes (consolas USB de Catalyst/ISR y adaptadores FTDI/Prolific/CP210x con su
// driver instalado), ordenados por número.
func List() []string { return listCOM(readSerialComm()) }
