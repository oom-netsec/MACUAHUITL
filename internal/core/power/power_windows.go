//go:build windows

package power

import (
	"context"
	"log"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	user32   = windows.NewLazySystemDLL("user32.dll")
	wtsapi32 = windows.NewLazySystemDLL("wtsapi32.dll")

	pCreateRequest = kernel32.NewProc("PowerCreateRequest")
	pSetRequest    = kernel32.NewProc("PowerSetRequest")
	pClearRequest  = kernel32.NewProc("PowerClearRequest")

	pRegisterClass = user32.NewProc("RegisterClassExW")
	pCreateWindow  = user32.NewProc("CreateWindowExW")
	pDefWindowProc = user32.NewProc("DefWindowProcW")
	pDestroyWindow = user32.NewProc("DestroyWindow")
	pPostMessage   = user32.NewProc("PostMessageW")
	pPostQuit      = user32.NewProc("PostQuitMessage")
	pGetMessage    = user32.NewProc("GetMessageW")
	pTranslateMsg  = user32.NewProc("TranslateMessage")
	pDispatchMsg   = user32.NewProc("DispatchMessageW")

	pWTSRegister   = wtsapi32.NewProc("WTSRegisterSessionNotification")
	pWTSUnregister = wtsapi32.NewProc("WTSUnRegisterSessionNotification")
)

const (
	powerRequestSystemRequired = 1
	powerRequestContextSimple  = 0x1
	notifyForThisSession       = 0
	wmDestroy                  = 0x0002
	wmClose                    = 0x0010
	hwndMessage                = ^uintptr(2) // (HWND)-3
)

// Windows no deja bloquear la tapa ni el apagado: eso se reporta siempre como faltante.
var notTakeable = []string{"handle-lid-switch", "shutdown"}

type windowsInhibitor struct{}

// NewLogind (nombre histórico, los llamadores no cambian) devuelve el inhibidor de Windows.
func NewLogind() Inhibitor { return windowsInhibitor{} }

// Take pide PowerRequestSystemRequired atado a un handle, no al hilo (en Go un goroutine cambia de hilo).
func (windowsInhibitor) Take(why string) (func(), []string) {
	reason, err := windows.UTF16PtrFromString("MACUAHUITL: " + why)
	if err != nil {
		return func() {}, What
	}
	ctx := struct {
		version, flags uint32
		reason         *uint16
	}{0, powerRequestContextSimple, reason}
	h, _, _ := pCreateRequest.Call(uintptr(unsafe.Pointer(&ctx)))
	if windows.Handle(h) == windows.InvalidHandle || h == 0 {
		return func() {}, What
	}
	if r, _, _ := pSetRequest.Call(h, powerRequestSystemRequired); r == 0 {
		windows.CloseHandle(windows.Handle(h))
		return func() {}, What
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			pClearRequest.Call(h, powerRequestSystemRequired)
			windows.CloseHandle(windows.Handle(h))
		})
	}, notTakeable
}

type wndClass struct {
	size, style uint32
	wndProc     uintptr
	clsExtra    int32
	wndExtra    int32
	instance    windows.Handle
	icon        windows.Handle
	cursor      windows.Handle
	background  windows.Handle
	menu        *uint16
	className   *uint16
	iconSm      windows.Handle
}

type handlers struct{ onSleep, onLock func() }

var (
	wins      sync.Map // hwnd -> handlers
	classOne  sync.Once
	classErr  error
	className = windows.StringToUTF16Ptr("MACUAHUITLPowerWatch")
)

func wndProc(hwnd, msg, wparam, lparam uintptr) uintptr {
	switch uint32(msg) {
	case wmClose:
		pDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		pPostQuit.Call(0)
		return 0
	}
	if v, ok := wins.Load(hwnd); ok {
		h := v.(handlers)
		dispatch(uint32(msg), wparam, h.onSleep, h.onLock)
	}
	r, _, _ := pDefWindowProc.Call(hwnd, msg, wparam, lparam)
	return r
}

func registerClass() error {
	classOne.Do(func() {
		inst, err := moduleHandle()
		if err != nil {
			classErr = err
			return
		}
		wc := wndClass{instance: inst, className: className, wndProc: windows.NewCallback(wndProc)}
		wc.size = uint32(unsafe.Sizeof(wc))
		if r, _, e := pRegisterClass.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
			classErr = e
		}
	})
	return classErr
}

// Watch crea una ventana message-only en un hilo fijo y llama a los manejadores hasta que ctx termine.
// Si no se puede crear la ventana avisa en el log y vuelve (como Noop, pero sin callarse).
func Watch(ctx context.Context, onSleep, onLock func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := registerClass(); err != nil {
		log.Printf("power: no se pudo registrar la ventana de suspensión: %v", err)
		return
	}
	inst, _ := moduleHandle()
	hwnd, _, e := pCreateWindow.Call(0, uintptr(unsafe.Pointer(className)), 0, 0, 0, 0, 0, 0, hwndMessage, 0, uintptr(inst), 0)
	if hwnd == 0 {
		log.Printf("power: no se pudo crear la ventana de suspensión: %v", e)
		return
	}
	wins.Store(hwnd, handlers{onSleep, onLock})
	defer wins.Delete(hwnd)
	// Sin WTS seguimos oyendo suspensión; solo falta el bloqueo, y se dice.
	if r, _, e := pWTSRegister.Call(hwnd, notifyForThisSession); r == 0 {
		log.Printf("power: sin aviso de bloqueo de pantalla (WTSRegisterSessionNotification): %v", e)
	} else {
		defer pWTSUnregister.Call(hwnd)
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			pPostMessage.Call(hwnd, wmClose, 0, 0) // PostMessage es seguro entre hilos
		case <-done:
		}
	}()
	var msg [48]byte // MSG
	for {
		r, _, _ := pGetMessage.Call(uintptr(unsafe.Pointer(&msg[0])), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
		pTranslateMsg.Call(uintptr(unsafe.Pointer(&msg[0])))
		pDispatchMsg.Call(uintptr(unsafe.Pointer(&msg[0])))
	}
}

func moduleHandle() (windows.Handle, error) {
	var h windows.Handle
	err := windows.GetModuleHandleEx(windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, nil, &h)
	return h, err
}
