package ipc

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const (
	lowPipeEnv = "MCTL_TEST_LOW_PIPE"
	lowModeEnv = "MCTL_TEST_LOW_MODE" // low (etiqueta Low), normal (pipeSDDL(own), lleva ME) o nolabel (sin S:)
)

// TestHelperLowPipe es el hijo de TestDialPipeRechazaServidorLow, no una prueba: solo actúa con la variable de entorno.
// Corre con integridad baja, crea el pipe de prueba (dueño y DACL del usuario; la etiqueta según lowModeEnv), acepta
// conexiones (sin Accept no hay instancia escuchando y el cliente recibe ERROR_PIPE_BUSY) y espera a que lo maten.
func TestHelperLowPipe(t *testing.T) {
	name := os.Getenv(lowPipeEnv)
	if name == "" {
		t.Skip("solo como hijo")
	}
	own, err := ownSID()
	if err != nil {
		os.Exit(2)
	}
	sddl := "O:" + own + "D:P(A;;GA;;;" + own + ")"
	switch os.Getenv(lowModeEnv) {
	case "normal":
		sddl = pipeSDDL(own)
	case "nolabel":
	default:
		sddl += "S:(ML;;NW;;;LW)"
	}
	l, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: sddl})
	if err != nil {
		os.Exit(3)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	time.Sleep(30 * time.Second)
}

// spawnLow relanza el binario de prueba con una copia del token propio rebajada a integridad baja (S-1-16-4096):
// sin privilegios, es una copia rebajada del propio token.
func spawnLow(t *testing.T, name, mode string) {
	t.Helper()
	var tok windows.Token
	if err := windows.DuplicateTokenEx(windows.GetCurrentProcessToken(), windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &tok); err != nil {
		t.Skipf("DuplicateTokenEx: %v", err)
	}
	defer tok.Close()
	low, err := windows.StringToSid("S-1-16-4096")
	if err != nil {
		t.Fatal(err)
	}
	tml := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: low, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(tok, windows.TokenIntegrityLevel, (*byte)(unsafe.Pointer(&tml)), uint32(unsafe.Sizeof(tml))+windows.GetLengthSid(low)); err != nil {
		t.Fatalf("SetTokenInformation: %v", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	app, _ := windows.UTF16PtrFromString(exe)
	cmd, _ := windows.UTF16PtrFromString(windows.ComposeCommandLine([]string{exe, "-test.run=^TestHelperLowPipe$"}))
	t.Setenv(lowPipeEnv, name) // el hijo hereda el entorno del padre
	t.Setenv(lowModeEnv, mode)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CreateProcessAsUser: %v", err)
		}
		t.Skipf("CreateProcessAsUser: %v", err)
	}
	t.Cleanup(func() {
		windows.TerminateProcess(pi.Process, 1)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	})
}

// Un servidor del mismo usuario con integridad baja, con dueño y DACL correctos, se rechaza con pipe_low_integrity: la
// comprobación de dialPipe (M1) de punta a punta. Y Listen sobre ese nombre propaga el código (no «otro usuario»).
func TestDialPipeRechazaServidorLow(t *testing.T) {
	for _, mode := range []string{"low", "normal", "nolabel"} {
		t.Run(mode, func(t *testing.T) {
			name := sockPath(t)
			spawnLow(t, name, mode)
			deadline := time.Now().Add(10 * time.Second)
			var err error
			for {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				nc, _, derr := dialPipe(ctx, name)
				cancel()
				err = derr
				if derr == nil {
					nc.Close()
					t.Fatal("dialPipe aceptó un pipe creado por un proceso de integridad baja")
				}
				if !errors.Is(derr, windows.ERROR_FILE_NOT_FOUND) || time.Now().After(deadline) {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}
			if mode == "normal" && errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
				// El kernel impidió fijar la etiqueta ME desde un proceso Low (ListenPipe falló): tampoco hay servidor.
				t.Logf("el hijo Low no pudo crear el pipe con la etiqueta Medium: %v", err)
				return
			}
			var ie *i18n.Error
			if !errors.As(err, &ie) || ie.Code != "ipc.err.pipe_low_integrity" {
				t.Fatalf("dialPipe = %v, quería ipc.err.pipe_low_integrity", err)
			}
			if _, err := Listen(name); !errors.Is(err, ErrAlreadyRunning) || !errors.As(err, &ie) || ie.Code != "ipc.err.pipe_low_integrity" {
				t.Fatalf("Listen sobre el pipe Low = %v, quería ErrAlreadyRunning con pipe_low_integrity", err)
			}
		})
	}
}
