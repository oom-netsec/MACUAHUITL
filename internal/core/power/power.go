// Package power evita que la laptop se suspenda durante trabajos armados y
// avisa al núcleo de suspensión, apagado y bloqueo de pantalla, vía logind (spec §10.4).
package power

import (
	"context"
	"os"

	"github.com/godbus/dbus/v5"
)

// Inhibitor toma los bloqueos de logind; release los suelta. missing lista los que no se pudieron tomar.
type Inhibitor interface {
	Take(why string) (release func(), missing []string)
}

// What son los bloqueos de spec §10.4: no suspender, no apagar, no reaccionar a la tapa ni a la inactividad.
var What = []string{"sleep", "idle", "handle-lid-switch", "shutdown"}

// Noop no bloquea nada y reporta todo como faltante (sin logind).
type Noop struct{}

func (Noop) Take(string) (func(), []string) { return func() {}, What }

type logind struct{ conn *dbus.Conn }

// NewLogind conecta al bus del sistema; sin logind devuelve Noop.
// shortcut: sin prueba automática (necesita systemd-logind real); se valida en el laboratorio (plan 1d Task 4).
func NewLogind() Inhibitor {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return Noop{}
	}
	return &logind{conn: c}
}

func (l *logind) Take(why string) (func(), []string) {
	obj := l.conn.Object("org.freedesktop.login1", "/org/freedesktop/login1")
	var fds []dbus.UnixFD
	var missing []string
	for _, w := range What {
		var fd dbus.UnixFD
		// Los bloqueos se sueltan solos si el núcleo muere: el descriptor se cierra con el proceso.
		if err := obj.Call("org.freedesktop.login1.Manager.Inhibit", 0, w, "MACUAHUITL", why, "block").Store(&fd); err != nil {
			missing = append(missing, w)
			continue
		}
		fds = append(fds, fd)
	}
	return func() {
		for _, fd := range fds {
			os.NewFile(uintptr(fd), "inhibit").Close()
		}
	}, missing
}

// Watch llama a los manejadores con las señales de logind hasta que ctx termine.
// shortcut: sin prueba automática; el núcleo expone OnSleep/OnLock y esas sí se prueban.
func Watch(ctx context.Context, onSleep, onLock func()) {
	c, err := dbus.ConnectSystemBus()
	if err != nil {
		return
	}
	defer c.Close()
	c.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.login1.Manager"), dbus.WithMatchMember("PrepareForSleep"))
	c.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.login1.Manager"), dbus.WithMatchMember("PrepareForShutdown"))
	c.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.login1.Session"), dbus.WithMatchMember("Lock"))
	ch := make(chan *dbus.Signal, 8)
	c.Signal(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case s := <-ch:
			switch s.Name {
			case "org.freedesktop.login1.Manager.PrepareForSleep", "org.freedesktop.login1.Manager.PrepareForShutdown":
				if len(s.Body) == 1 && s.Body[0] == true {
					onSleep()
				}
			case "org.freedesktop.login1.Session.Lock":
				onLock()
			}
		}
	}
}
