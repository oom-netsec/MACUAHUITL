package vault

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// MaxWindow es la duración máxima de una ventana armada (spec §10.4).
const MaxWindow = 96 * time.Hour

var ErrWindowTooLong = errors.New("vault: la ventana debe terminar en el futuro y durar como máximo 96 h")

// Window autoriza a un trabajo armado a descifrar ciertas credenciales hasta Until (excluido).
type Window struct {
	JobID         string
	Until         time.Time
	CredentialIDs []string
}

// SetClock reemplaza el reloj; lo usan las pruebas y el núcleo.
func (v *Vault) SetClock(now func() time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.now = now
}

// Arm abre una ventana para jobID. Requiere la bóveda abierta de forma interactiva.
// Rearmar el mismo jobID reemplaza la ventana anterior.
func (v *Vault) Arm(jobID string, until time.Time, credentialIDs []string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if err := v.requireFull(); err != nil {
		return err
	}
	now := v.now()
	if !until.After(now) || until.Sub(now) > MaxWindow {
		return ErrWindowTooLong
	}
	if len(credentialIDs) == 0 {
		return fmt.Errorf("%w: una ventana sin credenciales retendría la DEK sin autorizar nada", ErrNotFound)
	}
	for _, id := range credentialIDs {
		if _, err := v.find(id); err != nil {
			return err
		}
	}
	v.windows[jobID] = Window{JobID: jobID, Until: until, CredentialIDs: append([]string(nil), credentialIDs...)}
	return nil
}

// Disarm cierra la ventana de jobID.
func (v *Vault) Disarm(jobID string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.windows, jobID)
	v.sweep()
}

// Lock es el cierre interactivo (inactividad, pantalla bloqueada, botón).
// Si quedan ventanas vigentes la DEK se conserva solo para ellas.
func (v *Vault) Lock() {
	v.mu.Lock()
	v.unlocked = false
	v.sweep()
	hooks := slices.Clone(v.onLock)
	v.mu.Unlock()
	for _, f := range hooks {
		f()
	}
}

// LockAll es el cierre total (cierre de sesión, suspensión, apagado).
func (v *Vault) LockAll() {
	v.mu.Lock()
	v.unlocked = false
	v.windows = map[string]Window{}
	v.sweep()
	hooks := slices.Clone(v.onLock)
	v.mu.Unlock()
	for _, f := range hooks {
		f()
	}
}

// OnLock registra f para cuando la bóveda se cierra (Lock o LockAll): quien guarda secretos descifrados aparte los borra ahí. f no debe llamar a la bóveda.
func (v *Vault) OnLock(f func()) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.onLock = append(v.onLock, f)
}

// Windows devuelve las ventanas vigentes.
func (v *Vault) Windows() []Window {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep()
	out := make([]Window, 0, len(v.windows))
	for _, w := range v.windows {
		w.CredentialIDs = append([]string(nil), w.CredentialIDs...) // copia: el llamador no toca el estado vivo
		out = append(out, w)
	}
	return out
}

// Unlocked indica si la bóveda está abierta de forma interactiva (no solo por ventanas).
func (v *Vault) Unlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.sweep()
	return v.unlocked && !v.dek.Empty()
}

// sweep quita ventanas vencidas y destruye la DEK si ya nadie la necesita. Requiere v.mu.
func (v *Vault) sweep() {
	now := v.now()
	for id, w := range v.windows {
		if !now.Before(w.Until) {
			delete(v.windows, id)
		}
	}
	if !v.unlocked && len(v.windows) == 0 {
		v.dropDEK()
	}
}

// authorizeGet permite Get con la bóveda abierta, o para IDs cubiertos por una ventana vigente. Requiere v.mu.
func (v *Vault) authorizeGet(id string) error {
	v.sweep()
	if v.unlocked && !v.dek.Empty() {
		return nil
	}
	if !v.dek.Empty() {
		for _, w := range v.windows {
			for _, c := range w.CredentialIDs {
				if c == id {
					return nil
				}
			}
		}
	}
	return ErrLocked
}
