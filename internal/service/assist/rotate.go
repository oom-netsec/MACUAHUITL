package assist

import (
	"context"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/platform/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/secret"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

// rotation es lo que el servicio guarda de una rotación hasta que la ejecución empieza: a quién, con qué secreto y qué credencial de la
// bóveda recibe el secreto cuando la sesión nueva entre. El secreto no sale de aquí ni del plan.
type rotation struct{ user, secret, updateCred string }

// rotExec es el ejecutor de una rotación: el de siempre más la verificación con una sesión nueva y el cuidado de la bóveda.
type rotExec struct {
	*devExec
	rot rotation
}

// Verify abre una sesión nueva con el usuario rotado y el secreto nuevo (por el guard, con la llave del equipo ya conocida). No toca la
// bóveda: eso espera a que write memory salga bien (Saved). La sesión original no se toca: sigue abierta para revertir.
func (e *rotExec) Verify(ctx context.Context, dev string) (string, error) {
	t, ok := e.targets[dev]
	if !ok {
		return "", fmt.Errorf("equipo %q desconocido", dev)
	}
	v := e.d.Vault()
	oc, err := v.Get(t.cred) // solo para el enable con que el driver entra a privilegiado
	if err != nil {
		return "", err
	}
	oc.Password.Destroy()
	oc.SSHKey.Destroy()
	cred := vault.Credential{Username: e.rot.user, Password: secret.New([]byte(e.rot.secret)), Enable: oc.Enable}
	hk := e.d.Hosts().Callback(transport.HostKeyPolicy{}, func(en audit.Entry) { e.d.Audit(en.Action, en.Target, en.Detail) })
	sess, err := transport.OpenSSH(ctx, e.d.Guard(), e.id, t.host, t.port, cred, hk, transport.SSHOptions{})
	if err != nil {
		cred.Enable.Destroy()
		return "", err
	}
	defer sess.Close()
	r, w, err := sess.Shell()
	if err != nil {
		cred.Enable.Destroy()
		return "", err
	}
	drv := iosxe.New()
	defer drv.Close()
	if err := drv.Open(ctx, r, w, cred.Enable); err != nil {
		return "", err
	}
	e.d.Audit("assist.verify.session", dev, fmt.Sprintf("run=%s usuario=%s sesión nueva abierta", e.id, e.rot.user))
	return "la sesión nueva con " + e.rot.user + " entró", nil
}

// Saved se llama cuando write memory salió bien con [OK]: solo entonces la bóveda deja de coincidir con el arranque del equipo si no se
// actualiza. La credencial anterior se guarda como una entrada aparte ("<etiqueta> (anterior)") y la indicada queda con el secreto nuevo.
// La entrada anterior solo se borra a mano.
func (e *rotExec) Saved(_ context.Context, _ string) (string, error) {
	if e.rot.updateCred == "" {
		return "write memory salió bien; no se indicó credencial de la bóveda que actualizar", nil
	}
	v := e.d.Vault()
	cur, err := v.Get(e.rot.updateCred)
	if err != nil {
		return "", fmt.Errorf("no se pudo leer la credencial de la bóveda: %w", err)
	}
	prevLabel := cur.Label + " (anterior)"
	// Primero la copia: si falla, la credencial vigente no se toca.
	if _, err = v.Put(vault.Credential{Label: prevLabel, Username: cur.Username, Password: cur.Password, Enable: cur.Enable, SSHKey: cur.SSHKey}); err != nil {
		cur.Password.Destroy()
		cur.Enable.Destroy()
		cur.SSHKey.Destroy()
		return "", fmt.Errorf("la bóveda no pudo guardar la credencial anterior: %w", err)
	}
	nc := vault.Credential{ID: cur.ID, Label: cur.Label, Username: cur.Username, Password: secret.New([]byte(e.rot.secret)), Enable: cur.Enable, SSHKey: cur.SSHKey}
	_, err = v.Put(nc)
	nc.Password.Destroy()
	if err != nil {
		cur.Password.Destroy()
		cur.Enable.Destroy()
		cur.SSHKey.Destroy()
		return "", fmt.Errorf("la bóveda no pudo guardar la credencial nueva (la anterior quedó como %q): %w", prevLabel, err)
	}
	cur.Password.Destroy()
	cur.Enable.Destroy()
	cur.SSHKey.Destroy()
	e.d.Audit("assist.vault.update", e.rot.updateCred, fmt.Sprintf("run=%s usuario=%s anterior conservada como %q", e.id, e.rot.user, prevLabel))
	return fmt.Sprintf("la bóveda quedó con la credencial nueva; la anterior se conserva como %q (bórrala a mano cuando ya no haga falta)", prevLabel), nil
}

// Reverted: la bóveda solo cambia después de write memory (Saved), y tras eso la ejecución ya no revierte; no hay nada que devolver.
func (e *rotExec) Reverted(_ context.Context, _ string) error { return nil }
