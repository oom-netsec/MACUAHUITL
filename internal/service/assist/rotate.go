package assist

import (
	"context"
	"fmt"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
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
func (e *rotExec) Verify(ctx context.Context, dev string) (i18n.Text, error) {
	t, ok := e.targets[dev]
	if !ok {
		return i18n.Text{}, i18n.New("assist.svc.unknown_device", i18n.A("device", dev))
	}
	v := e.d.Vault()
	oc, err := v.Get(t.cred) // solo para el enable con que el driver entra a privilegiado
	if err != nil {
		return i18n.Text{}, err
	}
	oc.Password.Destroy()
	oc.SSHKey.Destroy()
	cred := vault.Credential{Username: e.rot.user, Password: secret.New([]byte(e.rot.secret)), Enable: oc.Enable}
	hk := e.d.Hosts().Callback(transport.HostKeyPolicy{}, func(en audit.Entry) { e.d.Audit(en.Action, en.Target, en.Detail) })
	sess, err := transport.OpenSSH(ctx, e.d.Guard(), e.id, t.host, t.port, cred, hk, transport.SSHOptions{})
	if err != nil {
		cred.Enable.Destroy()
		return i18n.Text{}, err
	}
	defer sess.Close()
	r, w, err := sess.Shell()
	if err != nil {
		cred.Enable.Destroy()
		return i18n.Text{}, err
	}
	drv := iosxe.New()
	defer drv.Close()
	if err := drv.Open(ctx, r, w, cred.Enable); err != nil {
		return i18n.Text{}, err
	}
	e.d.Audit("assist.verify.session", dev, fmt.Sprintf("run=%s user=%s new session opened", e.id, e.rot.user))
	return i18n.Tx("assist.run.new_session_ok", "user", e.rot.user), nil
}

// Saved se llama cuando write memory salió bien con [OK]: solo entonces la bóveda deja de coincidir con el arranque del equipo si no se
// actualiza. La credencial anterior se guarda como una entrada aparte ("<etiqueta> (anterior)") y la indicada queda con el secreto nuevo.
// La entrada anterior solo se borra a mano.
func (e *rotExec) Saved(_ context.Context, _ string) (i18n.Text, error) {
	if e.rot.updateCred == "" {
		return i18n.Tx("assist.run.saved_no_credential"), nil
	}
	v := e.d.Vault()
	cur, err := v.Get(e.rot.updateCred)
	if err != nil {
		return i18n.Text{}, i18n.Wrap("assist.svc.vault_read_failed", err, nil)
	}
	prevLabel := cur.Label + " (anterior)"
	// Primero la copia: si falla, la credencial vigente no se toca.
	if _, err = v.Put(vault.Credential{Label: prevLabel, Username: cur.Username, Password: cur.Password, Enable: cur.Enable, SSHKey: cur.SSHKey}); err != nil {
		cur.Password.Destroy()
		cur.Enable.Destroy()
		cur.SSHKey.Destroy()
		return i18n.Text{}, i18n.Wrap("assist.svc.vault_save_prev_failed", err, nil)
	}
	nc := vault.Credential{ID: cur.ID, Label: cur.Label, Username: cur.Username, Password: secret.New([]byte(e.rot.secret)), Enable: cur.Enable, SSHKey: cur.SSHKey}
	_, err = v.Put(nc)
	nc.Password.Destroy()
	if err != nil {
		cur.Password.Destroy()
		cur.Enable.Destroy()
		cur.SSHKey.Destroy()
		return i18n.Text{}, i18n.Wrap("assist.svc.vault_save_new_failed", err, i18n.A("prev", prevLabel))
	}
	cur.Password.Destroy()
	cur.Enable.Destroy()
	cur.SSHKey.Destroy()
	e.d.Audit("assist.vault.update", e.rot.updateCred, fmt.Sprintf("run=%s user=%s previous kept as %q", e.id, e.rot.user, prevLabel))
	return i18n.Tx("assist.run.saved_vault_updated", "prev", prevLabel), nil
}

// Reverted: la bóveda solo cambia después de write memory (Saved), y tras eso la ejecución ya no revierte; no hay nada que devolver.
func (e *rotExec) Reverted(_ context.Context, _ string) error { return nil }
