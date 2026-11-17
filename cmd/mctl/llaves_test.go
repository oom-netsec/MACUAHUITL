package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// keygen imprime el id y la pública; la guarda en la bóveda.
func keygen(t *testing.T, label string) (id, pub string) {
	t.Helper()
	out := must(t, "", "cred", "keygen", "--label", label, "--user", "USR-"+label)
	ls := strings.Split(strings.TrimSpace(out), "\n")
	if len(ls) != 2 || !strings.HasPrefix(ls[1], "ssh-ed25519 ") {
		t.Fatalf("keygen:\n%s", out)
	}
	return ls[0], ls[1]
}

// `cred pubkey` imprime SOLO la línea authorized_keys (más el salto final): se redirige con >> sin limpiar nada.
func TestCredPubkeyPuntaAPunta(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	id, pub := keygen(t, "ops")
	out := must(t, "", "cred", "pubkey", id)
	if out != pub+"\n" {
		t.Fatalf("pubkey = %q, quería exactamente %q", out, pub+"\n")
	}
	if l := must(t, "", "cred", "list"); !strings.Contains(l, id) || !strings.Contains(l, "llave") {
		t.Fatalf("list sin el tipo:\n%s", l)
	}
	if _, err := mctl(t, "", "cred", "pubkey"); err == nil {
		t.Fatal("pubkey sin ID debió fallar")
	}
	if _, err := mctl(t, "", "cred", "keygen", "--label", "x"); err == nil {
		t.Fatal("keygen sin --user debió fallar")
	}
}

// rekey sin --yes no cambia nada; con --yes la pública cambia y el id es el mismo.
func TestCredRekeyExigeYes(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	id, pub := keygen(t, "ops")
	if _, err := mctl(t, "", "cred", "rekey", id); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("sin --yes: %v", err)
	}
	if got := must(t, "", "cred", "pubkey", id); got != pub+"\n" {
		t.Fatalf("la llave cambió sin --yes: %q", got)
	}
	out := must(t, "", "cred", "rekey", id, "--yes")
	nueva := strings.Fields(out)
	if !strings.Contains(out, "ssh-ed25519 ") || strings.Contains(out, pub) || len(nueva) < 3 {
		t.Fatalf("rekey:\n%s", out)
	}
	if got := must(t, "", "cred", "pubkey", id); got == pub+"\n" || !strings.Contains(out, strings.TrimSpace(got)) {
		t.Fatalf("pubkey tras rekey: %q", got)
	}
}

func TestCredBackupAvisaLlaves(t *testing.T) {
	startCore(t)
	must(t, "maestra\nmaestra\n", "vault", "create")
	keygen(t, "ops")
	ruta := filepath.Join(t.TempDir(), "r.mcvault")
	out := must(t, "frase-respaldo-1\nfrase-respaldo-1\n", "cred", "backup", "export", ruta, "--yes")
	if strings.Count(out, "1 llave") < 2 {
		t.Fatalf("falta el aviso antes y después:\n%s", out)
	}
}

func TestHostsCarpetasYMover(t *testing.T) {
	startCore(t)
	must(t, "", "hosts", "folder", "add", "Lab")
	if _, err := mctl(t, "", "hosts", "folder", "add", "Lab"); err == nil {
		t.Fatal("carpeta repetida debió fallar")
	}
	id := addHost(t, "SW1", "10.0.0.1")
	must(t, "", "hosts", "mv", "--folder", "Lab", id)
	if out := must(t, "", "hosts", "folder", "list"); !regexp.MustCompile(`(?m)^Lab\s+1\b`).MatchString(out) {
		t.Fatalf("folder list:\n%s", out)
	}
	must(t, "", "hosts", "folder", "rename", "Lab", "Piso2")
	if out := must(t, "", "hosts", "list", "--folder", "Piso2"); !strings.Contains(out, "SW1") {
		t.Fatalf("rename:\n%s", out)
	}
	// Sin --yes y con hosts: dice cuántos, sale con error y no borra.
	if _, err := mctl(t, "", "hosts", "folder", "rm", "Piso2"); err == nil || !strings.Contains(err.Error(), "1 host") || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("rm sin --yes: %v", err)
	}
	if out := must(t, "", "hosts", "folder", "list"); !strings.Contains(out, "Piso2") {
		t.Fatalf("rm sin --yes borró la carpeta:\n%s", out)
	}
	must(t, "", "hosts", "mv", "--folder", "", id)
	if out := must(t, "", "hosts", "folder", "list"); !strings.Contains(out, "Piso2") || strings.Contains(out, "SW1") {
		t.Fatalf("mv a sin carpeta:\n%s", out)
	}
	must(t, "", "hosts", "folder", "rm", "Piso2")
	if out := must(t, "", "hosts", "folder", "list"); strings.Contains(out, "Piso2") {
		t.Fatalf("rm vacía:\n%s", out)
	}
	// Con hosts y --yes: se borra la carpeta, los hosts quedan.
	must(t, "", "hosts", "mv", "--folder", "Otra", id)
	must(t, "", "hosts", "folder", "rm", "Otra", "--yes")
	if out := must(t, "", "hosts", "list"); !strings.Contains(out, "SW1") {
		t.Fatalf("el host se perdió:\n%s", out)
	}
}

func TestHostsPlataformaYOrdenDeInicio(t *testing.T) {
	startCore(t)
	out := must(t, "", "hosts", "add", "srv", "--address", "10.0.0.5", "--platform", "linux", "--startup-command", "tmux a")
	m := hostIDRe.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("add: %q", out)
	}
	if j := must(t, "", "hosts", "list", "--json"); !strings.Contains(j, "tmux a") || !strings.Contains(j, "linux") {
		t.Fatalf("json:\n%s", j)
	}
	must(t, "", "hosts", "edit", m[1], "--platform", "windows", "--startup-command", "cmd /c echo ok")
	if j := must(t, "", "hosts", "list", "--json"); !strings.Contains(j, "cmd /c echo ok") || !strings.Contains(j, "windows") {
		t.Fatalf("json tras edit:\n%s", j)
	}
	// Editar otro campo no toca la orden ni la plataforma.
	must(t, "", "hosts", "edit", m[1], "--notes", "x")
	if j := must(t, "", "hosts", "list", "--json"); !strings.Contains(j, "cmd /c echo ok") || !strings.Contains(j, "windows") {
		t.Fatalf("edit sin --startup-command perdió la orden o la plataforma:\n%s", j)
	}
	must(t, "", "hosts", "edit", m[1], "--startup-command", "")
	if j := must(t, "", "hosts", "list", "--json"); strings.Contains(j, "cmd /c echo ok") {
		t.Fatalf("la orden no se borró:\n%s", j)
	}
}
