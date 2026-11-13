package vault

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func vaultStatus(c *cli.Env, args []string) error {
	if _, err := cli.Flags("vault status", args, nil); err != nil {
		return err
	}
	r, err := v1.NewVaultServiceClient(c.Conn).Status(context.Background(), &v1.StatusRequest{})
	if err != nil {
		return err
	}
	name := map[v1.VaultState]string{v1.VaultState_VAULT_STATE_ABSENT: "absent", v1.VaultState_VAULT_STATE_LOCKED: "locked", v1.VaultState_VAULT_STATE_UNLOCKED: "unlocked"}[r.State]
	fmt.Fprintln(c.Out, cli.T("mctl.vault.status", "state", cli.T("mctl.vault.state_"+name)))
	for _, j := range r.ArmedJobIds {
		fmt.Fprintln(c.Out, cli.T("mctl.vault.armed", "job", j))
	}
	return nil
}

func vaultCreate(c *cli.Env, args []string) error {
	if _, err := cli.Flags("vault create", args, nil); err != nil {
		return err
	}
	a, err := c.Secret(cli.T("mctl.vault.prompt_new_master"))
	if err != nil {
		return err
	}
	b, err := c.Secret(cli.T("mctl.vault.prompt_repeat"))
	if err != nil {
		return err
	}
	defer cli.Wipe(a, b)
	if string(a) != string(b) {
		return cli.Err("mctl.vault.mismatch")
	}
	_, err = v1.NewVaultServiceClient(c.Conn).Create(context.Background(), &v1.CreateRequest{MasterPassword: a})
	return err
}

func vaultUnlock(c *cli.Env, args []string) error {
	if _, err := cli.Flags("vault unlock", args, nil); err != nil {
		return err
	}
	pw, err := c.Secret(cli.T("mctl.vault.prompt_master"))
	if err != nil {
		return err
	}
	defer cli.Wipe(pw)
	_, err = v1.NewVaultServiceClient(c.Conn).Unlock(context.Background(), &v1.UnlockRequest{MasterPassword: pw})
	return err
}

func vaultLock(c *cli.Env, args []string) error {
	if _, err := cli.Flags("vault lock", args, nil); err != nil {
		return err
	}
	_, err := v1.NewVaultServiceClient(c.Conn).Lock(context.Background(), &v1.LockRequest{})
	return err
}

func vaultPasswd(c *cli.Env, args []string) error {
	if _, err := cli.Flags("vault passwd", args, nil); err != nil {
		return err
	}
	cur, err := c.Secret(cli.T("mctl.vault.prompt_current"))
	if err != nil {
		return err
	}
	a, err := c.Secret(cli.T("mctl.vault.prompt_new"))
	if err != nil {
		return err
	}
	b, err := c.Secret(cli.T("mctl.vault.prompt_repeat_new"))
	if err != nil {
		return err
	}
	defer cli.Wipe(cur, a, b)
	if string(a) != string(b) {
		return cli.Err("mctl.vault.mismatch")
	}
	_, err = v1.NewVaultServiceClient(c.Conn).ChangeMasterPassword(context.Background(), &v1.ChangeMasterPasswordRequest{CurrentMasterPassword: cur, NewMasterPassword: a})
	return err
}

func credList(c *cli.Env, args []string) error {
	if _, err := cli.Flags("cred list", args, nil); err != nil {
		return err
	}
	r, err := v1.NewVaultServiceClient(c.Conn).ListCredentials(context.Background(), &v1.ListCredentialsRequest{})
	if err != nil {
		return err
	}
	for _, i := range r.Credentials {
		extra := ""
		if i.HasEnableSecret {
			extra += " +enable"
		}
		if i.HasSshKey {
			extra += cli.T("mctl.vault.cred_key")
		}
		fmt.Fprintf(c.Out, "%s  %s  %s%s\n", i.Id, i.Label, i.Username, extra)
	}
	return nil
}

// wipe es cli.Wipe; una variable para que la prueba vea qué se borra.
var wipe = cli.Wipe

func credAdd(c *cli.Env, args []string) error {
	var label, user string
	var noEnable bool
	if _, err := cli.Flags("cred add", args, func(fs *flag.FlagSet) {
		fs.StringVar(&label, "label", "", "etiqueta")
		fs.StringVar(&user, "user", "", "usuario")
		fs.BoolVar(&noEnable, "no-enable", false, "no pedir el enable")
	}); err != nil {
		return err
	}
	if user == "" {
		return cli.Err("mctl.vault.missing_user")
	}
	pw, err := c.Secret(cli.T("mctl.vault.prompt_device"))
	if err != nil {
		return err
	}
	defer wipe(pw) // antes de leer el enable: si esa lectura falla, la contraseña de login no queda en memoria
	var en []byte
	if !noEnable {
		// Un guion que no trae la línea de enable (EOF) quiere decir «sin enable»; la contraseña de login sí es obligatoria.
		if en, err = c.Secret(cli.T("mctl.vault.prompt_enable")); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	defer wipe(en)
	r, err := v1.NewVaultServiceClient(c.Conn).PutCredential(context.Background(), &v1.PutCredentialRequest{Label: label, Username: user, Password: pw, EnableSecret: en})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.Id)
	return nil
}

func credRm(c *cli.Env, args []string) error {
	id, err := cli.OneArg("cred rm", args)
	if err != nil {
		return err
	}
	_, err = v1.NewVaultServiceClient(c.Conn).DeleteCredential(context.Background(), &v1.DeleteCredentialRequest{Id: id})
	return err
}

// help son las líneas de este área en mctl --help.
const help = `  vault status | create | unlock | lock | passwd
  cred  list | add --label L --user U [--no-enable] | rm ID
  cred  backup export RUTA [--overwrite] [--yes]  |  backup import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
        (respaldo cifrado de la bóveda con una frase propia, distinta de la maestra y de al menos 12 caracteres; la frase se lee de la terminal o de stdin, nunca como argumento.
         export exige --yes: el archivo trae todas tus credenciales. import muestra el estado de cada una: nueva, igual, conflicto_etiqueta o reservada (se omite);
         cada conflicto necesita una decisión por ID o etiqueta, o --all; si falta una no se importa nada)`

// Area registra los comandos de vault.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "vault status", Run: vaultStatus},
		{Name: "vault create", Run: vaultCreate},
		{Name: "vault unlock", Run: vaultUnlock},
		{Name: "vault lock", Run: vaultLock},
		{Name: "vault passwd", Run: vaultPasswd},
		{Name: "cred list", Run: credList},
		{Name: "cred add", Run: credAdd},
		{Name: "cred rm", Run: credRm},
		{Name: "cred backup export", Run: backupExport},
		{Name: "cred backup import", Run: backupImport},
	}}
}
