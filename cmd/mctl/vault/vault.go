package vault

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"

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
		kind := cli.T("mctl.vault.kind_password")
		if i.Kind == "key" {
			kind = cli.T("mctl.vault.kind_key")
		} else if i.HasSshKey {
			extra += cli.T("mctl.vault.cred_key")
		}
		fmt.Fprintf(c.Out, "%s  %s  %s  %s%s\n", i.Id, i.Label, i.Username, kind, extra)
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

// cred keygen --label L --user U: el id y la pública (la privada nunca sale del núcleo).
func credKeygen(c *cli.Env, args []string) error {
	var label, user string
	if _, err := cli.Flags("cred keygen", args, func(fs *flag.FlagSet) {
		fs.StringVar(&label, "label", "", "etiqueta")
		fs.StringVar(&user, "user", "", "usuario")
	}); err != nil {
		return err
	}
	if user == "" {
		return cli.Err("mctl.vault.missing_user")
	}
	r, err := v1.NewVaultServiceClient(c.Conn).GenerateKeyCredential(context.Background(), &v1.GenerateKeyCredentialRequest{Label: label, Username: user})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.Id)
	fmt.Fprintln(c.Out, strings.TrimSpace(r.PublicKey))
	return nil
}

// cred pubkey ID: SOLO la línea authorized_keys, para redirigirla con >>.
func credPubkey(c *cli.Env, args []string) error {
	id, err := cli.OneArg("cred pubkey", args)
	if err != nil {
		return err
	}
	r, err := v1.NewVaultServiceClient(c.Conn).GetCredentialPublicKey(context.Background(), &v1.GetCredentialPublicKeyRequest{Id: id})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, strings.TrimSpace(r.PublicKey))
	return nil
}

// cred rekey ID --yes: llave nueva con el mismo id; sin --yes no toca nada.
func credRekey(c *cli.Env, args []string) error {
	var yes bool
	fs, err := cli.Flags("cred rekey", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&yes, "yes", false, "confirmar el reemplazo de la llave")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return cli.Err("mctl.cli.needs_id", "name", "cred rekey")
	}
	if !yes {
		return cli.Err("mctl.vault.rekey_confirm_yes")
	}
	cl := v1.NewVaultServiceClient(c.Conn)
	r, err := cl.RegenerateKeyCredential(context.Background(), &v1.RegenerateKeyCredentialRequest{Id: fs.Arg(0), Confirm: true})
	if err != nil {
		return err
	}
	if r.PreviousOrigin == "imported" {
		fmt.Fprintln(c.Out, cli.T("mctl.vault.rekey_was_imported"))
	}
	fmt.Fprintln(c.Out, strings.TrimSpace(r.PublicKey))
	fmt.Fprintln(c.Out, cli.T("mctl.vault.rekey_done"))
	return nil
}

// maxKeyFile es el tope del núcleo para una llave importada (vault.MaxFieldBytes); mctl lo aplica antes de leer el archivo entero.
const maxKeyFile = 64 << 10

// readKeyFile lee la llave con el tope: ni abre un archivo enorme ni lo lee entero.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, cli.ErrWrap("mctl.vault.import_read", err, "path", path)
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxKeyFile {
		return nil, cli.Err("mctl.vault.import_too_big", "max", maxKeyFile>>10)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, cli.ErrWrap("mctl.vault.import_read", err, "path", path)
	}
	if len(b) > maxKeyFile {
		wipe(b)
		return nil, cli.Err("mctl.vault.import_too_big", "max", maxKeyFile>>10)
	}
	return b, nil
}

// needsPassphrase dice si el núcleo respondió que la llave está cifrada y falta la frase.
func needsPassphrase(err error) bool {
	for _, d := range status.Convert(err).Details() {
		if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.Reason == "vault.err.key_passphrase_required" {
			return true
		}
	}
	return false
}

// cred import-key --label L --user U --file PATH: guarda en la bóveda una llave privada que ya tienes. mctl lee el
// archivo (el núcleo recibe el contenido, nunca la ruta). La frase se pide sin eco solo si el núcleo dice que hace falta (o se lee de
// stdin sin terminal); nunca como argumento.
func credImportKey(c *cli.Env, args []string) error {
	var label, user, file string
	if _, err := cli.Flags("cred import-key", args, func(fs *flag.FlagSet) {
		fs.StringVar(&label, "label", "", "etiqueta")
		fs.StringVar(&user, "user", "", "usuario")
		fs.StringVar(&file, "file", "", "archivo de la llave privada")
	}); err != nil {
		return err
	}
	if user == "" {
		return cli.Err("mctl.vault.missing_user")
	}
	if file == "" {
		return cli.Err("mctl.vault.import_missing_file")
	}
	key, err := readKeyFile(file)
	if err != nil {
		return err
	}
	defer wipe(key)
	var pass []byte
	defer func() { wipe(pass) }()
	cl := v1.NewVaultServiceClient(c.Conn)
	r, err := cl.ImportKeyCredential(context.Background(), &v1.ImportKeyCredentialRequest{Label: label, Username: user, PrivateKey: key, Passphrase: pass})
	if err != nil && needsPassphrase(err) {
		// El núcleo ya no usa el búfer enviado (el cable lo copia): se vuelve a mandar una vez con la frase pedida.
		if pass, err = c.Secret(cli.T("mctl.vault.prompt_key_passphrase")); err != nil {
			return err
		}
		r, err = cl.ImportKeyCredential(context.Background(), &v1.ImportKeyCredentialRequest{Label: label, Username: user, PrivateKey: key, Passphrase: pass})
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.Id)
	fmt.Fprintln(c.Out, strings.TrimSpace(r.PublicKey))
	fmt.Fprintln(c.Out, cli.T("mctl.vault.import_fingerprint", "fingerprint", r.Fingerprint))
	fmt.Fprintln(c.Out, cli.T("mctl.vault.import_algorithm", "algorithm", r.Algorithm, "bits", r.Bits))
	if r.Weak {
		fmt.Fprintln(c.Out, cli.T("mctl.vault.import_weak", "bits", r.Bits))
	}
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
  cred  keygen --label L --user U | pubkey ID | rekey ID --yes
        (llave SSH ed25519 generada en el núcleo: la privada nunca sale. keygen imprime el id y la pública; pubkey imprime SOLO la línea authorized_keys, para «>> authorized_keys»;
         rekey cambia la llave conservando el id: autoriza la nueva en cada equipo, la anterior deja de servir. No confundir con «cred rotate», que rota una contraseña en un equipo)
  cred  import-key --label L --user U --file RUTA
        (importa a la bóveda una llave privada que ya tienes (OpenSSH, PKCS#1, PKCS#8 sin cifrar, SEC1 o PEM legado cifrado; ed25519, ECDSA o RSA de 1024 bits o más; máximo 64 KiB). mctl lee el archivo; la frase se pide sin eco (o se lee una línea de stdin si no hay terminal) solo si la llave está cifrada, nunca como argumento. Una PKCS#8 cifrada («ENCRYPTED PRIVATE KEY») se rechaza: conviértela antes con «ssh-keygen -p». Imprime el id, la pública, la huella y el algoritmo; avisa si es RSA de menos de 3072 bits. La privada nunca sale del núcleo, como las generadas;
         rekey sobre una importada la reemplaza por una ed25519 generada)
  cred  backup export RUTA [--overwrite] [--yes]  |  backup import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]
        (respaldo cifrado de la bóveda con una frase propia, distinta de la maestra y de al menos 12 caracteres; la frase se lee de la terminal o de stdin, nunca como argumento.
         export exige --yes: el archivo trae todas tus credenciales. import muestra el estado de cada una: new, same, label_conflict o reserved (se omite);
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
		{Name: "cred keygen", Run: credKeygen},
		{Name: "cred pubkey", Run: credPubkey},
		{Name: "cred import-key", Run: credImportKey},
		{Name: "cred rekey", Run: credRekey},
		{Name: "cred rm", Run: credRm},
		{Name: "cred backup export", Run: backupExport},
		{Name: "cred backup import", Run: backupImport},
	}}
}
