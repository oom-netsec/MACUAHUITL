package vault

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

var acciones = map[string]bool{"renombrar": true, "reemplazar": true, "omitir": true}

// confirmed: --yes, o «s» en la terminal. Sin terminal y sin --yes no se exporta: el archivo trae todas las credenciales.
func confirmed(c *cli.Env, yes bool) error {
	if yes {
		return nil
	}
	if c.TTY == nil {
		return cli.Err("mctl.vault.backup_confirm_yes")
	}
	fmt.Fprint(c.Out, cli.T("mctl.vault.backup_confirm_prompt"))
	line, _ := c.In.ReadString('\n')
	if l := strings.ToLower(strings.TrimSpace(line)); l != "s" && l != "si" && l != "sí" && l != "y" && l != "yes" {
		return cli.Err("mctl.vault.cancelled")
	}
	return nil
}

// cred backup export RUTA [--overwrite] [--yes]
func backupExport(c *cli.Env, args []string) error {
	var overwrite, yes bool
	fs, err := cli.Flags("cred backup export", args, func(fs *flag.FlagSet) {
		fs.BoolVar(&overwrite, "overwrite", false, "reemplazar el archivo si existe")
		fs.BoolVar(&yes, "yes", false, "confirmar que el archivo trae todas las credenciales")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl cred backup export RUTA [--overwrite] [--yes]")
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	if err := confirmed(c, yes); err != nil {
		return err
	}
	a, err := c.Secret(cli.T("mctl.vault.prompt_backup_phrase_new"))
	if err != nil {
		return err
	}
	defer wipe(a)
	b, err := c.Secret(cli.T("mctl.vault.prompt_backup_repeat"))
	if err != nil {
		return err
	}
	defer wipe(b)
	if string(a) != string(b) {
		return cli.Err("mctl.vault.phrase_mismatch")
	}
	r, err := v1.NewVaultServiceClient(c.Conn).ExportBackup(context.Background(), &v1.ExportBackupRequest{Path: path, Passphrase: a, Overwrite: overwrite, Confirm: true})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, cli.T("mctl.vault.backup_done", "n", r.Count, "path", path))
	if r.NoPermissions {
		fmt.Fprintln(c.Out, cli.T("mctl.vault.backup_no_perms"))
	}
	return nil
}

// cred backup import RUTA [--decision ID=acción]... [--all=acción] [--preview]
func backupImport(c *cli.Env, args []string) error {
	var decs cli.List
	var all string
	var onlyPreview bool
	fs, err := cli.Flags("cred backup import", args, func(fs *flag.FlagSet) {
		fs.Var(&decs, "decision", "ID=acción (o ETIQUETA=acción) para un conflicto (repetible)")
		fs.StringVar(&all, "all", "", "acción para los conflictos sin --decision")
		fs.BoolVar(&onlyPreview, "preview", false, "solo la vista previa")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl cred backup import RUTA [--decision ID=renombrar|reemplazar|omitir]... [--all=renombrar|reemplazar|omitir] [--preview]")
	}
	if all != "" && !acciones[all] {
		return cli.Err("mctl.import_a.bad_all", "value", all)
	}
	dec := map[string]string{}
	for _, d := range decs {
		k, act, ok := strings.Cut(d, "=")
		if !ok || k == "" || !acciones[act] {
			return cli.Err("mctl.import_a.bad_decision", "value", d)
		}
		dec[k] = act
	}
	path, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	phrase, err := c.Secret(cli.T("mctl.vault.prompt_backup_phrase"))
	if err != nil {
		return err
	}
	defer wipe(phrase)
	cl := v1.NewVaultServiceClient(c.Conn)
	p, err := cl.PreviewBackupImport(context.Background(), &v1.PreviewBackupImportRequest{Path: path, Passphrase: phrase})
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.Out, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, cli.T("mctl.vault.import_header"))
	var req []*v1.VaultBackupDecision
	var missing []string
	for _, it := range p.Items {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", it.Id, it.Label, it.State)
		a, ok := dec[it.Id]
		if !ok {
			a, ok = dec[it.Label]
		}
		if it.State == "conflicto_etiqueta" && !ok {
			if a = all; a == "" {
				missing = append(missing, it.Label)
				continue
			}
		} else if !ok {
			continue
		}
		req = append(req, &v1.VaultBackupDecision{Id: it.Id, Action: a})
	}
	tw.Flush()
	if onlyPreview {
		return nil
	}
	if len(missing) > 0 {
		return cli.Err("mctl.import_a.missing", "n", len(missing), "ids", strings.Join(missing, ", "))
	}
	r, err := cl.ApplyBackupImport(context.Background(), &v1.ApplyBackupImportRequest{Token: p.Token, Decisions: req})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, cli.T("mctl.vault.imported", "created", r.Created, "replaced", r.Replaced, "renamed", r.Renamed, "skipped", r.Skipped, "same", r.Same))
	return nil
}
