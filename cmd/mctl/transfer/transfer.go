// Package transfer son los comandos `mctl transfer`: servidores temporales de archivos
// (TFTP, FTP, SCP, SFTP, HTTP) y clientes (get y put).
package transfer

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// absAll vuelve absolutas las rutas (el núcleo no conoce el directorio de trabajo de mctl).
func absAll(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		a, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// resolveFiles resuelve --files: sin --from, contra el cwd; con --from, un nombre relativo va dentro de
// esa carpeta (os.Root rechaza «..» y enlaces que salen), no contra el cwd. Una ruta absoluta pasa tal cual
// (fileserve publica --files junto a --from y vuelve a confinar cada archivo).
func resolveFiles(paths []string, from string) ([]string, error) {
	if from == "" {
		return absAll(paths)
	}
	var root *os.Root
	var out []string
	for _, p := range paths {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if filepath.IsAbs(p) {
			out = append(out, filepath.Clean(p))
			continue
		}
		if !filepath.IsLocal(p) {
			return nil, cli.Err("mctl.transfer.files_relative", "path", p)
		}
		if root == nil { // se abre solo si hace falta: sin --files relativos, la carpeta la valida el servidor
			r, err := os.OpenRoot(from)
			if err != nil {
				return nil, err
			}
			defer r.Close()
			root = r
		}
		if _, err := root.Stat(p); err != nil {
			return nil, cli.ErrWrap("mctl.transfer.files_error", err, "path", p)
		}
		out = append(out, filepath.Join(from, p))
	}
	return out, nil
}

func abs(p string) (string, error) {
	if p == "" {
		return "", nil
	}
	return filepath.Abs(p)
}

func parseRange(s string) (lo, hi uint32, err error) {
	if s == "" {
		return 0, 0, nil
	}
	a, b, ok := strings.Cut(s, "-")
	x, e1 := strconv.ParseUint(a, 10, 16)
	y, e2 := strconv.ParseUint(b, 10, 16)
	if !ok || e1 != nil || e2 != nil || x > y {
		return 0, 0, cli.Err("mctl.transfer.pasv_range")
	}
	return uint32(x), uint32(y), nil
}

func serve(c *cli.Env, args []string) error {
	var proto, listen, dir, from, files, pasv string
	var allow cli.List
	var write, any, legacy bool
	var dur time.Duration
	var maxFile, maxTotal int64
	fs, err := cli.Flags("transfer serve", args, func(fs *flag.FlagSet) {
		fs.StringVar(&proto, "proto", "", "tftp, ftp, scp, sftp o http")
		fs.StringVar(&listen, "listen", "", "IP[:PUERTO] de escucha (puerto alto por omisión)")
		fs.BoolVar(&write, "write", false, "acepta subidas (no en http)")
		fs.Var(&allow, "allow", "IP de origen permitida (repetible; obligatoria al recibir por TFTP, donde en UDP la IP de origen se falsifica y la lista solo filtra)")
		fs.StringVar(&dir, "dir", "", "carpeta donde caen los archivos recibidos (por omisión outputs/recibidos/<sello>/)")
		fs.StringVar(&from, "from", "", "carpeta que se publica para leer")
		fs.StringVar(&files, "files", "", "archivos sueltos a publicar, separados por coma (con --from, nombres relativos dentro de esa carpeta)")
		fs.DurationVar(&dur, "duration", 30*time.Minute, "duración (máximo 24h)")
		fs.BoolVar(&any, "any", false, "escuchar en todas las interfaces (con --write exige --allow)")
		fs.BoolVar(&legacy, "legacy-ssh", false, "scp/sftp: ofrece también los algoritmos antiguos de IOS 15.x (aes128-cbc, 3des-cbc, group14-sha1, hmac-sha1, ssh-rsa); apagado por omisión")
		fs.StringVar(&pasv, "pasv-ports", "", "ftp: rango de puertos de datos MIN-MAX")
		fs.Int64Var(&maxFile, "max-file", 0, "tope por archivo recibido en bytes (0 = 512 MiB)")
		fs.Int64Var(&maxTotal, "max-total", 0, "tope de todo lo recibido en bytes (0 = 2 GiB)")
	})
	if err != nil {
		return err
	}
	if proto == "" || listen == "" || fs.NArg() != 0 {
		return errors.New("uso: mctl transfer serve --proto tftp|ftp|scp|sftp|http --listen IP[:PUERTO] [--write] [--allow IP]... [--dir CARPETA] [--from CARPETA] [--files A,B] [--duration 30m]")
	}
	for _, a := range allow {
		if _, err := netip.ParseAddr(a); err != nil {
			return cli.Err("mctl.transfer.allow_not_ip", "value", a)
		}
	}
	lo, hi, err := parseRange(pasv)
	if err != nil {
		return err
	}
	absDir, err := abs(dir)
	if err != nil {
		return err
	}
	absFrom, err := abs(from)
	if err != nil {
		return err
	}
	absFiles, err := resolveFiles(strings.Split(files, ","), absFrom)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt) // Ctrl-C detiene el servidor y audita el cierre
	defer stop()
	st, err := v1.NewTransferServiceClient(c.Conn).StartServer(ctx, &v1.StartServerRequest{Protocol: proto, Listen: listen, AllowAny: any,
		Files: absFiles, FromDir: absFrom, Write: write, RecvDir: absDir, Allow: allow, MaxFileBytes: maxFile, MaxTotalBytes: maxTotal,
		DurationSeconds: int32(dur / time.Second), LegacySsh: legacy, PassivePortMin: lo, PassivePortMax: hi})
	if err != nil {
		return err
	}
	for {
		r, err := st.Recv()
		if err == io.EOF || ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		if cl := r.GetClosed(); cl != nil {
			if cl.Cleanup != "" {
				fmt.Fprintln(c.Out, cli.T("mctl.transfer.closed", "cmd", cl.Cleanup))
			}
			continue
		}
		if rd := r.GetReady(); rd != nil {
			fmt.Fprintln(c.Out, cli.T("mctl.transfer.serving", "proto", rd.Protocol, "addr", rd.Listening, "id", rd.ServerId))
			if rd.FromDir != "" {
				fmt.Fprintln(c.Out, cli.T("mctl.transfer.reads_from", "dir", rd.FromDir))
			}
			if rd.RecvDir != "" {
				fmt.Fprintln(c.Out, cli.T("mctl.transfer.receives_in", "dir", rd.RecvDir))
			}
			if rd.User != "" {
				fmt.Fprintln(c.Out, cli.T("mctl.transfer.credentials", "user", rd.User, "password", rd.Password))
			}
			fmt.Fprint(c.Out, rd.Hint)
			continue
		}
		var t struct {
			Proto, Dir, Client, File, Path, SHA256, Result, Error string
			Bytes                                                 int64
			Duration                                              time.Duration
			Rejected                                              bool
		}
		json.Unmarshal([]byte(r.GetTransferJson()), &t)
		mark := ""
		if t.Rejected {
			mark = cli.T("mctl.transfer.rejected")
		}
		fmt.Fprintf(c.Out, "%s  %s %s %s  %s  %d bytes  %s  %s %s%s\n", time.Now().Format("15:04:05"), t.Proto, t.Dir, t.Client, t.File, t.Bytes, t.Duration.Round(time.Millisecond), t.Result, t.Error, mark)
	}
}

// split separa LOCAL en carpeta y nombre: si es una carpeta existente solo hay carpeta.
func split(local, dir string) (d, name string, err error) {
	if local == "" {
		return dir, "", nil
	}
	if dir != "" { // con --dir/--from, LOCAL es un nombre dentro de esa carpeta
		return dir, filepath.Base(local), nil
	}
	a, err := filepath.Abs(local)
	if err != nil {
		return "", "", err
	}
	if st, err := os.Stat(a); err == nil && st.IsDir() {
		return a, "", nil
	}
	return filepath.Dir(a), filepath.Base(a), nil
}

func get(c *cli.Env, args []string) error {
	var dir, cred, sha256, md5, sha512 string
	var accepted cli.List
	var insecure, legacy bool
	var maxBytes int64
	var timeout time.Duration
	fs, err := cli.Flags("transfer get", args, func(fs *flag.FlagSet) {
		fs.StringVar(&dir, "dir", "", "carpeta de destino (por omisión outputs/recibidos/<sello>/)")
		fs.StringVar(&cred, "cred", "", "ID de la credencial de la bóveda (obligatoria en scp y sftp)")
		fs.StringVar(&sha256, "sha256", "", "SHA-256 esperado")
		fs.StringVar(&md5, "md5", "", "MD5 esperado")
		fs.StringVar(&sha512, "sha512", "", "SHA-512 esperado")
		fs.BoolVar(&insecure, "insecure", false, "https sin verificar el certificado (queda auditado)")
		fs.BoolVar(&legacy, "legacy-ssh", false, "scp/sftp hacia equipos con SSH antiguo (queda auditado)")
		fs.Var(&accepted, "accept-host-key", "huella SHA256 de la llave de host a aceptar (repetible)")
		fs.Int64Var(&maxBytes, "max-bytes", 0, "tope de tamaño en bytes (0 = 2 GiB)")
		fs.DurationVar(&timeout, "timeout", 0, "tiempo máximo (0 = 30m, máximo 4h)")
	})
	if err != nil {
		return err
	}
	if fs.NArg() < 1 || fs.NArg() > 2 {
		return errors.New("uso: mctl transfer get URL [LOCAL] [--dir CARPETA] [--cred ID] [--sha256 H] [--insecure]")
	}
	absDir, err := abs(dir)
	if err != nil {
		return err
	}
	d, name, err := split(fs.Arg(1), absDir)
	if err != nil {
		return err
	}
	r, err := v1.NewTransferServiceClient(c.Conn).Get(context.Background(), &v1.GetRequest{Url: fs.Arg(0), DestDir: d, Name: name, CredentialId: cred,
		Sha256: sha256, Md5: md5, Sha512: sha512, Insecure: insecure, AcceptedHostKeyFingerprints: accepted, MaxBytes: maxBytes,
		TimeoutSeconds: int32(timeout / time.Second), LegacySsh: legacy})
	if err != nil {
		return hostKeyHelp(err)
	}
	fmt.Fprintln(c.Out, r.Result.Report)
	return nil
}

func put(c *cli.Env, args []string) error {
	var from, cred string
	var accepted cli.List
	var legacy bool
	var maxBytes int64
	var timeout time.Duration
	fs, err := cli.Flags("transfer put", args, func(fs *flag.FlagSet) {
		fs.StringVar(&from, "from", "", "carpeta de donde sale el archivo")
		fs.StringVar(&cred, "cred", "", "ID de la credencial de la bóveda (obligatoria en scp y sftp)")
		fs.BoolVar(&legacy, "legacy-ssh", false, "scp/sftp hacia equipos con SSH antiguo (queda auditado)")
		fs.Var(&accepted, "accept-host-key", "huella SHA256 de la llave de host a aceptar (repetible)")
		fs.Int64Var(&maxBytes, "max-bytes", 0, "tope de tamaño en bytes (0 = 2 GiB)")
		fs.DurationVar(&timeout, "timeout", 0, "tiempo máximo (0 = 30m, máximo 4h)")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("uso: mctl transfer put URL LOCAL [--from CARPETA] [--cred ID]")
	}
	absFrom, err := abs(from)
	if err != nil {
		return err
	}
	d, name, err := split(fs.Arg(1), absFrom)
	if err != nil {
		return err
	}
	if name == "" {
		return cli.Err("mctl.transfer.local_not_dir")
	}
	r, err := v1.NewTransferServiceClient(c.Conn).Put(context.Background(), &v1.PutRequest{Url: fs.Arg(0), FromDir: d, Name: name, CredentialId: cred,
		AcceptedHostKeyFingerprints: accepted, MaxBytes: maxBytes, TimeoutSeconds: int32(timeout / time.Second), LegacySsh: legacy})
	if err != nil {
		return hostKeyHelp(err)
	}
	fmt.Fprintln(c.Out, r.Result.Report)
	return nil
}

func ls(c *cli.Env, args []string) error {
	var cred, path string
	var accepted cli.List
	var insecure, legacy, asJSON bool
	var maxEntries int
	var timeout time.Duration
	fs, err := cli.Flags("transfer ls", args, func(fs *flag.FlagSet) {
		fs.StringVar(&cred, "cred", "", "ID de la credencial de la bóveda (obligatoria en scp y sftp)")
		fs.StringVar(&path, "path", "", "carpeta remota (por omisión la de la URL)")
		fs.IntVar(&maxEntries, "max", 0, "tope de entradas (2000 por omisión, máximo 20000)")
		fs.BoolVar(&insecure, "insecure", false, "https sin verificar el certificado (queda auditado)")
		fs.BoolVar(&legacy, "legacy-ssh", false, "scp/sftp hacia equipos con SSH antiguo (queda auditado)")
		fs.Var(&accepted, "accept-host-key", "huella SHA256 de la llave de host a aceptar (repetible)")
		fs.DurationVar(&timeout, "timeout", 0, "tiempo máximo (30s por omisión, máximo 5m)")
		fs.BoolVar(&asJSON, "json", false, "salida JSON")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl transfer ls URL [--cred ID] [--path CARPETA] [--max N] [--insecure] [--legacy-ssh] [--accept-host-key SHA256:...] [--json]")
	}
	r, err := v1.NewTransferServiceClient(c.Conn).Browse(context.Background(), &v1.BrowseRequest{Url: fs.Arg(0), CredentialId: cred, Path: path, MaxEntries: int32(maxEntries),
		Insecure: insecure, LegacySsh: legacy, AcceptedHostKeyFingerprints: accepted, TimeoutSeconds: int32(timeout / time.Second)})
	if err != nil {
		return hostKeyHelp(err)
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(r)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
		return nil
	}
	for _, e := range r.Entries {
		size, mod := "-", "-"
		if e.Size >= 0 {
			size = strconv.FormatInt(e.Size, 10)
		}
		if e.ModifiedMs > 0 {
			mod = time.UnixMilli(e.ModifiedMs).UTC().Format("2006-01-02 15:04")
		}
		name := e.Name
		if e.Type == "dir" {
			name += "/"
		}
		warn := ""
		if e.UnsafeName {
			warn = cli.T("mctl.transfer.unsafe_name")
		}
		fmt.Fprintf(c.Out, "%-5s %-10s %12s  %s  %s%s\n", e.Type, e.Perms, size, mod, name, warn)
	}
	fmt.Fprintln(c.Out, cli.T("mctl.transfer.entries", "n", len(r.Entries), "method", r.Method))
	if r.Truncated {
		fmt.Fprintln(c.Out, cli.T("mctl.transfer.truncated"))
	}
	return nil
}

// hostKeyHelp explica cómo aceptar una llave de host nueva, sin aceptarla por el usuario.
func hostKeyHelp(err error) error {
	if i := strings.Index(err.Error(), "SHA256:"); i >= 0 && (strings.Contains(err.Error(), "llave de host") || strings.Contains(err.Error(), "host key")) {
		fp := strings.Fields(err.Error()[i:])[0]
		return cli.ErrWrap("mctl.common_a.accept_host_key", err, "fp", fp)
	}
	return err
}

func stop(c *cli.Env, args []string) error {
	id, err := cli.OneArg("transfer stop", args)
	if err != nil {
		return err
	}
	r, err := v1.NewTransferServiceClient(c.Conn).StopServer(context.Background(), &v1.StopServerRequest{ServerId: id})
	if err != nil {
		return err
	}
	if !r.Stopped {
		return cli.Err("mctl.transfer.not_open")
	}
	fmt.Fprintln(c.Out, cli.T("mctl.transfer.stopped"))
	return nil
}

func list(c *cli.Env, _ []string) error {
	r, err := v1.NewTransferServiceClient(c.Conn).ListServers(context.Background(), &v1.ListServersRequest{})
	if err != nil {
		return err
	}
	if len(r.Servers) == 0 {
		fmt.Fprintln(c.Out, cli.T("mctl.transfer.none_open"))
	}
	for _, s := range r.Servers {
		fmt.Fprintln(c.Out, cli.T("mctl.transfer.server_line", "id", s.ServerId, "proto", s.Protocol, "addr", s.Listening, "write", s.Write, "transfers", s.Transfers, "rejected", s.Rejected))
	}
	return nil
}

func hint(c *cli.Env, args []string) error {
	fs, err := cli.Flags("transfer hint", args, nil)
	if err != nil {
		return err
	}
	port := 0
	if fs.NArg() >= 2 {
		port, _ = strconv.Atoi(fs.Arg(1))
	}
	if fs.NArg() < 2 || fs.NArg() > 3 || port == 0 {
		return errors.New("uso: mctl transfer hint tftp|ftp|scp|sftp PUERTO-ALTO [IP-DE-ESCUCHA]")
	}
	r, err := v1.NewTransferServiceClient(c.Conn).RedirectHint(context.Background(), &v1.RedirectHintRequest{Protocol: fs.Arg(0), Port: int32(port), Ip: fs.Arg(2)})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, cli.T("mctl.transfer.hint", "std", r.StandardPort, "port", port, "nft", r.Nftables, "remove", r.Remove, "setcap", r.Setcap))
	return nil
}

const help = `  transfer serve --proto tftp|ftp|scp|sftp|http --listen IP[:PUERTO] [--write] [--allow IP]... [--dir CARPETA] [--from CARPETA] [--files A,B] [--duration 30m] [--legacy-ssh] [--pasv-ports MIN-MAX]
        (servidor temporal, puerto alto: tftp 6969, ftp 2121, scp/sftp 2222, http 8080; --dir recibe, --from publica; ftp/scp/sftp muestran usuario y contraseña de la sesión (FTP las manda en claro); recibir por tftp exige --allow; --legacy-ssh activa los algoritmos de IOS 15.x; Ctrl-C lo detiene)
  transfer get URL [LOCAL] [--dir CARPETA] [--cred ID] [--sha256 H] [--md5 H] [--sha512 H] [--insecure] [--legacy-ssh] [--accept-host-key SHA256:...]
        (tftp://, ftp://, scp://, sftp://, http://, https://; archivo nuevo en la carpeta, con MD5 y SHA-256)
  transfer put URL LOCAL [--from CARPETA] [--cred ID] [--legacy-ssh] [--accept-host-key SHA256:...]
        (tftp://, ftp://, scp://, sftp://; sale de la carpeta elegida)
  transfer ls URL [--cred ID] [--path CARPETA] [--max N] [--insecure] [--legacy-ssh] [--accept-host-key SHA256:...] [--json]
        (lista una carpeta remota: ftp (MLSD o LIST), sftp, scp (si el servidor tiene SFTP) y http(s) (índice HTML); tftp no lista)
  transfer stop ID | transfer list | transfer hint tftp|ftp|scp|sftp PUERTO [IP]
        (cierra un servidor, los lista, o explica la redirección nftables a los puertos 69, 21 y 22)`

// Area registra los comandos de transferencias.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "transfer serve", Run: serve},
		{Name: "transfer get", Run: get},
		{Name: "transfer put", Run: put},
		{Name: "transfer ls", Run: ls},
		{Name: "transfer stop", Run: stop},
		{Name: "transfer list", Run: list},
		{Name: "transfer hint", Run: hint},
	}}
}
