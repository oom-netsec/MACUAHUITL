package transfer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// Topes del listado remoto: lo que devuelve el servidor no es de fiar ni tiene tamaño acotado.
const (
	DefaultMaxEntries    = 2000
	MaxEntriesCap        = 20000
	maxListBytes         = 4 << 20  // texto de MLSD/LIST y cuerpo del índice HTTP
	maxSFTPBytes         = 16 << 20 // bytes que se leen del subsistema SFTP al listar
	maxBrowsePath        = 1024
	DefaultBrowseTimeout = 30 * time.Second
	MaxBrowseTimeout     = 5 * time.Minute
)

// Listing es el contenido de una carpeta remota, con las carpetas primero y por nombre.
type Listing struct {
	Path      string
	Entries   []Entry
	Truncated bool   // se cortó por el tope de entradas o de bytes
	Method    string // mlsd, list, sftp o http
}

// NoListingError: el protocolo o el servidor no permiten listar. No es una falla de conexión.
type NoListingError struct{ Proto, Reason string }

func (e *NoListingError) Error() string { return "este servidor no permite listar: " + e.Reason }

// browsePath valida la carpeta que se pide: va como texto a un protocolo, así que sin control ni formato invisible.
func browsePath(p string) error {
	if len(p) > maxBrowsePath {
		return errors.New("transfer: la ruta es demasiado larga")
	}
	for _, c := range p {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return errors.New("transfer: la ruta tiene caracteres de control o invisibles")
		}
	}
	return nil
}

// Browse lista la carpeta path de la URL de r (FTP: MLSD o, si no, LIST; SFTP y SCP: SFTP; HTTP(S):
// índice HTML; TFTP no lista). max acota las entradas (0 = DefaultMaxEntries). r.Timeout acota el tiempo.
func Browse(ctx context.Context, r Request, path string, max int) (Listing, error) {
	if r.URL == nil {
		return Listing{}, errors.New("transfer: falta la URL")
	}
	if r.URL.Scheme == "tftp" { // por diseño del protocolo: ni se abre un socket
		return Listing{}, &NoListingError{"tftp", "TFTP no tiene comando para listar carpetas"}
	}
	if _, err := Port(r.URL); err != nil {
		return Listing{}, err
	}
	if path == "" {
		path = r.URL.Path
	}
	if err := browsePath(path); err != nil {
		return Listing{}, err
	}
	if max <= 0 {
		max = DefaultMaxEntries
	}
	max = min(max, MaxEntriesCap)
	to := r.Timeout
	if to <= 0 {
		to = DefaultBrowseTimeout
	}
	if to > MaxBrowseTimeout {
		return Listing{}, fmt.Errorf("transfer: el tiempo máximo es %s", MaxBrowseTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	var ls Listing
	var err error
	switch r.URL.Scheme {
	case "ftp":
		ls, err = r.ftpList(ctx, path)
	case "sftp", "scp":
		ls, err = r.sftpList(ctx, path)
	case "http", "https":
		ls, err = r.httpList(ctx, path)
	default:
		return Listing{}, fmt.Errorf("transfer: esquema %q no soportado", r.URL.Scheme)
	}
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w (%v)", ctx.Err(), err)
		}
		return Listing{}, err
	}
	ls.Path = path
	sort.SliceStable(ls.Entries, func(i, j int) bool {
		a, b := ls.Entries[i], ls.Entries[j]
		if (a.Type == "dir") != (b.Type == "dir") {
			return a.Type == "dir"
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	if len(ls.Entries) > max {
		ls.Entries, ls.Truncated = ls.Entries[:max], true
	}
	return ls, nil
}

// ---- FTP ----

// readCapped lee hasta maxListBytes de la conexión de datos; si hay más, corta en la última línea entera.
func readCapped(rd io.Reader) (text string, truncated bool, err error) {
	b, err := io.ReadAll(io.LimitReader(rd, maxListBytes+1))
	if err != nil {
		return "", false, err
	}
	if len(b) > maxListBytes {
		b = b[:maxListBytes]
		if i := strings.LastIndexByte(string(b), '\n'); i >= 0 {
			b = b[:i+1]
		}
		return string(b), true, nil
	}
	return string(b), false, nil
}

// listData pide un listado (MLSD o LIST) por una conexión de datos nueva.
func (c *ftpConn) listData(ctx context.Context, verb string) (string, bool, error) {
	dc, err := c.data(ctx)
	if err != nil {
		return "", false, err
	}
	defer dc.Close()
	if _, _, err := c.cmd(150, 125, "%s", verb); err != nil {
		return "", false, err
	}
	text, trunc, err := readCapped(dc)
	if err != nil {
		return "", false, err
	}
	if trunc { // se deja de leer: el servidor sigue mandando y se cierra la conexión sin esperar su cierre
		return text, true, nil
	}
	dc.Close()
	if _, _, err := c.resp(226, 250); err != nil {
		return "", false, err
	}
	return text, false, nil
}

func (r *Request) ftpList(ctx context.Context, path string) (Listing, error) {
	if err := cleanFTP(path); err != nil {
		return Listing{}, err
	}
	c, err := r.ftpLogin(ctx)
	if err != nil {
		return Listing{}, err
	}
	defer c.close()
	if path != "" {
		if _, _, err := c.cmd(250, 0, "CWD %s", path); err != nil {
			return Listing{}, err
		}
	}
	// MLSD (RFC 3659) da tipos, tamaños y fechas sin ambigüedad; si el servidor no lo entiende, LIST.
	text, trunc, err := c.listData(ctx, "MLSD")
	if err == nil {
		return Listing{Entries: ParseMLSD(text), Truncated: trunc, Method: "mlsd"}, nil
	}
	var re *ftpReplyError
	if ctx.Err() != nil || !errors.As(err, &re) || re.Code < 500 {
		return Listing{}, err
	}
	text, trunc, err = c.listData(ctx, "LIST")
	if err != nil {
		return Listing{}, err
	}
	return Listing{Entries: ParseList(text, time.Now()), Truncated: trunc, Method: "list"}, nil
}

// ---- SFTP (y SCP, que lista por el subsistema SFTP si el servidor lo tiene) ----

var errNoSubsystem = errors.New("el servidor rechazó el subsistema sftp")

// sftpOpen abre el subsistema SFTP leyendo a lo más limit bytes del servidor (pkg/sftp lee un
// directorio entero en memoria: así un servidor hostil no la llena).
func sftpOpen(c *ssh.Client, limit int64) (*sftp.Client, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	wr, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	rd, err := s.StdoutPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := s.RequestSubsystem("sftp"); err != nil {
		s.Close()
		return nil, fmt.Errorf("%w: %v", errNoSubsystem, err)
	}
	cl, err := sftp.NewClientPipe(io.LimitReader(rd, limit), wr)
	if err != nil {
		s.Close()
		return nil, err
	}
	return cl, nil
}

func (r *Request) sftpList(ctx context.Context, path string) (Listing, error) {
	if r.SSH == nil {
		return Listing{}, errors.New("transfer: falta la conexión SSH")
	}
	sess, err := r.SSH(ctx)
	if err != nil {
		return Listing{}, err
	}
	c := sess.Client()
	stop := closeOnDone(ctx, c)
	defer func() { stop(); sess.Close() }()
	cl, err := sftpOpen(c, maxSFTPBytes)
	if err != nil {
		if r.URL.Scheme == "scp" && errors.Is(err, errNoSubsystem) {
			return Listing{}, &NoListingError{"scp", "SCP no lista y el servidor no ofrece el subsistema SFTP"}
		}
		return Listing{}, err
	}
	defer cl.Close()
	if path == "" {
		path = "."
	}
	fis, err := cl.ReadDir(path)
	if err != nil {
		return Listing{}, err
	}
	var ls Listing
	ls.Method = "sftp"
	for _, fi := range fis {
		typ := "other"
		switch m := fi.Mode(); {
		case m.IsDir():
			typ = "dir"
		case m&os.ModeSymlink != 0:
			typ = "link"
		case m.IsRegular():
			typ = "file"
		}
		e, ok := entry(fi.Name(), typ)
		if !ok {
			continue
		}
		e.Size, e.ModTime = fi.Size(), fi.ModTime()
		if e.Perms = fi.Mode().Perm().String(); len(e.Perms) == 10 {
			e.Perms = e.Perms[1:]
		}
		if typ == "dir" {
			e.Size = -1
		}
		ls.Entries = append(ls.Entries, e)
	}
	return ls, nil
}

// ---- HTTP(S): índice HTML simple ----

func (r *Request) httpList(ctx context.Context, path string) (Listing, error) {
	u := *r.URL
	u.User, u.RawQuery, u.ForceQuery, u.Fragment = nil, "", false, "" // la query suele llevar tokens
	if path != "" {
		u.Path, u.RawPath = path, ""
	}
	if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	cl, closeIdle := r.httpClient()
	defer closeIdle()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Listing{}, err
	}
	req.Header.Set("Accept", "text/html")
	resp, err := cl.Do(req)
	if err != nil {
		return Listing{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Listing{}, fmt.Errorf("HTTP %s", resp.Status)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); !strings.Contains(ct, "html") {
		return Listing{}, errors.New("la respuesta no es un índice HTML (Content-Type " + resp.Header.Get("Content-Type") + ")")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return Listing{}, err
	}
	trunc := len(body) > maxListBytes
	if trunc {
		body = body[:maxListBytes]
	}
	es, more := ParseHTMLIndex(body, MaxEntriesCap+1)
	return Listing{Entries: es, Truncated: trunc || more, Method: "http"}, nil
}
