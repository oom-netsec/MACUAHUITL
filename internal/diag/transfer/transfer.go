// Package transfer son los clientes de transferencia: TFTP (RFC 1350 con blksize y tsize),
// FTP pasivo, SCP y SFTP (sobre una conexión SSH que abre quien llama, con llave de host
// estricta) y HTTP(S) de solo bajada. Toda conexión sale por las funciones de Net, que en la
// app son las del EgressGuard. Con tope de tamaño y de tiempo.
//
// Las descargas caen en una carpeta elegida por el usuario: archivo nuevo (O_EXCL, 0600, sin
// seguir enlaces), solo con el nombre base saneado, con MD5 y SHA-256 calculados al vuelo y,
// si se pide, verificados. Los envíos salen de una carpeta elegida, con las reglas de la
// publicación de fileserve.
package transfer

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/fileserve"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/sys"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// Topes por omisión.
const (
	DefaultMaxBytes = 2 << 30
	DefaultTimeout  = 30 * time.Minute
	MaxTimeout      = 4 * time.Hour
)

var errTooBig = i18n.New("xfer.err.too_big", nil)

// Net es la única puerta de salida. Dial es TCP; Packet abre un socket UDP sin conectar
// (TFTP contesta desde otro puerto). En la app, ambas pasan por el EgressGuard.
type Net struct {
	Dial   func(ctx context.Context, network, host string, port uint16) (net.Conn, error)
	Packet func(ctx context.Context, host string, port uint16) (net.PacketConn, *net.UDPAddr, error)
}

// SSHSession es una conexión SSH ya autenticada y con la llave de host verificada
// (*transport.Session la cumple); el cliente la cierra al terminar.
type SSHSession interface {
	Client() *ssh.Client
	Close() error
}

// GuardNet arma la salida de un trabajo sobre el EgressGuard: lo que no autorizó el
// usuario para jobID se niega y se audita.
func GuardNet(g *transport.Guard, jobID string) Net {
	return Net{
		Dial: g.DialerFor(jobID),
		Packet: func(ctx context.Context, host string, port uint16) (net.PacketConn, *net.UDPAddr, error) {
			return g.PacketTo(ctx, jobID, host, port)
		},
	}
}

type Request struct {
	URL      *url.URL
	Net      Net
	SSH      func(ctx context.Context) (SSHSession, error) // scp y sftp; la sesión se cierra al terminar
	User     string                                        // FTP; vacío = anónimo
	Pass     string
	Insecure bool // HTTPS sin verificar el certificado (explícito, se audita fuera)
	MaxBytes int64
	Timeout  time.Duration
	DenyDirs []string

	// OnProgress recibe el avance (a lo más 10 veces por segundo y un último aviso al terminar). Puede ser nil.
	OnProgress func(Progress)
	track      *progressTracker

	// Descarga (Get).
	DestDir    string
	Name       string // nombre local; vacío = el de la URL
	WantSHA256 string
	WantMD5    string

	// Envío (Put): se toma de FromDir el archivo regular Name.
	FromDir string
}

type Result struct {
	Path     string // archivo guardado (Get) o enviado (Put)
	Bytes    int64
	MD5      string
	SHA256   string
	Verified string // "", "ok" o "distinto"
	Duration time.Duration
}

// Port da el puerto de la URL, o el estándar del esquema.
func Port(u *url.URL) (uint16, error) {
	if p := u.Port(); p != "" {
		var n uint16
		if _, err := fmt.Sscanf(p, "%d", &n); err != nil || n == 0 {
			return 0, i18n.New("xfer.err.port", i18n.A("port", p))
		}
		return n, nil
	}
	switch u.Scheme {
	case "tftp":
		return 69, nil
	case "ftp":
		return 21, nil
	case "scp", "sftp":
		return 22, nil
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	}
	return 0, i18n.New("xfer.err.scheme_all", i18n.A("scheme", u.Scheme))
}

func (r *Request) limits() (int64, error) {
	if r.Timeout > MaxTimeout {
		return 0, i18n.New("xfer.err.max_time", i18n.A("max", MaxTimeout))
	}
	if r.MaxBytes <= 0 {
		return DefaultMaxBytes, nil
	}
	return r.MaxBytes, nil
}

// remotePath es la ruta de la URL sin el "/" inicial, validada: se manda como texto de un
// protocolo (o a un shell remoto en scp), así que nada de control ni metacaracteres.
func remotePath(u *url.URL) (string, error) {
	p := strings.TrimPrefix(u.Path, "/")
	if p == "" || strings.HasSuffix(p, "/") || strings.HasPrefix(p, "-") { // "-" inicial sería una opción de scp
		return "", i18n.New("xfer.err.name_url", nil)
	}
	for _, c := range p {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-/:@+,=~", c)
		if !ok {
			return "", i18n.New("xfer.err.char", i18n.A("char", strconv.QuoteRune(c)))
		}
	}
	return p, nil
}

type sink struct {
	f        *os.File
	n, max   int64
	md5, sha hash.Hash
	track    *progressTracker
}

func (s *sink) Write(p []byte) (int, error) {
	if s.n+int64(len(p)) > s.max {
		return 0, errTooBig
	}
	n, err := s.f.Write(p)
	s.n += int64(n)
	s.md5.Write(p[:n])
	s.sha.Write(p[:n])
	s.track.add(int64(n))
	return n, err
}

func normHex(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
}

// Download baja la URL a DestDir.
func Download(ctx context.Context, r Request) (Result, error) {
	var res Result
	max, err := r.limits()
	if err != nil {
		return res, err
	}
	if r.URL == nil {
		return res, i18n.New("xfer.err.no_url", nil)
	}
	if _, err := Port(r.URL); err != nil {
		return res, err
	}
	root, dir, err := fileserve.OpenDir(r.DestDir, r.DenyDirs...) // abierta una vez: un enlace puesto después no la desvía
	if err != nil {
		return res, err
	}
	defer root.Close()
	raw := r.Name
	if raw == "" {
		raw = path.Base(r.URL.Path)
	}
	name, err := fileserve.SafeName(raw)
	if err != nil {
		return res, fmt.Errorf("transfer: nombre local: %w", err)
	}
	to := r.Timeout
	if to <= 0 {
		to = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	dst := filepath.Join(dir, name)
	f, err := sys.OpenNewIn(root, name)
	if errors.Is(err, os.ErrExist) {
		return res, i18n.New("xfer.err.exists", i18n.A("path", dst))
	}
	if err != nil {
		return res, fmt.Errorf("transfer: %w", err)
	}
	r.track = newTracker(r.OnProgress, nil)
	sk := &sink{f: f, max: max, md5: md5.New(), sha: sha256.New(), track: r.track}
	start := time.Now()
	err = r.fetch(ctx, sk)
	if err == nil {
		r.track.finish()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		root.Remove(name) // nada a medias
		if ctx.Err() != nil && !errors.Is(err, errTooBig) {
			err = fmt.Errorf("%w (%v)", ctx.Err(), err)
		}
		return res, err
	}
	res = Result{Path: dst, Bytes: sk.n, MD5: hex.EncodeToString(sk.md5.Sum(nil)), SHA256: hex.EncodeToString(sk.sha.Sum(nil)), Duration: time.Since(start)}
	if r.WantSHA256 != "" || r.WantMD5 != "" {
		res.Verified = "ok"
		if (r.WantSHA256 != "" && normHex(r.WantSHA256) != res.SHA256) || (r.WantMD5 != "" && normHex(r.WantMD5) != res.MD5) {
			res.Verified = "distinto"
			root.Remove(name) // una imagen que no coincide no se deja lista para instalar
			return res, i18n.New("xfer.err.digest", i18n.A("sha256", res.SHA256, "md5", res.MD5))
		}
	}
	return res, nil
}

func (r *Request) fetch(ctx context.Context, w io.Writer) error {
	switch r.URL.Scheme {
	case "tftp":
		return r.tftpGet(ctx, w)
	case "ftp":
		return r.ftpGet(ctx, w)
	case "scp":
		return r.scpGet(ctx, w)
	case "sftp":
		return r.sftpGet(ctx, w)
	case "http", "https":
		return r.httpGet(ctx, w)
	}
	return i18n.New("xfer.err.scheme", i18n.A("scheme", r.URL.Scheme))
}

// Upload envía FromDir/Name a la URL.
func Upload(ctx context.Context, r Request) (Result, error) {
	var res Result
	max, err := r.limits()
	if err != nil {
		return res, err
	}
	if r.URL == nil {
		return res, i18n.New("xfer.err.no_url", nil)
	}
	if r.URL.Scheme == "http" || r.URL.Scheme == "https" {
		return res, i18n.New("xfer.err.http_get_only", nil)
	}
	if _, err := Port(r.URL); err != nil {
		return res, err
	}
	f, fi, err := fileserve.OpenFrom(r.FromDir, r.Name, r.DenyDirs...)
	if err != nil {
		return res, err
	}
	defer f.Close()
	if fi.Size() > max {
		return res, errTooBig
	}
	to := r.Timeout
	if to <= 0 {
		to = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	m, s := md5.New(), sha256.New()
	r.track = newTracker(r.OnProgress, nil)
	r.track.setTotal(fi.Size())
	rd := progressReader{io.TeeReader(f, io.MultiWriter(m, s)), r.track}
	start := time.Now()
	switch r.URL.Scheme {
	case "tftp":
		err = r.tftpPut(ctx, rd, fi.Size())
	case "ftp":
		err = r.ftpPut(ctx, rd)
	case "scp":
		err = r.scpPut(ctx, rd, fi.Size())
	case "sftp":
		err = r.sftpPut(ctx, rd)
	}
	if err != nil {
		return res, err
	}
	r.track.finish()
	return Result{Path: f.Name(), Bytes: fi.Size(), MD5: hex.EncodeToString(m.Sum(nil)), SHA256: hex.EncodeToString(s.Sum(nil)), Duration: time.Since(start)}, nil
}

// closeOnDone cierra c si ctx termina antes: así una lectura bloqueada se interrumpe.
func closeOnDone(ctx context.Context, c io.Closer) (stop func() bool) {
	return context.AfterFunc(ctx, func() { c.Close() })
}

func deadline(ctx context.Context, c net.Conn) {
	if d, ok := ctx.Deadline(); ok {
		c.SetDeadline(d)
	}
}
