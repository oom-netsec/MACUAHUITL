// Package fileserve son los servidores temporales de archivos para pasar imágenes IOS y
// configuraciones a un equipo, o recibir de él un running-config o un crashinfo: TFTP
// (RFC 1350, blksize RFC 2348, tsize y timeout RFC 2349), FTP pasivo mínimo, SCP y SFTP
// (servidor SSH propio) y HTTP (GET/HEAD con Range, solo lectura).
//
// Lectura: solo los archivos elegidos uno por uno, por su nombre base; no hay rutas ni
// listados. Escritura (apagada por defecto): únicamente en la carpeta de recepción, con
// nombre saneado, archivo nuevo (O_EXCL, 0600), topes de tamaño y lista de IP de origen.
// Lectura y escritura se habilitan por separado.
package fileserve

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/sys"
)

// Límites ante clientes maliciosos o en bucle.
const (
	maxTransfers = 16
	maxBlksize   = 65464
	retries      = 5
	firstTries   = 2  // envíos al par aún no verificado (antes del primer ACK)
	maxTimeout   = 30 // segundos; tope de la opción timeout
	perClient    = 2  // transferencias TFTP simultáneas por IP de origen
)

type Transfer struct {
	Proto    string
	Client   string
	File     string
	Bytes    int64
	Duration time.Duration
	Result   string // ok o error
	Dir      string `json:",omitempty"` // lectura o escritura
	Path     string `json:",omitempty"` // ruta del archivo recibido o servido
	SHA256   string `json:",omitempty"` // del archivo recibido
	Error    string `json:",omitempty"`
	Rejected bool   `json:",omitempty"` // rechazada antes de empezar (no publicado, método, saturación)
}

// Ready es lo que el usuario necesita saber al abrir el servidor.
type Ready struct {
	Addr         string
	User, Pass   string   // FTP, SCP y SFTP: de un solo servidor, generados al abrir
	Fingerprints []string // SCP y SFTP: huellas SHA256 de las llaves de host efímeras
}

type Config struct {
	Addr     string   // IP:puerto; el host es obligatorio
	Proto    string   // tftp, ftp, scp, sftp o http
	AllowAny bool     // permite 0.0.0.0 / ::
	Files    []string // rutas absolutas de los archivos publicados (lectura)
	FromDir  string   // carpeta publicada (lectura): sus archivos regulares de primer nivel; convive con Files
	// Lectura apagada = ni Files ni FromDir.
	// Escritura: apagada salvo Write. RecvDir es la única carpeta donde se escribe.
	Write    bool
	RecvDir  string
	MaxFile  int64 // tope por archivo recibido; 0 = DefaultMaxFile
	MaxTotal int64 // tope de todo lo recibido; 0 = DefaultMaxTotal
	// Allow: IP de origen permitidas; vacío = cualquiera que llegue a la IP de escucha.
	Allow []netip.Addr
	// DenyDirs: carpetas sensibles de más (p. ej. la de datos de la app) además de las de siempre.
	DenyDirs []string
	// User y Pass (FTP, SCP, SFTP): si van vacíos se generan.
	User, Pass string
	// Legacy (SCP, SFTP): ofrece también los algoritmos SSH antiguos que aún usa IOS 15.x.
	Legacy bool
	// PassivePorts (FTP): rango de puertos de datos; cero = de Addr+1 a Addr+32.
	PassivePorts [2]uint16
	OnListening  func(addr string)
	OnReady      func(Ready)
	OnTransfer   func(Transfer)
}

// udpAllowNote es el aviso que acompaña a --allow en TFTP.
const udpAllowNote = "en UDP la lista de IP no autentica: la IP de origen se puede falsificar; úsala como filtro, no como seguridad, y solo en una red de confianza"

// Topes por omisión de lo que se recibe.
const (
	DefaultMaxFile  = 512 << 20
	DefaultMaxTotal = 2 << 30
	maxRecvFiles    = 200
)

// ready anuncia que el servidor ya escucha.
func (c Config) ready(r Ready) { c.OnListening(r.Addr); c.OnReady(r) }

func (c Config) permits(ip netip.Addr) bool {
	if len(c.Allow) == 0 {
		return true
	}
	ip = ip.Unmap()
	for _, a := range c.Allow {
		if a.Unmap() == ip {
			return true
		}
	}
	return false
}

func (c Config) permitsAddr(a net.Addr) bool {
	ap, err := netip.ParseAddrPort(a.String())
	return err == nil && c.permits(ap.Addr())
}

// TFTPRedirectHint es la regla nftables que el usuario puede aplicar él mismo para
// que los equipos usen el puerto 69 estándar sin que la app tenga privilegios.
func TFTPRedirectHint(ip string, port int) string { return RedirectHint("tftp", ip, port) }

// standard es el puerto privilegiado de cada protocolo y su transporte para nftables.
var standard = map[string]struct {
	port  int
	trans string
}{"tftp": {69, "udp"}, "ftp": {21, "tcp"}, "scp": {22, "tcp"}, "sftp": {22, "tcp"}}

// redirTarget separa lo que cambia según la IP de escucha: la familia de nftables y la IP
// (si es 0.0.0.0, :: o no es una IP, se pide la de la máquina: la regla no queda ancha).
func redirTarget(ip string) (family, addr string) {
	a, err := netip.ParseAddr(strings.Trim(ip, "[]"))
	if err != nil || a.IsUnspecified() {
		return "ip", "IP-DE-ESTA-MÁQUINA"
	}
	if a = a.Unmap(); a.Is6() {
		return "ip6", a.String()
	}
	return "ip", a.String()
}

// nftTable es la tabla propia de un servidor: así quitar la regla de uno no toca la de otro.
func nftTable(proto string, port int) string { return fmt.Sprintf("macuahuitl_%s_%d", proto, port) }

// RedirectHint es la regla nftables que el usuario puede aplicar él mismo para que los
// equipos usen el puerto estándar (69, 21, 22) sin que la app tenga privilegios (ADR 0004).
// Solo redirige lo dirigido a la IP de escucha, en una tabla propia de ese servidor, y trae
// cómo quitarla. La app nunca la ejecuta. En FTP solo se redirige el puerto de control.
func RedirectHint(proto, ip string, port int) string {
	s, ok := standard[proto]
	if !ok {
		return ""
	}
	fam, addr := redirTarget(ip)
	t := nftTable(proto, port)
	return fmt.Sprintf("sudo nft add table %[1]s %[2]s; "+
		"sudo nft add chain %[1]s %[2]s pre '{ type nat hook prerouting priority dstnat; }'; "+
		"sudo nft add rule %[1]s %[2]s pre %[1]s daddr %[3]s %[4]s dport %[5]d redirect to :%[6]d   "+
		"(quitar al terminar: %[7]s)", fam, t, addr, s.trans, s.port, port, RedirectCleanup(proto, ip, port))
}

// RedirectCleanup es el comando que quita la regla de RedirectHint ("" si el protocolo no
// tiene puerto privilegiado). Se muestra al cerrar el servidor.
func RedirectCleanup(proto, ip string, port int) string {
	if _, ok := standard[proto]; !ok {
		return ""
	}
	fam, _ := redirTarget(ip)
	return fmt.Sprintf("sudo nft delete table %s %s", fam, nftTable(proto, port))
}

// RedirectCleanupAddr es RedirectCleanup para una dirección "IP:puerto" (la de escucha real); "" si no se puede leer.
func RedirectCleanupAddr(proto, listening string) string {
	host, port, err := net.SplitHostPort(listening)
	p, perr := strconv.Atoi(port)
	if err != nil || perr != nil {
		return ""
	}
	return RedirectCleanup(proto, host, p)
}

// SetcapHint es la alternativa a la redirección para quien prefiera que un binario suyo
// (otro servidor, no esta app, que siempre escucha en puerto alto por el ADR 0004) abra
// puertos bajos. Es más amplia que la redirección: se explica, nunca se ejecuta.
func SetcapHint(binary string) string {
	return fmt.Sprintf("sudo setcap cap_net_bind_service=+ep %s   "+
		"(ADVERTENCIA: ese binario podrá abrir cualquier puerto menor a 1024 mientras conserve el permiso; "+
		"quitar: sudo setcap -r %s)", binary, binary)
}

// Hint explica cómo copiar desde el equipo. IOS no deja elegir el puerto TFTP:
// para TFTP la redirección del 69 es necesaria. Sintaxis sin validar en laboratorio.
func Hint(proto, listen string, files []string) string {
	h, p, _ := net.SplitHostPort(listen)
	if ip, err := netip.ParseAddr(h); err == nil && ip.IsUnspecified() {
		h = "IP-DE-ESTA-MÁQUINA"
	}
	var b strings.Builder
	b.WriteString("En el equipo:\n")
	for _, f := range files {
		name := filepath.Base(f)
		if proto == "tftp" {
			fmt.Fprintf(&b, "  copy tftp://%s/%s flash:\n", strings.TrimSuffix(net.JoinHostPort(h, "0"), ":0"), name) // [IPv6] entre corchetes
		} else {
			fmt.Fprintf(&b, "  copy http://%s/%s flash:\n", net.JoinHostPort(h, p), name)
		}
	}
	if proto == "tftp" {
		port, _ := strconv.Atoi(p)
		b.WriteString("IOS siempre usa el puerto 69; redirígelo a este servidor (sin privilegios para la app):\n  " + TFTPRedirectHint(h, port) + "\n")
	}
	return b.String()
}

// ValidateAddr exige IP explícita, puerto no privilegiado y, salvo que se pida,
// nada de escuchar en todas las interfaces.
func ValidateAddr(addr string, allowAny bool) error {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("fileserve: dirección inválida %q: %w", addr, err)
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return fmt.Errorf("fileserve: puerto inválido %q", p)
	}
	if port != 0 && port < 1024 {
		return fmt.Errorf("fileserve: el puerto %d es privilegiado; usa uno alto (TFTP 6969, FTP 2121, SSH 2222, HTTP 8080) y redirige con nftables si hace falta", port)
	}
	ip, err := netip.ParseAddr(h)
	if err != nil {
		return fmt.Errorf("fileserve: el host debe ser una IP local, no %q", h)
	}
	if ip.IsUnspecified() && !allowAny {
		return errors.New("fileserve: escuchar en todas las interfaces requiere pedirlo explícitamente")
	}
	return nil
}

// Publish arma el mapa nombre base → ruta. Solo archivos regulares con ruta absoluta
// y nombres sin repetir.
func Publish(files []string) (map[string]string, error) {
	out, _, err := publish(files)
	return out, err
}

// publish además devuelve el estado de cada archivo al publicarse, para detectar que después sea otro.
// Un archivo con enlaces duros (Nlink > 1) no se publica: puede ser el mismo inodo que uno sensible.
func publish(files []string) (map[string]string, map[string]os.FileInfo, error) {
	if len(files) == 0 {
		return nil, nil, errors.New("fileserve: no hay archivos que publicar")
	}
	out, infos := map[string]string{}, map[string]os.FileInfo{}
	for _, f := range files {
		if !filepath.IsAbs(f) {
			return nil, nil, fmt.Errorf("fileserve: la ruta %q debe ser absoluta", f)
		}
		st, err := os.Stat(f)
		if err != nil {
			return nil, nil, fmt.Errorf("fileserve: %w", err)
		}
		if !st.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("fileserve: %s no es un archivo regular", f)
		}
		if sys.HardLinked(st) {
			return nil, nil, fmt.Errorf("fileserve: %s tiene enlaces duros (más de un nombre): publica una copia", f)
		}
		name := filepath.Base(f)
		if _, dup := out[name]; dup {
			return nil, nil, fmt.Errorf("fileserve: dos archivos se llaman %q", name)
		}
		out[name], infos[name] = f, st
	}
	return out, infos, nil
}

// prepare valida la configuración y arma lo que sirve; no abre ningún socket. Las carpetas de
// envío y de recepción se abren una sola vez (os.Root) y toda la E/S va por ese Root: quien llama
// cierra con closeAll.
func prepare(c Config) (src *source, rcv *receiver, err error) {
	if err := ValidateAddr(c.Addr, c.AllowAny); err != nil {
		return nil, nil, err
	}
	switch c.Proto {
	case "tftp", "ftp", "scp", "sftp", "http":
	default:
		return nil, nil, fmt.Errorf("fileserve: protocolo %q no soportado (tftp, ftp, scp, sftp o http)", c.Proto)
	}
	if c.Write && c.Proto == "http" {
		return nil, nil, errors.New("fileserve: HTTP es de solo lectura")
	}
	if lo, hi := c.PassivePorts[0], c.PassivePorts[1]; lo != 0 || hi != 0 {
		if lo < 1024 || hi < lo {
			return nil, nil, fmt.Errorf("fileserve: el rango de puertos pasivos %d-%d es inválido: debe empezar en 1024 o más (los bajos son privilegiados) y MIN ≤ MAX", lo, hi)
		}
	}
	src = &source{}
	defer func() {
		if err != nil {
			closeAll(src, rcv)
			src, rcv = nil, nil
		}
	}()
	if len(c.Files) > 0 {
		if src.files, src.infos, err = publish(c.Files); err != nil {
			return nil, nil, err
		}
	}
	if c.FromDir != "" {
		if src.root, src.dir, err = OpenDir(c.FromDir, c.DenyDirs...); err != nil {
			return nil, nil, err
		}
	}
	if c.Write {
		if len(c.Allow) == 0 && c.Proto == "tftp" {
			return nil, nil, errors.New("fileserve: recibir por TFTP exige --allow con la IP del equipo (sin lista cualquiera escribiría); " + udpAllowNote)
		}
		if len(c.Allow) == 0 && h(c.Addr).IsUnspecified() {
			return nil, nil, errors.New("fileserve: recibir en todas las interfaces exige indicar las IP de origen permitidas")
		}
		root, dir, err := OpenDir(c.RecvDir, c.DenyDirs...)
		if err != nil {
			return nil, nil, err
		}
		rcv = newReceiverIn(root, dir, c.MaxFile, c.MaxTotal)
		src.rcv = rcv
	}
	if !src.enabled() && rcv == nil {
		return nil, nil, errors.New("fileserve: no hay nada que servir: indica archivos o una carpeta para leer, o habilita la escritura")
	}
	return src, rcv, nil
}

// closeAll suelta las carpetas abiertas por prepare.
func closeAll(src *source, rcv *receiver) {
	if src != nil {
		src.close()
	}
	if rcv != nil {
		rcv.close()
	}
}

// Check valida la configuración sin abrir nada: los errores de uso salen antes de escuchar.
func Check(c Config) error {
	src, rcv, err := prepare(c)
	closeAll(src, rcv)
	return err
}

// Names son los archivos que el servidor entregaría ahora, por nombre.
func Names(c Config) []string {
	src, rcv, err := prepare(c)
	if err != nil {
		return nil
	}
	defer closeAll(src, rcv)
	var out []string
	for _, fi := range src.list() {
		out = append(out, fi.Name())
	}
	return out
}

// Folders devuelve las rutas reales (ya validadas) de las carpetas de envío y de recepción.
func Folders(c Config) (from, recv string) {
	src, rcv, err := prepare(c)
	if err != nil {
		return "", ""
	}
	defer closeAll(src, rcv)
	if rcv != nil {
		recv = rcv.dir
	}
	return src.dir, recv
}

// Serve atiende hasta que ctx se cancela.
func Serve(ctx context.Context, c Config) error {
	src, rcv, err := prepare(c)
	if err != nil {
		return err
	}
	defer closeAll(src, rcv) // los protocolos esperan a sus sesiones antes de volver
	if c.OnListening == nil {
		c.OnListening = func(string) {}
	}
	if c.OnReady == nil {
		c.OnReady = func(Ready) {}
	}
	if c.OnTransfer == nil {
		c.OnTransfer = func(Transfer) {}
	}
	if c.Proto == "ftp" || c.Proto == "scp" || c.Proto == "sftp" {
		if c.User == "" {
			c.User = "mac"
		}
		if c.Pass == "" {
			c.Pass = randPass()
		}
	}
	switch c.Proto {
	case "tftp":
		return serveTFTP(ctx, c, src, rcv)
	case "ftp":
		return serveFTP(ctx, c, src, rcv)
	case "scp", "sftp":
		return serveSSH(ctx, c, src, rcv)
	}
	return serveHTTP(ctx, c, src)
}

// h devuelve el host de una dirección ya validada.
func h(addr string) netip.Addr {
	host, _, _ := net.SplitHostPort(addr)
	ip, _ := netip.ParseAddr(host)
	return ip
}

// randPass da 16 caracteres sin ambiguos, de 80 bits de entropía.
func randPass() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}
