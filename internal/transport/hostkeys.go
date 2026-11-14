package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

type HostKeyStatus int

const (
	HostKeyKnown HostKeyStatus = iota
	HostKeyUnknown
	HostKeyChanged
)

func (s HostKeyStatus) String() string {
	return [...]string{"conocida", "desconocida", "cambiada"}[s]
}

// ErrKnownHosts: el archivo no se pudo leer o está dañado. Nunca se trata como "llave desconocida".
var ErrKnownHosts error = i18n.New("transport.err.known_hosts", nil)

// HostKeyError lleva la huella para que el ingeniero la confirme en el Login Test.
type HostKeyError struct {
	Host        string
	Status      HostKeyStatus
	Fingerprint string
}

func (e *HostKeyError) Error() string {
	return fmt.Sprintf("transport: llave de host %s de %s: %s", e.Status, e.Host, e.Fingerprint)
}

// Reason, Metadata y Localize hacen de HostKeyError un error con código del catálogo (i18n.Coded).
func (e *HostKeyError) Reason() string { return "transport.hostkey." + e.status() }

func (e *HostKeyError) Metadata() map[string]string {
	return map[string]string{"host": e.Host, "fingerprint": e.Fingerprint}
}

func (e *HostKeyError) Localize(loc string) string {
	return i18n.Msg(loc, "transport.hostkey."+e.status(), i18n.A("host", e.Host, "fingerprint", e.Fingerprint))
}

func (e *HostKeyError) status() string { return [...]string{"known", "unknown", "changed"}[e.Status] }

// HostKeyPolicy es la decisión del trabajo sobre llaves no conocidas.
type HostKeyPolicy struct {
	Accepted      map[string]bool // huellas aceptadas por el ingeniero en el Login Test
	AcceptChanged bool            // casilla del trabajo; por defecto false (spec §12.2)
}

// KnownHosts es el registro de llaves de host de la app. Formato propio, una línea por equipo:
// "<host:puerto en minúsculas> <llave en formato authorized_keys>". No es el formato de OpenSSH
// a propósito: su normalización rompe con IPv6 en el puerto 22.
type KnownHosts struct {
	path string
	mu   sync.Mutex
}

func Fingerprint(key ssh.PublicKey) string { return ssh.FingerprintSHA256(key) }

// OpenKnownHosts abre o crea (0600) el archivo.
func OpenKnownHosts(path string) (*KnownHosts, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("transport: %w", err)
	}
	return &KnownHosts{path: path}, nil
}

func hostKeyID(hostport string) (string, error) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", fmt.Errorf("transport: %q: %w", hostport, err)
	}
	return net.JoinHostPort(strings.ToLower(h), p), nil
}

func (k *KnownHosts) load() (map[string]ssh.PublicKey, error) {
	b, err := os.ReadFile(k.path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKnownHosts, err)
	}
	out := map[string]ssh.PublicKey{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		ln := strings.TrimSpace(sc.Text())
		if ln == "" {
			continue
		}
		id, rest, ok := strings.Cut(ln, " ")
		key, _, _, _, perr := ssh.ParseAuthorizedKey([]byte(rest))
		if !ok || perr != nil {
			return nil, i18n.Wrap("transport.err.known_hosts_ln", ErrKnownHosts, i18n.A("n", n))
		}
		out[id] = key
	}
	return out, nil
}

// check devuelve el estado y, si cambió, la huella anterior. Requiere k.mu.
func (k *KnownHosts) check(hostport string, key ssh.PublicKey) (HostKeyStatus, string, error) {
	id, err := hostKeyID(hostport)
	if err != nil {
		return 0, "", err
	}
	m, err := k.load()
	if err != nil {
		return 0, "", err
	}
	old, ok := m[id]
	switch {
	case !ok:
		return HostKeyUnknown, "", nil
	case bytes.Equal(old.Marshal(), key.Marshal()):
		return HostKeyKnown, "", nil
	}
	return HostKeyChanged, Fingerprint(old), nil
}

func (k *KnownHosts) Check(hostport string, key ssh.PublicKey) (HostKeyStatus, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	s, _, err := k.check(hostport, key)
	return s, err
}

// Add guarda la llave de hostport, reemplazando la anterior si existía.
func (k *KnownHosts) Add(hostport string, key ssh.PublicKey) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.add(hostport, key)
}

func (k *KnownHosts) add(hostport string, key ssh.PublicKey) error {
	id, err := hostKeyID(hostport)
	if err != nil {
		return err
	}
	m, err := k.load()
	if err != nil {
		return err
	}
	m[id] = key
	ids := make([]string, 0, len(m))
	for i := range m {
		ids = append(ids, i)
	}
	sort.Strings(ids)
	var b strings.Builder
	for _, i := range ids {
		b.WriteString(i + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(m[i]))) + "\n")
	}
	tmp := k.path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		return fmt.Errorf("transport: %w", err)
	}
	return os.Rename(tmp, k.path)
}

// Callback aplica la política del trabajo en el handshake SSH.
func (k *KnownHosts) Callback(p HostKeyPolicy, onEvent func(audit.Entry)) ssh.HostKeyCallback {
	if onEvent == nil {
		onEvent = func(audit.Entry) {}
	}
	return func(hostport string, _ net.Addr, key ssh.PublicKey) error {
		k.mu.Lock()
		defer k.mu.Unlock()
		status, old, err := k.check(hostport, key)
		if err != nil {
			return err
		}
		fp := Fingerprint(key)
		switch {
		case status == HostKeyKnown:
			return nil
		case status == HostKeyChanged && (p.Accepted[fp] || p.AcceptChanged):
			// Toda llave cambiada aceptada queda con la huella anterior y la nueva (spec §12.2).
			onEvent(audit.Entry{Action: "hostkey.accepted_changed", Target: hostport, Detail: old + " -> " + fp})
			return k.add(hostport, key)
		case p.Accepted[fp]:
			onEvent(audit.Entry{Action: "hostkey.accepted", Target: hostport, Detail: fp})
			return k.add(hostport, key)
		}
		return &HostKeyError{Host: hostport, Status: status, Fingerprint: fp}
	}
}
