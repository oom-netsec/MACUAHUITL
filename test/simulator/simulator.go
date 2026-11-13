// Package simulator es un servidor SSH en 127.0.0.1 que imita la CLI de
// equipos Cisco a partir de transcripciones (test/transcripts). Solo para pruebas.
package simulator

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
)

// Config describe el equipo simulado.
type Config struct {
	Hostname, Username, Password, Enable string
	Transcripts                          string // carpeta con archivos "# command: ..."
	StartPrivileged                      bool
	IgnoreTerminalLength                 bool          // la paginación sigue activa aunque pidan terminal length 0
	HangAfterLogin                       bool          // nunca muestra prompt
	DropDuringCommand                    string        // al recibir este comando manda media salida y corta
	KeyboardInteractive                  bool          // además de password, ofrece keyboard-interactive y re-pregunta 3 veces como IOS
	Attempts                             *atomic.Int32 // si no es nil, cuenta cada contraseña recibida (password o KI)
	SlowCommand                          string        // este comando tarda SlowDelay en responder
	SlowDelay                            time.Duration
	StreamCommand                        string // este comando manda StreamLines líneas, una cada SlowDelay (una salida grande y lenta)
	StreamLines                          int
	SlowConfigLine                       string        // esta línea de configuración tarda SlowDelay en terminar (el prompt llega tarde)
	WriteMemoryOutput                    string        // si no está vacío, es la respuesta de write memory
	IdleTimeout                          time.Duration // cierra la sesión si pasa este tiempo sin recibir una línea (exec-timeout)
	// Modo configuración (fase 16a). Interfaces da el cuerpo inicial de cada interfaz y hace que
	// "show running-config interface X" refleje lo aplicado; ConfigErrors responde con ese texto
	// a la línea de configuración indicada (sin aplicarla); Commands suma salidas estáticas;
	// Recorder anota cada línea de configuración recibida.
	Interfaces       map[string][]string
	IgnoreUserChange bool              // `username ...` se acepta pero no cambia el acceso (un equipo que autentica con AAA remoto)
	Users            map[string]string // otros usuarios locales (nombre: contraseña); `username U secret S` los cambia y `show running-config | include ^username` los muestra
	VlanNames        map[int]string    // nombre inicial de las VLAN de Vlans; sin entrada, VLANnnnn
	Vlans            []int             // si no es nil, el equipo responde show vlan id N y crea (con aviso) la VLAN de acceso que no existía
	ErrDisabled      []string          // interfaces que show interfaces X status muestra err-disabled
	// Running (fase 16c): running-config completo y jerárquico; `show running-config` lo muestra tal como lo dejan las líneas de configuración.
	Running      string
	ConfigErrors map[string]string
	Commands     map[string]string
	Recorder     *Recorder
}

// Recorder anota lo que el equipo simulado recibió en modo configuración.
type Recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *Recorder) add(l string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.lines = append(r.lines, l)
	r.mu.Unlock()
}

// Lines devuelve una copia de las líneas recibidas, en orden. "!write memory" marca un guardado.
func (r *Recorder) Lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// device es el estado compartido por todas las sesiones de un equipo simulado.
type device struct {
	mu     sync.Mutex
	ifaces map[string][]string
	vlans  map[int]string
	users  map[string]*user
	hashes map[string]string // hash falso -> contraseña, para que `secret 9 HASH` restaure la contraseña de antes
	run    *runCfg           // running-config completo (Config.Running); nil = el modelo por interfaz de la fase 16a
}

// user es un usuario local: la contraseña en claro (solo del simulador) y el tipo con que se guardó.
type user struct{ pass, typ string }

func fakeHash(typ, pass string) string {
	sum := sha256.Sum256([]byte(typ + pass))
	return "$" + typ + "$" + hex.EncodeToString(sum[:])[:22]
}

func (d *device) setUser(name, pass, typ string) {
	d.users[name] = &user{pass: pass, typ: typ}
	d.hashes[fakeHash(typ, pass)] = pass
}

const pageLines = 24

// Start levanta el servidor y lo cierra con t.Cleanup.
func Start(t testing.TB, c Config) (addr string, hostKey ssh.PublicKey) {
	t.Helper()
	outputs, err := load(c.Transcripts)
	if err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	dev := &device{ifaces: map[string][]string{}, vlans: map[int]string{}, users: map[string]*user{}, hashes: map[string]string{}}
	if c.Running != "" {
		dev.run = newRunCfg(c.Running)
	}
	dev.setUser(c.Username, c.Password, "9")
	for u, p := range c.Users {
		dev.setUser(u, p, "9")
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if c.Attempts != nil {
				c.Attempts.Add(1)
			}
			if dev.checkLogin(m.User(), string(pw)) {
				return nil, nil
			}
			return nil, errors.New("acceso denegado")
		},
	}
	if c.KeyboardInteractive {
		cfg.KeyboardInteractiveCallback = func(m ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for i := 0; i < 3; i++ {
				ans, err := ch("", "", []string{"Password: "}, []bool{false})
				if err != nil {
					return nil, err
				}
				if c.Attempts != nil {
					c.Attempts.Add(1)
				}
				if len(ans) == 1 && dev.checkLogin(m.User(), ans[0]) {
					return nil, nil
				}
			}
			return nil, errors.New("acceso denegado")
		}
	}
	cfg.AddHostKey(signer)
	for _, v := range c.Vlans {
		dev.vlans[v] = vlanName(c.VlanNames, v)
	}
	for k, v := range c.Interfaces {
		dev.ifaces[k] = append([]string(nil), v...)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go serve(conn, cfg, c, outputs, dev)
		}
	}()
	return l.Addr().String(), signer.PublicKey()
}

func vlanName(names map[int]string, id int) string {
	if n := names[id]; n != "" {
		return n
	}
	return fmt.Sprintf("VLAN%04d", id)
}

func (d *device) checkLogin(name, pass string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	u := d.users[name]
	return u != nil && u.pass == pass
}

func load(dir string) (map[string]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		first, body, _ := strings.Cut(string(b), "\n")
		cmd, ok := strings.CutPrefix(first, "# command: ")
		if !ok {
			return nil, errors.New("simulator: " + f + " sin encabezado '# command:'")
		}
		out[strings.TrimSpace(cmd)] = body
	}
	return out, nil
}

func serve(conn net.Conn, cfg *ssh.ServerConfig, c Config, outputs map[string]string, dev *device) {
	defer conn.Close()
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "solo session")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		shell := make(chan struct{})
		go func() {
			for r := range creqs {
				ok := r.Type == "pty-req" || r.Type == "shell"
				if r.WantReply {
					r.Reply(ok, nil)
				}
				if r.Type == "shell" {
					close(shell)
				}
			}
		}()
		<-shell
		(&session{ch: ch, c: c, outputs: outputs, dev: dev, priv: c.StartPrivileged, paging: true}).run()
		ch.Close()
		return
	}
}

type session struct {
	ch      ssh.Channel
	c       Config
	outputs map[string]string
	dev     *device
	priv    bool
	paging  bool
	vlan    int      // VLAN del contexto config-vlan
	mode    string   // "" = exec; "config", "config-if", "config-if-range", "config-vlan"
	cur     []string // interfaces del contexto config-if
	rctx    []string // contexto del running-config completo (Config.Running)
}

func (s *session) write(str string) { io.WriteString(s.ch, strings.ReplaceAll(str, "\n", "\r\n")) }

func (s *session) prompt() {
	if s.mode != "" {
		host := s.c.Hostname
		if len(host) > 16 { // IOS acorta el nombre en el prompt de configuración
			host = host[:16]
		}
		s.write(host + "(" + s.mode + ")#")
	} else if s.priv {
		s.write(s.c.Hostname + "#")
	} else {
		s.write(s.c.Hostname + ">")
	}
}

// readLine lee hasta CR o LF; echo controla si se repite lo tecleado.
func (s *session) readLine(echo bool) (string, error) {
	var b strings.Builder
	buf := make([]byte, 1)
	for {
		if _, err := s.ch.Read(buf); err != nil {
			return "", err
		}
		switch buf[0] {
		case '\r', '\n':
			if b.Len() == 0 && buf[0] == '\n' {
				continue // LF tras CR
			}
			s.write("\n")
			return b.String(), nil
		default:
			b.WriteByte(buf[0])
			if echo {
				s.ch.Write(buf)
			}
		}
	}
}

func (s *session) run() {
	if s.c.HangAfterLogin {
		io.Copy(io.Discard, s.ch)
		return
	}
	for {
		s.prompt()
		var idle *time.Timer
		if s.c.IdleTimeout > 0 {
			idle = time.AfterFunc(s.c.IdleTimeout, func() { s.ch.Close() })
		}
		line, err := s.readLine(true)
		if idle != nil {
			idle.Stop()
		}
		if err != nil {
			return
		}
		cmd := strings.Join(strings.Fields(line), " ")
		if s.mode != "" {
			s.configLine(cmd)
			continue
		}
		switch {
		case cmd == "":
		case cmd == "exit" || cmd == "quit":
			return
		case cmd == "enable":
			// Como IOS: tres intentos y luego "% Bad secrets".
			for i := 0; i < 3 && !s.priv; i++ {
				s.write("Password: ")
				pw, err := s.readLine(false)
				if err != nil {
					return
				}
				s.priv = pw == s.c.Enable
			}
			if !s.priv {
				s.write("% Bad secrets\n\n")
			}
		case cmd == "configure terminal" || cmd == "conf t":
			s.write("Enter configuration commands, one per line.  End with CNTL/Z.\n")
			s.mode = "config"
		case cmd == "write memory":
			s.c.Recorder.add("!write memory")
			if s.c.WriteMemoryOutput != "" {
				s.write(s.c.WriteMemoryOutput)
				continue
			}
			s.write("Building configuration...\n[OK]\n")
		case cmd == "show running-config" && s.dev.run != nil:
			if !s.page(s.dev.run.render()) {
				return
			}
		case strings.HasPrefix(cmd, "show running-config interface ") && s.dev.has(strings.TrimPrefix(cmd, "show running-config interface ")):
			s.write(s.dev.show(strings.TrimPrefix(cmd, "show running-config interface ")))
		case s.showModeled(cmd):
		case s.c.Commands[cmd] != "":
			s.write(s.c.Commands[cmd])
		case cmd == "terminal length 0":
			s.paging = s.c.IgnoreTerminalLength
		case strings.HasPrefix(cmd, "terminal "):
		case cmd == s.c.SlowCommand && cmd != "":
			time.Sleep(s.c.SlowDelay)
			s.write("SALIDA LENTA DE " + cmd + "\n")
		case cmd == s.c.StreamCommand && cmd != "":
			for i := range s.c.StreamLines {
				time.Sleep(s.c.SlowDelay)
				s.write(fmt.Sprintf("linea %d de %s\n", i+1, cmd))
			}
		case cmd == s.c.DropDuringCommand:
			out := s.outputs[cmd]
			s.write(out[:len(out)/2])
			return
		default:
			out, ok := s.outputs[cmd]
			if !ok {
				s.write("                 ^\n% Invalid input detected at '^' marker.\n\n")
				continue
			}
			if !s.page(out) {
				return
			}
		}
	}
}

// page imprime out paginando cada 24 líneas si la paginación sigue activa.
func (s *session) page(out string) bool {
	lines := strings.SplitAfter(out, "\n")
	if !s.paging {
		s.write(out)
		return true
	}
	buf := make([]byte, 1)
	for i := 0; i < len(lines); i += pageLines {
		end := min(i+pageLines, len(lines))
		s.write(strings.Join(lines[i:end], ""))
		if end == len(lines) {
			break
		}
		s.write(" --More-- ")
		if _, err := s.ch.Read(buf); err != nil {
			return false
		}
		s.write("\r          \r")
		if buf[0] == 'q' {
			break
		}
	}
	return true
}

// TrustKey acepta solo la llave del simulador; evita que las pruebas fuera
// de transport importen la librería SSH (noegress).
func TrustKey(k ssh.PublicKey) ssh.HostKeyCallback { return ssh.FixedHostKey(k) }

// HangUp escucha en 127.0.0.1 y corta cada conexión antes del handshake SSH
// (una falla de conexión, no de autenticación). Cuenta las conexiones en accepts.
func HangUp(t testing.TB, accepts *atomic.Int32) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			c.Close()
		}
	}()
	return l.Addr().String()
}

// showModeled responde los show que dependen del estado del equipo (VLAN, estado y modo de los puertos).
func (s *session) showModeled(cmd string) bool {
	if s.c.Vlans != nil {
		const head = "VLAN Name                             Status    Ports\n---- -------------------------------- --------- -------------------------------\n"
		if id, ok := strings.CutPrefix(cmd, "show vlan id "); ok {
			n, _ := strconv.Atoi(id)
			s.dev.mu.Lock()
			name, has := s.dev.vlans[n]
			s.dev.mu.Unlock()
			if !has {
				s.write("VLAN id " + id + " not found in current VLAN database\n")
			} else {
				// Como IOS, también tipo y MTU, Remote SPAN y VLAN privadas (formato sin validar en laboratorio).
				s.write(head + fmt.Sprintf("%-4d %-32s active    \n", n, name) +
					"\nVLAN Type  SAID       MTU   Parent RingNo BridgeNo Stp  BrdgMode Trans1 Trans2\n---- ----- ---------- ----- ------ ------ -------- ---- -------- ------ ------\n" +
					fmt.Sprintf("%-4d enet  %-10d 1500  -      -      -        -    -        0      0\n", n, 100000+n) +
					"\nRemote SPAN VLAN\n----------------\nDisabled\n\nPrimary Secondary Type              Ports\n------- --------- ----------------- ------------------------------------------\n")
			}
			return true
		}
		if cmd == "show vlan brief" {
			s.dev.mu.Lock()
			ids := make([]int, 0, len(s.dev.vlans))
			for id := range s.dev.vlans {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			var b strings.Builder
			b.WriteString(head)
			for _, id := range ids {
				fmt.Fprintf(&b, "%-4d %-32s active    \n", id, s.dev.vlans[id])
			}
			s.dev.mu.Unlock()
			s.write(b.String())
			return true
		}
	}
	if cmd == "show running-config | include ^username" {
		s.dev.mu.Lock()
		names := make([]string, 0, len(s.dev.users))
		for n := range s.dev.users {
			names = append(names, n)
		}
		slices.Sort(names)
		var b strings.Builder
		for _, n := range names {
			u := s.dev.users[n]
			fmt.Fprintf(&b, "username %s privilege 15 secret %s %s\n", n, u.typ, fakeHash(u.typ, u.pass))
		}
		s.dev.mu.Unlock()
		s.write(b.String())
		return true
	}
	if pat, ok := strings.CutPrefix(cmd, "show running-config | section "); ok && s.dev.run != nil {
		re, err := regexp.Compile(pat)
		if err != nil {
			return false
		}
		s.write(s.dev.run.section(re))
		return true
	}
	if pat, ok := strings.CutPrefix(cmd, "show running-config | include "); ok && s.dev.run != nil {
		re, err := regexp.Compile(pat)
		if err != nil {
			return false
		}
		var b strings.Builder
		for _, l := range strings.Split(s.dev.run.render(), "\n") {
			if t := strings.TrimSpace(l); t != "" && t != "!" && t != "end" && !strings.HasPrefix(t, "Building") && !strings.HasPrefix(t, "Current") && re.MatchString(l) {
				b.WriteString(l + "\n")
			}
		}
		s.write(b.String())
		return true
	}
	rest, ok := strings.CutPrefix(cmd, "show interfaces ")
	if !ok {
		return false
	}
	name, what, found := strings.Cut(rest, " ")
	if !found || !s.dev.has(name) || (what != "status" && what != "switchport" && what != "switchport | include Mode:") {
		return false
	}
	s.dev.mu.Lock()
	lines := append([]string(nil), s.dev.ifaces[name]...)
	s.dev.mu.Unlock()
	has := func(l string) bool { return slices.Contains(lines, l) }
	if strings.HasPrefix(what, "switchport") {
		mode := "dynamic auto"
		switch {
		case has("no switchport"):
			s.write("Name: " + name + "\nSwitchport: Disabled\n")
			return true
		case has("switchport mode access"):
			mode = "static access"
		case has("switchport mode trunk"):
			mode = "trunk"
		case has("switchport mode dynamic desirable"):
			mode = "dynamic desirable"
		}
		oper := mode
		if strings.HasPrefix(mode, "dynamic") {
			oper = "down" // sin vecino que negocie, un puerto dynamic no opera como trunk
		}
		modes := "Administrative Mode: " + mode + "\nOperational Mode: " + oper + "\n"
		if what == "switchport" {
			modes = "Name: " + name + "\nSwitchport: Enabled\n" + modes
		}
		s.write(modes)
		return true
	}
	vlan, desc, status := "1", "", "connected"
	for _, l := range lines {
		if v, ok := strings.CutPrefix(l, "switchport access vlan "); ok {
			vlan = v
		}
		if v, ok := strings.CutPrefix(l, "description "); ok {
			desc = v
		}
	}
	n, _ := strconv.Atoi(vlan)
	s.dev.mu.Lock()
	_, known := s.dev.vlans[n]
	missing := s.c.Vlans != nil && !known && n != 1
	s.dev.mu.Unlock()
	switch {
	case slices.Contains(s.c.ErrDisabled, name):
		status = "err-disabled"
	case has("shutdown"):
		status = "disabled"
	case missing:
		status = "inactive"
	}
	s.write("Port      Name               Status       Vlan       Duplex  Speed Type\n" +
		fmt.Sprintf("%-9s %-18s %-12s %-10s a-full  a-1000 10/100/1000BaseTX\n", shortName(name), desc, status, vlan))
	return true
}

func shortName(n string) string {
	if r, ok := strings.CutPrefix(n, "GigabitEthernet"); ok {
		return "Gi" + r
	}
	return n
}

func (d *device) hasVlan(n int) bool { _, ok := d.vlans[n]; return ok }

func (d *device) has(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.ifaces[name]
	return ok
}

func (d *device) show(name string) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	var b strings.Builder
	b.WriteString("Building configuration...\n\nCurrent configuration : 100 bytes\n!\ninterface " + name + "\n")
	for _, l := range d.ifaces[name] {
		b.WriteString(" " + l + "\n")
	}
	b.WriteString("end\n\n")
	return b.String()
}

// lineKeys son las familias de líneas de interfaz que se sustituyen entre sí; las más largas van antes de su prefijo. storm-control action no está:
// shutdown y trap son banderas independientes (cada línea es su propia clave) y pueden estar las dos.
var lineKeys = []string{"switchport access vlan", "switchport voice vlan", "switchport mode", "description", "ip address", "speed", "duplex",
	"storm-control broadcast level", "storm-control multicast level", "storm-control unicast level",
	"spanning-tree portfast", "spanning-tree bpduguard", "switchport port-security maximum", "switchport port-security violation",
	"switchport port-security aging time", "switchport port-security"}

// ifaceDefaults son valores de fábrica que IOS no muestra en el running-config: aplicarlos quita la línea (modelo de la documentación de Cisco,
// sin validar en laboratorio).
var ifaceDefaults = []string{"speed auto", "duplex auto", "storm-control broadcast level 100.00", "storm-control multicast level 100.00", "storm-control unicast level 100.00",
	"switchport port-security maximum 1", "switchport port-security violation shutdown", "switchport port-security aging time 0", "switchport mode dynamic auto"}

// lineKey agrupa las líneas que se sustituyen entre sí (una VLAN de acceso reemplaza a la anterior).
func lineKey(l string) string {
	for _, p := range lineKeys {
		if l == p || strings.HasPrefix(l, p+" ") {
			return p
		}
	}
	return l
}

// apply aplica una línea a las interfaces del contexto. Devuelve el aviso de IOS cuando la línea crea una VLAN.
func (d *device) apply(names []string, line string, track bool) (warn string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if v, ok := strings.CutPrefix(line, "switchport access vlan "); ok && track {
		if n, err := strconv.Atoi(v); err == nil && !d.hasVlan(n) && n != 1 {
			d.vlans[n] = fmt.Sprintf("VLAN%04d", n)
			warn = "% Access VLAN does not exist. Creating vlan " + v + "\n"
		}
	}
	for _, n := range names {
		cur := d.ifaces[n]
		if strings.HasPrefix(line, "switchport trunk allowed vlan add ") || strings.HasPrefix(line, "switchport trunk allowed vlan remove ") {
			d.ifaces[n] = trunkAllowed(cur, line)
			continue
		}
		rest, neg := strings.CutPrefix(line, "no ")
		if slices.Contains(ifaceDefaults, line) {
			rest, neg = line, true
		}
		if neg {
			k := lineKey(rest)
			out := cur[:0:0]
			for _, l := range cur {
				if lineKey(l) != k {
					out = append(out, l)
				}
			}
			d.ifaces[n] = out
			continue
		}
		k := lineKey(line)
		replaced := false
		for i, l := range cur {
			if lineKey(l) == k {
				cur[i], replaced = line, true
			}
		}
		if !replaced {
			cur = append(cur, line)
		}
		d.ifaces[n] = cur
	}
	return warn
}

// configLine atiende una línea en modo configuración.
func (s *session) configLine(cmd string) {
	if cmd == "" {
		return
	}
	s.c.Recorder.add(cmd)
	if cmd == s.c.SlowConfigLine && cmd != "" {
		time.Sleep(s.c.SlowDelay)
	}
	if msg, ok := s.c.ConfigErrors[cmd]; ok {
		s.write("                 ^\n" + msg + "\n\n")
		return
	}
	switch {
	case cmd == "end":
		s.mode, s.cur, s.rctx = "", nil, nil
	case s.dev.run != nil && cmd != "exit":
		s.rctx = s.dev.run.apply(s.rctx, cmd)
		s.mode = promptMode(s.rctx)
	case cmd == "exit":
		if s.mode == "config" {
			s.mode = ""
		} else {
			s.mode, s.cur = "config", nil
		}
	case strings.HasPrefix(cmd, "interface range "):
		s.cur = nil
		for _, n := range strings.Split(strings.TrimPrefix(cmd, "interface range "), ",") {
			s.cur = append(s.cur, strings.TrimSpace(n))
		}
		s.enter(s.cur, "config-if-range")
	case strings.HasPrefix(cmd, "interface "):
		s.enter([]string{strings.TrimPrefix(cmd, "interface ")}, "config-if")
	case s.global(cmd):
	case s.mode == "config":
		// Global: se acepta sin efecto.
	case s.mode == "config-vlan":
		if n, ok := strings.CutPrefix(cmd, "name "); ok {
			s.dev.mu.Lock()
			s.dev.vlans[s.vlan] = n
			s.dev.mu.Unlock()
		}
	case s.dev.ifaces != nil:
		s.write(s.dev.apply(s.cur, cmd, s.c.Vlans != nil))
	}
}

// global atiende los comandos de configuración global que modela el simulador: vlan, usuarios locales y
// borrar una interfaz lógica.
func (s *session) global(cmd string) bool {
	f := strings.Fields(cmd)
	switch {
	case len(f) == 2 && f[0] == "vlan":
		n, err := strconv.Atoi(f[1])
		if err != nil {
			return false
		}
		s.dev.mu.Lock()
		if !s.dev.hasVlan(n) {
			s.dev.vlans[n] = vlanName(nil, n)
		}
		s.dev.mu.Unlock()
		s.vlan, s.mode, s.cur = n, "config-vlan", nil
	case len(f) == 3 && f[0] == "no" && f[1] == "vlan":
		n, _ := strconv.Atoi(f[2])
		s.dev.mu.Lock()
		delete(s.dev.vlans, n)
		s.dev.mu.Unlock()
	case len(f) == 3 && f[0] == "no" && f[1] == "interface":
		s.dev.mu.Lock()
		delete(s.dev.ifaces, f[2])
		s.dev.mu.Unlock()
	case f[0] == "username" && len(f) >= 4:
		if !s.c.IgnoreUserChange {
			s.dev.setUserLine(f[1:])
		}
	default:
		return false
	}
	return true
}

// setUserLine aplica `username U [privilege N] [algorithm-type T] secret [N] S` o `... secret 9 HASH`.
func (d *device) setUserLine(f []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	typ, name := "5", f[0]
	for i := 1; i < len(f); i++ {
		switch f[i] {
		case "privilege":
			i++
		case "algorithm-type":
			typ = map[string]string{"scrypt": "9", "sha256": "8", "md5": "5"}[f[i+1]]
			i++
		case "secret", "password":
			rest := f[i+1:]
			if len(rest) == 2 && len(rest[0]) == 1 { // tipo y hash ya calculado
				pass, known := d.hashes[rest[1]]
				if !known {
					pass = rest[1]
				}
				d.users[name] = &user{pass: pass, typ: rest[0]}
				return
			}
			if len(rest) == 1 {
				d.users[name] = &user{pass: rest[0], typ: typ}
				d.hashes[fakeHash(typ, rest[0])] = rest[0]
			}
			return
		}
	}
}

func (s *session) enter(names []string, mode string) {
	s.dev.mu.Lock()
	for _, n := range names {
		if _, ok := s.dev.ifaces[n]; !ok {
			s.dev.ifaces[n] = nil
		}
	}
	s.dev.mu.Unlock()
	s.cur, s.mode = names, mode
}

// trunkAllowed aplica `switchport trunk allowed vlan add|remove L` y deja una sola línea con la lista (ninguna si quedan todas).
func trunkAllowed(cur []string, line string) []string {
	const p = "switchport trunk allowed vlan"
	var allowed, rest []string
	for _, l := range cur {
		if strings.HasPrefix(l, p) {
			allowed = append(allowed, l)
		} else {
			rest = append(rest, l)
		}
	}
	set, all := iosxe.TrunkAllowedSet(append(allowed, line))
	if all {
		return rest
	}
	ids := make([]int, 0, len(set))
	for i := range set {
		ids = append(ids, i)
	}
	slices.Sort(ids)
	strs := make([]string, len(ids))
	for i, id := range ids {
		strs[i] = strconv.Itoa(id)
	}
	if len(strs) == 0 {
		return append(rest, p+" none")
	}
	return append(rest, p+" "+strings.Join(strs, ","))
}
