package tacacstest

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"time"
)

// FakeConfig arma un servidor TACACS+ mínimo en loopback para las pruebas de este
// paquete, del núcleo y de mctl. No es un servidor de producción.
type FakeConfig struct {
	Secret string
	Users  map[string]string
	Permit map[string][]string // comando (cmd=) permitido → AV pairs devueltos
}

type Fake struct {
	cfg FakeConfig
	l   net.Listener
	wg  sync.WaitGroup
}

func StartFake(cfg FakeConfig) (*Fake, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Fake{cfg: cfg, l: l}
	f.wg.Add(1)
	go func() {
		defer f.wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			f.wg.Add(1)
			go func() { defer f.wg.Done(); f.serve(c) }()
		}
	}()
	return f, nil
}

func (f *Fake) Addr() string { return f.l.Addr().String() }
func (f *Fake) Close()       { f.l.Close(); f.wg.Wait() }

func (f *Fake) serve(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	key := []byte(f.cfg.Secret)
	var user string
	for {
		h, body, err := readPacket(c, key)
		if err != nil {
			return
		}
		reply := func(b []byte) { h.Seq++; writePacket(c, h, key, b) }
		authen := func(st byte, msg string) {
			b := binary.BigEndian.AppendUint16([]byte{st, 0}, uint16(len(msg)))
			reply(append(binary.BigEndian.AppendUint16(b, 0), msg...))
		}
		switch {
		case h.Type == typeAuthen && h.Seq == 1:
			if len(body) < 8 {
				return // cuerpo ilegible (secreto distinto): se cierra, como ISE
			}
			fs, err := fields(body[8:], int(body[4]), int(body[5]), int(body[6]), int(body[7]))
			if err != nil {
				return
			}
			user = string(fs[0])
			if body[2] == authenPAP {
				f.verdict(authen, user, string(fs[3]))
				return
			}
			authen(5, "Password: ")
		case h.Type == typeAuthen:
			if len(body) < 5 {
				return
			}
			fs, err := fields(body[5:], int(binary.BigEndian.Uint16(body[0:2])), int(binary.BigEndian.Uint16(body[2:4])))
			if err != nil {
				return
			}
			f.verdict(authen, user, string(fs[0]))
			return
		case h.Type == typeAuthor:
			args := parseArgs(body, 4)
			st, av := byte(0x10), []string(nil)
			for _, a := range args {
				if cmd, ok := strings.CutPrefix(a, "cmd="); ok {
					if p, ok := f.cfg.Permit[cmd]; ok {
						st, av = 1, p
					}
				}
			}
			b := []byte{st, byte(len(av)), 0, 0, 0, 0}
			for _, a := range av {
				b = append(b, byte(len(a)))
			}
			for _, a := range av {
				b = append(b, a...)
			}
			reply(b)
			return
		case h.Type == typeAcct:
			if parseArgs(body, 5) == nil {
				return
			}
			reply([]byte{0, 0, 0, 0, 1})
			return
		default:
			return
		}
	}
}

func (f *Fake) verdict(authen func(byte, string), user, pw string) {
	if want, ok := f.cfg.Users[user]; ok && want == pw {
		authen(1, "")
		return
	}
	authen(2, "Authentication failed")
}

// parseArgs lee user/port/rem/args de un cuerpo author (fixed=4) o acct (fixed=5).
func parseArgs(b []byte, fixed int) []string {
	if len(b) < fixed+4 {
		return nil
	}
	n := int(b[fixed+3])
	if len(b) < fixed+4+n {
		return nil
	}
	lens := []int{int(b[fixed]), int(b[fixed+1]), int(b[fixed+2])}
	for _, l := range b[fixed+4 : fixed+4+n] {
		lens = append(lens, int(l))
	}
	fs, err := fields(b[fixed+4+n:], lens...)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, a := range fs[3:] {
		out = append(out, string(a))
	}
	return out
}
