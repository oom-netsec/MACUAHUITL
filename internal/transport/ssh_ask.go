package transport

import (
	"context"
	"net"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Prompt es una ronda de preguntas del equipo (keyboard-interactive) o la contraseña pedida como una sola pregunta.
type Prompt struct {
	Name, Instruction string
	Questions         []Question
	Attempt           int // 1 + fallos de autenticación hasta ahora
}

// Question es una pregunta del equipo; Echo=false es una respuesta secreta (no se muestra al teclearla).
type Question struct {
	Text string
	Echo bool
}

var (
	ErrTypedMixed    error = i18n.New("transport.err.typed_mixed", nil)
	ErrNoCredential  error = i18n.New("transport.err.no_credential", nil)
	ErrAuthAttempts  error = i18n.New("transport.err.auth_attempts", nil)
	ErrTypedNoMethod error = i18n.New("transport.err.typed_no_method", nil)
	ErrTypedPrompt   error = i18n.New("transport.err.typed_prompt", nil)
)

// Topes del texto del equipo y de las respuestas: un equipo hostil no inunda la terminal ni la memoria.
const (
	maxAskAttempts = 3
	maxPromptName  = 128
	maxPromptInstr = 1024
	maxPromptText  = 256
	maxPromptQs    = 16
	maxAnswer      = 1024
	methodKbdInter = "keyboard-interactive"
	methodPassword = "password"
	methodNone     = "none"
)

// limpia quita los caracteres de control C0/C1 (salvo \n si keepNL), el Unicode de formato (bidi, ancho cero) y los
// separadores de línea/párrafo. Más de max bytes en el original es ErrTypedPrompt.
func limpia(s string, max int, keepNL bool) (string, error) {
	if len(s) > max {
		return "", ErrTypedPrompt
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' && keepNL:
			return r
		case r == utf8.RuneError || unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp):
			return -1
		}
		return r
	}, s), nil
}

func saneaPrompt(name, ins string, qs []string, echos []bool, attempt int) (p Prompt, err error) {
	if len(qs) > maxPromptQs {
		return p, ErrTypedPrompt
	}
	p.Attempt = attempt
	if p.Name, err = limpia(name, maxPromptName, false); err != nil {
		return Prompt{}, err
	}
	if p.Instruction, err = limpia(ins, maxPromptInstr, true); err != nil {
		return Prompt{}, err
	}
	for i, q := range qs {
		t, err := limpia(q, maxPromptText, false)
		if err != nil {
			return Prompt{}, err
		}
		p.Questions = append(p.Questions, Question{Text: t, Echo: i < len(echos) && echos[i]})
	}
	return p, nil
}

type askRes struct {
	ans [][]byte
	err error
}

func wipe(ans [][]byte) {
	for _, b := range ans {
		clear(b)
	}
}

// askAuth es el AuthCallback del modo tecleado: elige el método, cuenta los fallos y relaya las preguntas a o.Ask.
// El texto del equipo se sanea antes de llegar a Ask. Sin deadline mientras se espera a Ask.
func askAuth(ctx context.Context, conn net.Conn, host, user string, o SSHOptions) ssh.ClientAuthCallback {
	var abort error // error de Ask (o saneo) que x/crypto cuenta como fallo; el siguiente callback lo convierte en aborto
	run := func(p Prompt) ([]string, error) {
		conn.SetDeadline(time.Time{})
		res, abandon := make(chan askRes), make(chan struct{})
		go func() { // si el ctx gana, la goroutine pone en ceros lo que Ask devuelva tarde
			a, err := o.Ask(p)
			select {
			case res <- askRes{a, err}:
			case <-abandon:
				wipe(a)
			}
		}()
		var r askRes
		select {
		case r = <-res:
		case <-ctx.Done():
			close(abandon)
			return nil, ctx.Err()
		}
		defer wipe(r.ans)
		conn.SetDeadline(time.Now().Add(o.HandshakeTimeout))
		if r.err != nil {
			return nil, r.err
		}
		if len(r.ans) != len(p.Questions) {
			return nil, ErrTypedPrompt
		}
		out := make([]string, len(r.ans)) // x/crypto exige string: límite declarado en THREAT_MODEL (límite 1)
		for i, b := range r.ans {
			if len(b) > maxAnswer {
				return nil, ErrTypedPrompt
			}
			out[i] = string(b)
		}
		return out, nil
	}
	fail := func(err error) ([]string, error) { abort = err; return nil, err }
	return func(c *ssh.ClientAuthContext) (ssh.AuthMethod, error) {
		if abort != nil {
			return nil, abort
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fails := 0
		for _, m := range c.TriedMethods {
			if m != methodNone {
				fails++
			}
		}
		if fails >= maxAskAttempts {
			return nil, ErrAuthAttempts
		}
		attempt := fails + 1
		switch {
		case slices.Contains(c.AllowedMethods, methodKbdInter):
			return ssh.KeyboardInteractive(func(name, ins string, qs []string, echos []bool) ([]string, error) {
				p, err := saneaPrompt(name, ins, qs, echos, attempt)
				if err != nil {
					return fail(err)
				}
				ans, err := run(p)
				if err != nil {
					return fail(err)
				}
				return ans, nil
			}), nil
		case slices.Contains(c.AllowedMethods, methodPassword):
			return ssh.PasswordCallback(func() (string, error) {
				ans, err := run(Prompt{Attempt: attempt, Questions: []Question{{Text: user + "@" + host + "'s password: "}}})
				if err != nil {
					_, err = fail(err)
					return "", err
				}
				return ans[0], nil
			}), nil
		}
		return nil, ErrTypedNoMethod
	}
}
