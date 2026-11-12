package vault

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
)

// pwThenFail entrega la línea de login y después falla con un error que no es EOF.
type pwThenFail struct{ r io.Reader }

func (p *pwThenFail) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if err == io.EOF {
		return n, errors.New("lectura rota")
	}
	return n, err
}

// Si leer el enable falla, la contraseña de login ya leída se borra de memoria igual.
func TestCredAddWipesLoginPasswordWhenEnableReadFails(t *testing.T) {
	var wiped [][]byte
	old := wipe
	wipe = func(bs ...[]byte) {
		for _, b := range bs {
			wiped = append(wiped, append([]byte(nil), b...))
		}
		old(bs...)
	}
	defer func() { wipe = old }()
	env := &cli.Env{In: bufio.NewReader(&pwThenFail{strings.NewReader("pw-login\n")})}
	if err := credAdd(env, []string{"--user", "admin"}); err == nil || !strings.Contains(err.Error(), "lectura rota") {
		t.Fatalf("err = %v", err)
	}
	found := false
	for _, b := range wiped {
		found = found || string(b) == "pw-login"
	}
	if !found {
		t.Errorf("la contraseña de login no se pasó por Wipe: %q", wiped)
	}
}
