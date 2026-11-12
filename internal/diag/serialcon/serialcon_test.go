package serialcon

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeDevice abre un pty: el maestro hace de equipo, el esclavo de puerto serie.
func fakeDevice(t *testing.T) (*os.File, string) {
	t.Helper()
	m, path, err := Pty()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	return m, path
}

func TestOpenAppliesCiscoDefaults(t *testing.T) {
	_, path := fakeDevice(t)
	p, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var tio *unix.Termios
	p.control(func(fd int) { tio, err = unix.IoctlGetTermios(fd, unix.TCGETS) })
	if err != nil {
		t.Fatal(err)
	}
	if tio.Cflag&unix.CBAUD != unix.B9600 || tio.Cflag&unix.CSIZE != unix.CS8 || tio.Cflag&(unix.PARENB|unix.CSTOPB|unix.CRTSCTS) != 0 {
		t.Fatalf("cflag = %#o; se esperaba 9600 8N1 sin flujo", tio.Cflag)
	}
	if tio.Lflag&(unix.ICANON|unix.ECHO) != 0 || tio.Iflag&(unix.IXON|unix.ICRNL) != 0 || tio.Oflag&unix.OPOST != 0 {
		t.Fatalf("no quedó en modo crudo: %+v", tio)
	}
}

func TestRawCustomParams(t *testing.T) {
	// El pty descarta la paridad, así que esto se comprueba sobre la estructura.
	tio := &unix.Termios{Cflag: unix.B9600 | unix.CS8, Iflag: unix.ICRNL}
	raw(tio, Config{Baud: 115200, DataBits: 7, Parity: "even", StopBits: 2, Flow: "rtscts"})
	if tio.Cflag&unix.CBAUD != unix.B115200 || tio.Cflag&unix.CSIZE != unix.CS7 || tio.Cflag&unix.PARENB == 0 || tio.Cflag&unix.PARODD != 0 ||
		tio.Cflag&unix.CSTOPB == 0 || tio.Cflag&unix.CRTSCTS == 0 || tio.Iflag&unix.IXON != 0 {
		t.Fatalf("cflag = %#o", tio.Cflag)
	}
	raw(tio, Config{Baud: 9600, DataBits: 8, Parity: "odd", StopBits: 1, Flow: "xonxoff"})
	if tio.Cflag&(unix.PARENB|unix.PARODD) != unix.PARENB|unix.PARODD || tio.Cflag&(unix.CSTOPB|unix.CRTSCTS) != 0 || tio.Iflag&unix.IXON == 0 {
		t.Fatalf("cflag = %#o iflag = %#o", tio.Cflag, tio.Iflag)
	}
}

func TestConfigValidation(t *testing.T) {
	for _, c := range []Config{
		{Path: "relativo"},
		{Path: "/etc/passwd"},
		{Path: "/dev/ttyUSB0", Baud: 12345},
		{Path: "/dev/ttyUSB0", Parity: "mark"},
		{Path: "/dev/ttyUSB0", DataBits: 9},
		{Path: "/dev/ttyUSB0", StopBits: 3},
		{Path: "/dev/ttyUSB0", Flow: "dtr"},
	} {
		if _, err := Open(c); err == nil {
			t.Errorf("%+v aceptado", c)
		}
	}
}

func TestBidirectionalAndBreak(t *testing.T) {
	m, path := fakeDevice(t)
	p, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Write([]byte("show version\r")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, _ := m.Read(buf)
	if string(buf[:n]) != "show version\r" { // crudo: sin traducir \r
		t.Fatalf("equipo recibió %q", buf[:n])
	}
	m.Write([]byte("Switch>"))
	n, _ = p.Read(buf)
	if string(buf[:n]) != "Switch>" {
		t.Fatalf("leído %q", buf[:n])
	}
	if err := p.Break(); err != nil {
		t.Fatal(err)
	}
	// Cerrar desbloquea una lectura pendiente.
	done := make(chan error)
	go func() { _, err := p.Read(buf); done <- err }()
	time.Sleep(50 * time.Millisecond)
	p.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close no desbloqueó Read")
	}
}

func TestExclusive(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignora TIOCEXCL")
	}
	_, path := fakeDevice(t)
	p, err := Open(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if _, err := Open(Config{Path: path}); err == nil {
		t.Fatal("se abrió dos veces el mismo puerto")
	}
}

func TestPermissionErrorExplainsDialout(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root no recibe EACCES")
	}
	err := openErr("/dev/ttyUSB9", &os.PathError{Op: "open", Path: "/dev/ttyUSB9", Err: unix.EACCES})
	if !errors.Is(err, ErrPermission) || !strings.Contains(err.Error(), "dialout") || !strings.Contains(err.Error(), "usermod -aG dialout") {
		t.Fatalf("err = %v", err)
	}
	// Un archivo que no es terminal se rechaza con un mensaje claro.
	f := filepath.Join(t.TempDir(), "x")
	os.WriteFile(f, nil, 0o600)
	if _, err := open(Config{Path: f}.withDefaults()); err == nil || !strings.Contains(err.Error(), "no es un puerto serie") {
		t.Fatalf("archivo normal: %v", err)
	}
}

func TestListFindsUSBAndACM(t *testing.T) {
	d := t.TempDir()
	for _, n := range []string{"ttyUSB0", "ttyACM1", "ttyS0", "sda"} {
		os.WriteFile(filepath.Join(d, n), nil, 0o600)
	}
	got := list(d)
	if strings.Join(got, ",") != filepath.Join(d, "ttyACM1")+","+filepath.Join(d, "ttyUSB0") {
		t.Fatalf("got %v", got)
	}
}

func TestRecorderStampsEachLine(t *testing.T) {
	var b bytes.Buffer
	now := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)
	r := NewRecorder(&b, func() time.Time { return now })
	r.Mark("abierto /dev/ttyUSB0 9600 8N1")
	io.WriteString(r, "Switch>sh")
	io.WriteString(r, "ow ver\r\nCisco IOS\r\n")
	r.Mark("BREAK")
	io.WriteString(r, "rommon 1 >")
	want := "2026-11-04T10:00:00.000Z ### abierto /dev/ttyUSB0 9600 8N1\n" +
		"2026-11-04T10:00:00.000Z Switch>show ver\n" +
		"2026-11-04T10:00:00.000Z Cisco IOS\n" +
		"2026-11-04T10:00:00.000Z ### BREAK\n" +
		"2026-11-04T10:00:00.000Z rommon 1 >"
	if b.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

// AuditString va junto a String: mismo formato de línea pero con la clave en inglés para la bitácora.
func TestConfigAuditString(t *testing.T) {
	c := Config{Baud: 9600, DataBits: 8, Parity: "n", StopBits: 1, Flow: "none"}
	if got, want := c.AuditString(), "9600 8N1 flow=none"; got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
