package fileserve

import (
	"encoding/binary"
	"strings"
	"testing"
)

const hostil = "x\x1b]0;pwn\a\u202e"

func errPkt(msg string) []byte {
	return append(append(binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(nil, 5), 0), msg...), 0)
}

// limpio comprueba que el texto que llegó del par salió saneado y corto.
func limpio(t *testing.T, donde string, x Transfer) {
	t.Helper()
	for k, v := range x.ReasonT.Args {
		if strings.ContainsAny(v, "\x1b\a\u202e") || len([]rune(v)) > 128 {
			t.Fatalf("%s: arg %s sin sanear o largo (%d runas): %q", donde, k, len([]rune(v)), v)
		}
	}
	if strings.ContainsAny(x.Error, "\x1b\a\u202e") || len([]rune(x.Error)) > 256 {
		t.Fatalf("%s: Error sin sanear o largo (%d runas): %q", donde, len([]rune(x.Error)), x.Error)
	}
}

func TestTextosDelParteTFTPErrorRRQ(t *testing.T) {
	p, _ := image(t, "img.bin", 512*5)
	rec, r := liveStart(t, Config{Proto: "tftp", Files: []string{p}})
	c := dialTFTP(t, r.Addr)
	c.send(c.srv, rrq("img.bin"))
	_, tid := c.recv()
	c.send(tid, errPkt(hostil+strings.Repeat("A", 60000)))
	x := rec.waitEnds(t, 1)[0]
	if x.ReasonT.Args["msg"] == "" {
		t.Fatalf("sin msg: %+v", x)
	}
	limpio(t, "RRQ", x)
}

func TestTextosDelParteTFTPErrorWRQ(t *testing.T) {
	rec, r := liveStart(t, Config{Proto: "tftp", Write: true, RecvDir: t.TempDir()})
	c := dialTFTP(t, r.Addr)
	c.send(c.srv, wrq("cfg"))
	_, tid := c.recv()
	c.send(tid, errPkt(hostil+strings.Repeat("A", 60000)))
	x := rec.waitEnds(t, 1)[0]
	if x.ReasonT.Args["msg"] == "" {
		t.Fatalf("sin msg: %+v", x)
	}
	limpio(t, "WRQ", x)
}

func TestTextosDelParteSSHCanalYTipo(t *testing.T) {
	rec, r := liveStart(t, Config{Proto: "sftp", Write: true, RecvDir: t.TempDir()})
	cl := mustDial(t, r.Addr, r)
	cl.OpenChannel(hostil+strings.Repeat("A", 5000), nil)
	x := rec.waitEnds(t, 1)[0]
	if !x.Rejected || x.ReasonT.Args["type"] == "" {
		t.Fatalf("%+v", x)
	}
	limpio(t, "canal", x)
	s, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	s.SendRequest(hostil+strings.Repeat("A", 5000), true, nil) // request_rejected
	y := rec.waitEnds(t, 2)[1]
	if !y.Rejected || y.ReasonT.Args["type"] == "" {
		t.Fatalf("%+v", y)
	}
	limpio(t, "petición", y)
}
