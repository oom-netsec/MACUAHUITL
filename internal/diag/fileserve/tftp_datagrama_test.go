package fileserve

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// Un datagrama más grande que una petición al puerto de escucha no tumba el servidor (en Windows, con un búfer
// chico, la lectura fallaba con WSAEMSGSIZE): la descarga siguiente funciona igual.
func TestTFTPDatagramaGrande(t *testing.T) {
	p, want := image(t, "img.bin", 512*2+7)
	s := start(t, "tftp", p)
	c := dialTFTP(t, s.addr)
	c.send(c.srv, bytes.Repeat([]byte{0, 1}, 30000))
	if got, _ := c.get("img.bin", 512); !bytes.Equal(got, want) {
		t.Fatal("contenido distinto tras el datagrama grande")
	}
}

// Un DATA mayor que el blksize acordado aborta la subida con error 4, no se trunca.
func TestTFTPDataMayorQueBlksize(t *testing.T) {
	s, _ := startCfg(t, Config{Proto: "tftp", Write: true, RecvDir: realTemp(t)})
	c := dialTFTP(t, s.addr)
	c.send(c.srv, wrq("cfg"))
	_, tid := c.recv()
	c.send(tid, dataPkt(1, make([]byte, 60000)))
	p, _ := c.recv()
	if binary.BigEndian.Uint16(p) != 5 || binary.BigEndian.Uint16(p[2:]) != 4 {
		t.Fatalf("esperaba error 4, llegó %v", p[:4])
	}
}
