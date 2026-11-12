package imgverify

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSumAndCompare(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c2960x-universalk9-mz.152-7.E9.bin")
	os.WriteFile(p, []byte("abc"), 0o600)
	r, err := Check(p, " 900150983CD24FB0D6963F7D28E17F72 \n", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.MD5 != "900150983cd24fb0d6963f7d28e17f72" ||
		r.SHA512 != "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" {
		t.Fatalf("%+v", r)
	}
	if r.MD5Match != "ok" || r.SHA512Match != "" {
		t.Fatalf("%+v", r)
	}
	if r.VerifyCommand != "verify /md5 flash:c2960x-universalk9-mz.152-7.E9.bin 900150983cd24fb0d6963f7d28e17f72" {
		t.Fatal(r.VerifyCommand)
	}
	r, _ = Check(p, "", "00"+r.SHA512[2:])
	if r.SHA512Match != "distinto" || r.OK() {
		t.Fatalf("%+v", r)
	}
	if _, err := Check(p, "xyz", ""); err == nil {
		t.Fatal("MD5 inválido aceptado")
	}
	if _, err := Check("rel.bin", "", ""); err == nil {
		t.Fatal("ruta relativa")
	}
}
