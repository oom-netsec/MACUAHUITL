package mask_test

import (
	"strings"
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/mask"
)

// SecretValues salta los algoritmos exactos (sha1, hmac-sha256…), no cualquier palabra que empiece con sha, aes o hmac.
func TestSecretValuesNoSaltaContrasenasConPrefijoDeAlgoritmo(t *testing.T) {
	for _, v := range []string{"Shadow2024x", "Sharepoint1", "aesop99", "HmacKey1", "Aes256Pass9", "shared#Key1"} {
		_, vals := mask.CutCommand("", "cry isa key "+v+" add 1.1.1.1", "cry isa key <MASKED:secret> add 1.1.1.1")
		if len(vals) == 0 || vals[0] != v {
			t.Errorf("%s: valores %q", v, vals)
		}
	}
	_, vals := mask.CutCommand("", "ntp authentication-key 10 sha1 Xq7z9Pw0rd", "ntp authentication-key 10 sha1 Xq7z9Pw0rd")
	if len(vals) == 0 || vals[0] != "Xq7z9Pw0rd" || strings.Contains(strings.Join(vals, " "), "sha1") {
		t.Errorf("sha1: %q", vals)
	}
}

// Algoritmos de IOS-XE 17 (ntp authentication-key 1 hmac-sha2-256 KEY): se saltan y el valor recordado es la clave.
func TestSecretValuesSaltaAlgoritmosHmacSha2YCmac(t *testing.T) {
	for _, alg := range []string{"hmac-sha2-256", "hmac-sha2-384", "hmac-sha2-512", "cmac-aes-128", "cmac", "hmac-sha1-96", "sha256"} {
		cmd := "ntp authentication-key 1 " + alg + " Xq7z9Pw0rd"
		_, vals := mask.CutCommand("", cmd, cmd)
		if len(vals) == 0 || vals[0] != "Xq7z9Pw0rd" {
			t.Errorf("%s: valores %q", alg, vals)
		}
	}
	for _, v := range []string{"cmacPass77", "hmacBlue77", "sha1Pass99"} {
		_, vals := mask.CutCommand("", "cry isa key "+v+" add 1.1.1.1", "cry isa key <MASKED:secret> add 1.1.1.1")
		if len(vals) == 0 || vals[0] != v {
			t.Errorf("%s: valores %q", v, vals)
		}
	}
}
