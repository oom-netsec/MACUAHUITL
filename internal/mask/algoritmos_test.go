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
