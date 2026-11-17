package transfer

import (
	"net/url"
	"testing"
)

// Los equipos Cisco nombran el archivo con prefijo de dispositivo (flash:c3560cx.bin): no va en el nombre local.
func TestURLNameQuitaElDispositivo(t *testing.T) {
	for in, want := range map[string]string{
		"scp://h/flash:c3560cx.bin":  "c3560cx.bin",
		"scp://h/flash:/x":           "x",
		"scp://h/bootflash:img.bin":  "img.bin",
		"scp://h/dir/disk0:a.bin":    "a.bin",
		"scp://h/nvram:startup-conf": "startup-conf",
		"http://h/plain.bin":         "plain.bin",
	} {
		u, _ := url.Parse(in)
		if got := URLName(u.Path); got != want {
			t.Errorf("URLName(%q) = %q, quiero %q", in, got, want)
		}
	}
}
