package ref065

import (
	"bytes"
	"strings"
)

// MaskRaw es maskRaw de internal/diag/syslogd tal como lo publicó la v0.6.5.
func MaskRaw(raw []byte) []byte {
	platform := ""
	if bytes.Contains(raw, []byte("%ASA-")) || bytes.Contains(raw, []byte("%FTD-")) {
		platform = "asa"
	}
	out, _ := Apply(platform, string(raw))
	if strings.ContainsAny(out, "\r\n") {
		out = strings.Join(strings.Fields(strings.NewReplacer("\r", " ", "\n", " ").Replace(out)), " ")
		out, _ = Apply(platform, out)
	}
	return []byte(out)
}
