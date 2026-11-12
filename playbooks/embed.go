// Package playbooks incrusta en el binario los playbooks versionados del repo.
package playbooks

import "embed"

//go:embed cisco
var FS embed.FS
