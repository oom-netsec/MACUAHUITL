package vault

import "os/exec" // want `noegress: .* importa "os/exec"`

var _ = exec.Command
