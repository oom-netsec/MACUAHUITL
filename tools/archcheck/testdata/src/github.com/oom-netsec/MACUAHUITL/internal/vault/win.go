package vault

import "golang.org/x/sys/windows" // want `archcheck: internal/vault importa "golang.org/x/sys/windows": x/sys/windows solo en internal/sys, internal/ipc, internal/diag, internal/diag/serialcon, internal/core/power y ui \(ADR 0012\)`

var _ = windows.X
