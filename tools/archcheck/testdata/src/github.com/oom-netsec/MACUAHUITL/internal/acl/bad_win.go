package acl

import "golang.org/x/sys/windows/registry" // want `archcheck: internal/acl importa "golang.org/x/sys/windows/registry": x/sys/windows solo en`

var _ = registry.X
