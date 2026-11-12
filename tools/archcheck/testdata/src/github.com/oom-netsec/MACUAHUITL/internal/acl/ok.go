package acl

import (
	"net/netip"

	"github.com/oom-netsec/MACUAHUITL/internal/parse/iosxe"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

var _ = netip.Addr{}
var _ = iosxe.Parse
var _ = vault.Open
