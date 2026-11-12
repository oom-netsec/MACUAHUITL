package vault

import (
	"fmt"
	"net/http" // want `noegress: github.com/oom-netsec/MACUAHUITL/internal/vault importa "net/http"`

	n "net" // want `noegress: .* importa "net"`
)

var _ = fmt.Sprint
var _ = http.MethodGet
var _ n.IP
