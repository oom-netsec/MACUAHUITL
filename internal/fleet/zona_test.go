package fleet

import (
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Las horas que se muestran son locales: se fija solo la zona de pantalla (no time.Local) para que los golden sean iguales en Linux y en Windows.
func init() { i18n.DisplayZone = time.FixedZone("UTC", 0) }
