package analyze

import "time"

// Las horas que se muestran son locales: se fija la zona para que los golden sean iguales en Linux y en Windows.
func init() { time.Local = time.FixedZone("UTC", 0) }
