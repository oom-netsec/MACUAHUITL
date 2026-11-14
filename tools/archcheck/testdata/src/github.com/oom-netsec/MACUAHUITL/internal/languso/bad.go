package languso

import (
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest" // want `i18ntest es solo para pruebas`
)

func f() {
	i18n.SetDefault("es") // want `SetDefault es solo para pruebas`
	i18ntest.Set()
}
