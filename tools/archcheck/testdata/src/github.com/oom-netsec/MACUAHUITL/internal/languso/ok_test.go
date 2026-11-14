package languso

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n/i18ntest"
)

func TestX(t *testing.T) {
	i18n.SetDefault("es")
	i18ntest.Set()
}
