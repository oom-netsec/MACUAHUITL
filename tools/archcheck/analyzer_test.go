package archcheck_test

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/tools/archcheck"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	m := "github.com/oom-netsec/MACUAHUITL/"
	analysistest.Run(t, analysistest.TestData(), archcheck.Analyzer,
		m+"internal/acl",
		m+"internal/topo",
		m+"internal/change",
		m+"internal/diag",
		m+"internal/diag/dnsq",
		m+"internal/core",
		m+"internal/capture",
		m+"internal/service/acl",
		m+"internal/service/field",
		m+"internal/calc/sub",
		m+"internal/iosconf",
		m+"internal/pcapan",
		m+"internal/audit",
		m+"internal/languso",
		m+"internal/i18n/i18ntest",
	)
}
