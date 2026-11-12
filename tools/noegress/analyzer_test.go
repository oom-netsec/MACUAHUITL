package noegress_test

import (
	"testing"

	"github.com/oom-netsec/MACUAHUITL/tools/noegress"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestAnalyzer(t *testing.T) {
	m := "github.com/oom-netsec/MACUAHUITL/"
	analysistest.Run(t, analysistest.TestData(), noegress.Analyzer,
		m+"internal/vault",
		m+"internal/transport/ssh",
		m+"internal/transporter",
		m+"internal/patrol",
		m+"gen/macuahuitl/v1",
		m+"internal/sys",
		"github.com/oom-netsec/MACUAHUITL",
	)
}
