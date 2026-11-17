package core

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// relojFlota fija el reloj del núcleo: la antigüedad de la evidencia («hace N d») no puede depender de la hora real
// (con el reloj real, TestFlotaRegresionEs fallaba cada día entre las 08:00 y las 08:03 UTC, las horas de las fixtures).
var relojFlota = time.Date(2036, 11, 5, 12, 0, 0, 0, time.UTC) // lejos de la fecha real: con time.Now la prueba no puede pasar por casualidad

func harnessFlota(t *testing.T) *harness {
	t.Helper()
	return newHarness(t, func(o *Options) { o.Now = func() time.Time { return relojFlota } })
}

// La antigüedad de la evidencia de flota sale del reloj del núcleo, no de time.Now.
func TestFlotaUsaElRelojDelNucleo(t *testing.T) {
	h := harnessFlota(t)
	fdir, _ := filepath.Abs("../fleet/testdata/outputs")
	r, err := v1.NewFleetServiceClient(h.conn).Find(con(t, "es"), &v1.FindRequest{Dir: fdir, Query: "dist1"})
	if err != nil {
		t.Fatal(err)
	}
	if txt := r.GetReport().GetText(); !strings.Contains(txt, "hace 3653 d") {
		t.Fatalf("la antigüedad no sale del reloj del núcleo:\n%s", txt)
	}
}
