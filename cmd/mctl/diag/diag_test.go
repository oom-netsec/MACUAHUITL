package diag

import (
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestEstimateMTU(t *testing.T) {
	pt := func(size int32, r string) *v1.SweepPoint { return &v1.SweepPoint{Size: size, Result: r} }
	for _, c := range []struct {
		pts  []*v1.SweepPoint
		hdr  int
		want int
	}{
		{[]*v1.SweepPoint{pt(1500, "frag")}, 28, 0},
		{[]*v1.SweepPoint{pt(1400, "ok"), pt(1450, "loss"), pt(1500, "frag")}, 28, 1428},
		{[]*v1.SweepPoint{pt(1400, "ok"), pt(1500, "frag")}, 48, 1448},
		{[]*v1.SweepPoint{pt(0, "ok"), pt(1, "frag")}, 28, 28},
		{[]*v1.SweepPoint{pt(1400, "ok"), pt(1500, "frag"), pt(1600, "ok")}, 28, 1428},
		{[]*v1.SweepPoint{pt(1400, "ok")}, 28, 0},
	} {
		if got, _ := estimateMTU(c.pts, c.hdr); got != c.want {
			t.Errorf("%v: %d, quiero %d", c.pts, got, c.want)
		}
	}
}
