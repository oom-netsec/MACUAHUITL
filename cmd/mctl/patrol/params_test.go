package patrol

import (
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestApplyParams(t *testing.T) {
	spec := &v1.JobSpec{Params: map[string]string{"ap": "AP1", "mac": "viejo"}}
	if err := applyParams(spec, []string{"mac=aa:bb:cc:dd:ee:ff", "x=a=b"}); err != nil {
		t.Fatal(err)
	}
	if spec.Params["mac"] != "aa:bb:cc:dd:ee:ff" || spec.Params["ap"] != "AP1" || spec.Params["x"] != "a=b" {
		t.Fatal(spec.Params)
	}
	for _, bad := range []string{"mac", "=x", ""} {
		if err := applyParams(&v1.JobSpec{}, []string{bad}); err == nil {
			t.Errorf("aceptó %q", bad)
		}
	}
	if err := applyParams(&v1.JobSpec{}, []string{"a=1", "a=2"}); err == nil {
		t.Error("repetido aceptado")
	}
}

func TestPlaybookLine(t *testing.T) {
	p := &v1.PlaybookInfo{Id: "ios-xe/x", Name: "X", Commands: []string{"a", "b"}}
	if got := playbookLine(p); got != "ios-xe/x  X  2 comandos" {
		t.Fatal(got)
	}
	p.Params = []*v1.PlaybookParam{{Name: "mac", Kind: "mac"}, {Name: "ap", Kind: "ap"}}
	if got := playbookLine(p); got != "ios-xe/x  X  2 comandos  datos: mac:mac ap:ap" {
		t.Fatal(got)
	}
}
