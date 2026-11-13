package core

import (
	"testing"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestSpecFromProtoLlevaLosDatos(t *testing.T) {
	s := specFromProto(&v1.JobSpec{Params: map[string]string{"mac": "aabb.ccdd.eeff"}})
	if s.Params["mac"] != "aabb.ccdd.eeff" {
		t.Fatal(s.Params)
	}
}
