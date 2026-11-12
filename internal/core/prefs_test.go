package core

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

func TestPreferencesRoundTripAndValidation(t *testing.T) {
	h := newHarness(t, nil)
	c := v1.NewPrefsServiceClient(h.conn)
	r, err := c.GetPreference(ctx(t), &v1.GetPreferenceRequest{Key: "terminal"})
	if err != nil || r.Found {
		t.Fatalf("sin valor: %v %v", r, err)
	}
	for _, v := range []string{`{"palette":"p3"}`, `{"palette":"ibm","hl":true}`} {
		if _, err := c.SetPreference(ctx(t), &v1.SetPreferenceRequest{Key: "terminal", Value: v}); err != nil {
			t.Fatal(err)
		}
	}
	r, _ = c.GetPreference(ctx(t), &v1.GetPreferenceRequest{Key: "terminal"})
	if !r.Found || r.Value != `{"palette":"ibm","hl":true}` {
		t.Fatalf("%v", r)
	}
	for _, bad := range []*v1.SetPreferenceRequest{
		{Key: "", Value: "x"}, {Key: "Mala Clave", Value: "x"}, {Key: "terminal", Value: strings.Repeat("x", 4097)}, {Key: "otra", Value: "x"},
	} {
		if _, err := c.SetPreference(ctx(t), bad); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%q: %v", bad.Key, err)
		}
	}
	if _, err := c.GetPreference(ctx(t), &v1.GetPreferenceRequest{Key: "MAL"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal(err)
	}
	if _, err := c.GetPreference(ctx(t), &v1.GetPreferenceRequest{Key: "otra"}); status.Code(err) != codes.InvalidArgument {
		t.Fatal("clave desconocida aceptada:", err)
	}
}
