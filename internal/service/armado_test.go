package service

import (
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func conInfo(meta map[string]string) error {
	st, _ := status.New(codes.FailedPrecondition, "x").WithDetails(&errdetails.ErrorInfo{Reason: "patrol.svc.login_failed", Metadata: meta})
	return st.Err()
}

// ArmFailure: varias llaves; un error sin status ni metadata; metadata rota o con entradas rotas no rompen nada.
func TestArmFailure(t *testing.T) {
	r, keys := ArmFailure(conInfo(map[string]string{"host_keys": `[{"host":"[2001:db8::1]:2222","fingerprint":"SHA256:a","keyType":"ssh-ed25519"},{"host":"sw1:22","fingerprint":"SHA256:b","changed":true}]`}))
	if r != "patrol.svc.login_failed" || len(keys) != 2 || keys[0].Host != "[2001:db8::1]:2222" || keys[0].KeyType != "ssh-ed25519" || !keys[1].Changed {
		t.Fatalf("%q %v", r, keys)
	}
	if r, keys := ArmFailure(errors.New("sin status")); r != "" || keys != nil {
		t.Errorf("sin status: %q %v", r, keys)
	}
	if r, keys := ArmFailure(conInfo(nil)); r != "patrol.svc.login_failed" || keys != nil {
		t.Errorf("sin metadata: %q %v", r, keys)
	}
	if _, keys := ArmFailure(conInfo(map[string]string{"host_keys": `{no`})); keys != nil {
		t.Errorf("JSON roto: %v", keys)
	}
	if _, keys := ArmFailure(conInfo(map[string]string{"host_keys": `[{"host":1},{"host":"a:22"}]`})); len(keys) != 1 || keys[0].Host != "a:22" {
		t.Errorf("entrada rota: %v", keys)
	}
}
