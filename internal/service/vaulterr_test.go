package service

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/vault"
)

func vaultErrsEs() map[string]string {
	out := map[string]string{}
	for n, e := range map[string]error{
		"locked": vault.ErrLocked, "wrong": vault.ErrWrongPassword, "notfound": vault.ErrNotFound, "empty": vault.ErrEmptyPassword,
		"window": vault.ErrWindowTooLong, "reserved": vault.ErrReserved, "notbackup": vault.ErrNotBackup, "short": vault.ErrShortPhrase,
		"same": vault.ErrSamePhrase, "many": vault.ErrTooManyEntries, "notregular": vault.ErrNotRegular, "params": vault.ErrBackupParams,
		"exists": vault.ErrExists, "bexists": vault.ErrBackupExists, "corrupt": vault.ErrCorrupt, "weak": vault.ErrWeakParams,
		"wrapped": fmt.Errorf("abrir: %w", vault.ErrLocked), "other": fmt.Errorf("algo raro"),
	} {
		st := status.Convert(vaultErr(e))
		out[n] = st.Code().String() + "|" + st.Message()
	}
	return out
}

// Regresión: el código gRPC y el texto en español de cada error de la bóveda son los de antes del catálogo.
func TestVaultErrEspanolRegresion(t *testing.T) {
	got := vaultErrsEs()
	const file = "testdata/vaulterr_es.golden.json"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		b, _ := json.MarshalIndent(got, "", " ")
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(file, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	json.Unmarshal(raw, &want)
	for n, g := range got {
		if g != want[n] {
			t.Errorf("%s cambió:\n got: %s\nwant: %s", n, g, want[n])
		}
	}
	if len(want) != len(got) {
		t.Errorf("%d casos, golden %d", len(got), len(want))
	}
}

func vaultErr(e error) error { return VaultErr(context.Background(), e) }

// Con en, el error de la bóveda sale en inglés, con su código gRPC y su reason.
func TestVaultErrEn(t *testing.T) {
	err := VaultErr(i18n.WithLocale(context.Background(), "en"), fmt.Errorf("abrir: %w", vault.ErrLocked))
	st := status.Convert(err)
	if st.Code() != codes.FailedPrecondition || st.Message() != "abrir: vault: vault is locked" {
		t.Fatalf("%v", err)
	}
	if ei, _ := st.Details()[0].(*errdetails.ErrorInfo); ei == nil || ei.Reason != "vault.err.locked" {
		t.Fatalf("%v", st.Details())
	}
}
