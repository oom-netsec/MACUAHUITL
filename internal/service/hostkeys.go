package service

import (
	"context"

	"google.golang.org/grpc/codes"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/transport"
)

// HostKeyAccepts arma transport.HostKeyPolicy.Accepted desde los dos campos del contrato.
// targets son los destinos del RPC ya normalizados con transport.HostKeyID. El campo nuevo (host, huella)
// entra tal cual. El anterior (solo huellas) solo vale con un destino: cada huella se ata a ese destino;
// con varios es InvalidArgument hostkey.err.accept_ambiguous.
func HostKeyAccepts(ctx context.Context, targets, legacy []string, keys []*v1.AcceptedHostKey) (map[string]map[string]bool, error) {
	out := map[string]map[string]bool{}
	add := func(id, fp string) {
		if out[id] == nil {
			out[id] = map[string]bool{}
		}
		out[id][fp] = true
	}
	if len(legacy) > 0 {
		if len(targets) != 1 {
			return nil, Err(ctx, codes.InvalidArgument, "hostkey.err.accept_ambiguous", nil)
		}
		for _, fp := range legacy {
			add(targets[0], fp)
		}
	}
	for _, k := range keys {
		id, err := transport.ParseHostKeyID(k.GetHost())
		if err != nil {
			return nil, Err(ctx, codes.InvalidArgument, "hostkey.err.accept_invalid", i18n.A("host", k.GetHost()))
		}
		add(id, k.GetFingerprint())
	}
	return out, nil
}
