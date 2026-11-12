package bridge

import (
	"context"

	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/ipc"
)

// ListPlaybooks devuelve el catálogo de playbooks del núcleo como ListPlaybooksResponse en JSON
// (camelCase); cada id es el que CreateJob acepta en playbook_ids. Una lista vacía llega como {}.
func (b *Bridge) ListPlaybooks() (string, error) {
	return call(b, func(ctx context.Context, c *ipc.ClientConn) (string, error) {
		r, err := v1.NewPatrolServiceClient(c).ListPlaybooks(ctx, &v1.ListPlaybooksRequest{})
		if err != nil {
			return "", err
		}
		raw, err := protojson.Marshal(r)
		return string(raw), err
	})
}
