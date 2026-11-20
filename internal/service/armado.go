package service

import (
	"encoding/json"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// ArmFailure saca de un error de ArmJob el motivo del catálogo y las llaves de host pendientes (metadata host_keys,
// un arreglo JSON de PendingHostKey), para la respuesta de los servicios que arman un trabajo (ad hoc, respaldos).
func ArmFailure(err error) (reason string, keys []*v1.PendingHostKey) {
	for _, d := range status.Convert(err).Details() {
		ei, ok := d.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		var raw []json.RawMessage
		if json.Unmarshal([]byte(ei.Metadata["host_keys"]), &raw) == nil {
			for _, r := range raw {
				var k v1.PendingHostKey
				if protojson.Unmarshal(r, &k) == nil {
					keys = append(keys, &k)
				}
			}
		}
		return ei.Reason, keys
	}
	return "", nil
}
