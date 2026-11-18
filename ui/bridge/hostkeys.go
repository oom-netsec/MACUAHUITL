package bridge

import v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"

// AcceptedHostKeyDTO ata una huella SSH aceptada al equipo que la mostró. Host es la dirección tal como se marca
// (con :puerto si no es 22); con varios destinos es la única forma de aceptar una huella.
type AcceptedHostKeyDTO struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
}

func protoKeys(in []AcceptedHostKeyDTO) []*v1.AcceptedHostKey {
	var out []*v1.AcceptedHostKey
	for _, k := range in {
		out = append(out, &v1.AcceptedHostKey{Host: k.Host, Fingerprint: k.Fingerprint})
	}
	return out
}
