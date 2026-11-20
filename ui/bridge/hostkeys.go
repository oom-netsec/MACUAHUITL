package bridge

import v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"

// AcceptedHostKeyDTO ata una huella SSH aceptada al equipo que la mostró. Host es la dirección tal como se marca
// (con :puerto si no es 22); con varios destinos es la única forma de aceptar una huella.
// Nombres JSON: en los DTO de struct (metrics, transfer, terminal) los pares van en "acceptedKeys" porque
// "acceptedHostKeys" ya es la lista vieja de huellas; en Assist, que pasa protojson tal cual, "acceptedHostKeys" son los pares.
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

// PendingHostKeyDTO es una huella que el núcleo pide aceptar (PendingHostKey); Host vuelve tal cual en AcceptedHostKeyDTO.
type PendingHostKeyDTO struct {
	Host        string `json:"host"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"keyType"`
	Changed     bool   `json:"changed"`
}

func pendingKeys(in []*v1.PendingHostKey) []PendingHostKeyDTO {
	out := []PendingHostKeyDTO{}
	for _, k := range in {
		out = append(out, PendingHostKeyDTO{Host: k.GetHost(), Fingerprint: k.GetFingerprint(), KeyType: k.GetKeyType(), Changed: k.GetChanged()})
	}
	return out
}
