package playbooks

// MovedToIOSXE son los IDs de playbook que salieron del binario al paquete oficial oom/ios-xe (ADR 0010). Un trabajo
// que pide uno sin el paquete instalado falla con pack.missing. Una prueba la compara con packs/ios-xe/playbooks.
var MovedToIOSXE = []string{}
