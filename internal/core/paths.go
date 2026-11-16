// Package core arranca el núcleo, controla su ciclo de vida y conecta los
// servicios entre sí.
//
// No hace: lógica de negocio; solo cableado.
package core

import "github.com/oom-netsec/MACUAHUITL/internal/paths"

// Paths son las rutas de spec §14 (internal/paths, compartido con la UI).
type Paths = paths.Paths

// ResolvePaths sigue la especificación XDG (en Windows, ADR 0012); env suele ser os.Getenv.
func ResolvePaths(env func(string) string) Paths { return paths.Resolve(env) }
