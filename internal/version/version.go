// Package version expone la versión de los binarios de MACUAHUITL.
package version

// Version se sobrescribe al compilar con
// -ldflags "-X github.com/oom-netsec/MACUAHUITL/internal/version.Version=v1.2.3".
var Version = "dev"

// String devuelve la versión legible para --version.
func String() string { return "macuahuitl " + Version }
