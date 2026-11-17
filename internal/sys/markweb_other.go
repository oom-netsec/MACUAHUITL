//go:build !windows

package sys

import "os"

// MarkOfTheWeb no hace nada fuera de Windows: no hay flujo Zone.Identifier.
func MarkOfTheWeb(string) error { return nil }

// MarkOfTheWebIfSame no hace nada fuera de Windows.
func MarkOfTheWebIfSame(string, os.FileInfo) error { return nil }
