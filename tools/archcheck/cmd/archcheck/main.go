// Command archcheck corre el analizador archcheck sobre los paquetes dados.
package main

import (
	"github.com/oom-netsec/MACUAHUITL/tools/archcheck"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() { singlechecker.Main(archcheck.Analyzer) }
