// Command noegress corre el analizador noegress sobre los paquetes dados.
package main

import (
	"github.com/oom-netsec/MACUAHUITL/tools/noegress"
	"golang.org/x/tools/go/analysis/singlechecker"
)

func main() { singlechecker.Main(noegress.Analyzer) }
