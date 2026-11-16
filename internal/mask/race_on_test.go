//go:build race

package mask_test

import "os"

// raceOn: con -race todo corre unas 30 veces más lento; las propiedades pesadas usan una muestra con semilla (ver muestra)
// y el corpus completo corre sin -race (paso «mask sin -race» del CI y de ./dev.sh test). MACUAHUITL_CORPUS=full lo
// obliga completo también con -race (workflow corpus.yml).
var raceOn = os.Getenv("MACUAHUITL_CORPUS") != "full"
