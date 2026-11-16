//go:build race

package mask_test

// raceOn: con -race todo corre unas 30 veces más lento; las propiedades pesadas usan una muestra (cada plantilla una vez)
// y el corpus completo corre sin -race (paso «mask sin -race» del CI y de ./dev.sh test).
const raceOn = true
