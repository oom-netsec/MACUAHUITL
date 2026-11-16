package mask_test

import (
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"
)

// semillaMuestra: MACUAHUITL_SEED, o la fecha (YYYYMMDD) si no está: la muestra con -race cambia cada día y se reproduce.
// Se calcula una sola vez para que la fecha no cambie a mitad de una corrida que cruza la medianoche.
var semillaMuestra = sync.OnceValue(func() int64 {
	if s, err := strconv.ParseInt(os.Getenv("MACUAHUITL_SEED"), 10, 64); err == nil {
		return s
	}
	n, _ := strconv.ParseInt(time.Now().Format("20060102"), 10, 64)
	return n
})

func TestMain(m *testing.M) {
	if raceOn {
		fmt.Printf("mask: muestra con -race, MACUAHUITL_SEED=%d (MACUAHUITL_CORPUS=full para el corpus completo)\n", semillaMuestra())
	}
	os.Exit(m.Run())
}

// indicesMuestra: k índices distintos de [0,n), en orden, determinista para una semilla.
func indicesMuestra(n, k int, semilla int64) []int {
	if k >= n {
		k = n
	}
	idx := rand.New(rand.NewSource(semilla)).Perm(n)[:k]
	sort.Ints(idx)
	return idx
}

// muestra: sin -race devuelve todo; con -race, 1 de cada «cada» pares (cmds, plats) elegidos con la semilla del día.
func muestra(cmds, plats []string, cada int) ([]string, []string) {
	if !raceOn {
		return cmds, plats
	}
	var c, p []string
	for _, i := range indicesMuestra(len(cmds), len(cmds)/cada, semillaMuestra()) {
		c, p = append(c, cmds[i]), append(p, plats[i])
	}
	return c, p
}

func TestIndicesMuestra(t *testing.T) {
	a, b := indicesMuestra(100, 10, 7), indicesMuestra(100, 10, 7)
	if fmt.Sprint(a) != fmt.Sprint(b) || len(a) != 10 || !sort.IntsAreSorted(a) {
		t.Fatalf("no determinista u ordenada: %v %v", a, b)
	}
	if fmt.Sprint(a) == fmt.Sprint(indicesMuestra(100, 10, 8)) {
		t.Fatal("otra semilla dio la misma muestra")
	}
	if len(indicesMuestra(3, 10, 1)) != 3 {
		t.Fatal("k > n debe devolver todo")
	}
}
