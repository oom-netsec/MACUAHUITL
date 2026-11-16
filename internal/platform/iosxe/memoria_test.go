package iosxe

import (
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

// salidaConRuido: líneas con CRLF, --More-- borrados de las dos formas y retornos de carro sueltos.
func salidaConRuido(n int, r *rand.Rand, ruido bool) []byte {
	piezas := []string{"interface GigabitEthernet1/0/1\r\n", " description uplink\r\n", " --More-- \r        \r\n", "x --More--\x08\x08\x08\x08\x08\x08\x08\x08        \x08\x08\x08\x08\x08\x08\x08\x08\n",
		"abc\rdef\r\n", "<--- More --->\r\n", "--More-- or (q)uit\r\n", "sin salto de línea al final de este trozo grande ", "\r", "\n"}
	var b strings.Builder
	for b.Len() < n {
		if !ruido || r.Intn(40) > 0 { // la salida real es casi toda líneas normales
			b.WriteString(" ip address 10.1.1.1 255.255.255.0 description uplink-to-core\r\n")
			continue
		}
		b.WriteString(piezas[r.Intn(len(piezas))])
	}
	return []byte(b.String())
}

// cleanBuf da exactamente lo mismo que clean(string(b)), con trozos que cortan en cualquier parte.
func TestCleanBufIgualAClean(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	for _, n := range []int{0, 10, 64 << 10, 64<<10 + 1, 300 << 10, 1 << 20} {
		for range 4 {
			b := salidaConRuido(n, r, true)
			if got, want := cleanBuf(b), clean(string(b)); got != want {
				t.Fatalf("n=%d: cleanBuf difiere de clean (%d contra %d bytes)", n, len(got), len(want))
			}
		}
	}
	// sin borrados ni --More--: la vía rápida, con retornos de carro sueltos y dobles
	b := []byte(strings.Repeat("a\rb\r\r\nc\r\n\rd\n", 30<<10))
	if cleanBuf(b) != clean(string(b)) {
		t.Fatal("la vía rápida difiere de clean")
	}
	// una sola línea enorme sin saltos
	b = []byte(strings.Repeat("a\r --More-- ", 40<<10))
	if cleanBuf(b) != clean(string(b)) {
		t.Fatal("línea enorme sin saltos difiere")
	}
}

// Al cerrar un comando con mucha salida (hasta 64 MiB) el pico no es de 5 o 6 copias de la salida: se limpia por trozos y
// se convierte a string una sola vez. Con -race o -short, 8 MiB.
func TestCierreDeComandoGrandeNoMultiplicaLaMemoria(t *testing.T) {
	n := 64 << 20
	if raceOn || testing.Short() {
		n = 8 << 20
	}
	b := salidaConRuido(n, rand.New(rand.NewSource(2)), false) // una running-config: solo CRLF, sin --More-- ni borrados
	medir := func(f func() string) float64 {
		runtime.GC()
		var a, c runtime.MemStats
		runtime.ReadMemStats(&a)
		s := f()
		runtime.ReadMemStats(&c)
		runtime.KeepAlive(s)
		return float64(c.TotalAlloc-a.TotalAlloc) / float64(len(b))
	}
	viejo := medir(func() string { return clean(string(b)) })
	nuevo := medir(func() string { return cleanBuf(b) })
	t.Logf("n=%d: antes %.2f n, ahora %.2f n", len(b), viejo, nuevo)
	if nuevo > 2.5 {
		t.Errorf("el cierre asigna %.2f veces el tamaño de la salida (tope 2,5; antes %.2f)", nuevo, viejo)
	}
}
