package metrics

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// limites fija los topes de lectura durante la prueba.
func limites(t *testing.T, file, total int64) {
	t.Helper()
	f, tt := maxFile, maxTotal
	maxFile, maxTotal = file, total
	t.Cleanup(func() { maxFile, maxTotal, readHook = f, tt, nil })
}

func escribe(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// dosEquipos deja SW1 (normal, 3 rondas) y GRANDE (un archivo de relleno por encima del tope).
func dosEquipos(t *testing.T) string {
	dir := writeJob(t,
		round{n: 1, cpu: cpuText(5, 4, 3), mem: memText},
		round{n: 2, cpu: cpuText(6, 4, 3), mem: memText},
		round{n: 3, cpu: cpuText(7, 4, 3), mem: memText})
	big := header(at(1), "show processes cpu sorted") + cpuText(1, 1, 1) + strings.Repeat("relleno relleno relleno\n", 400)
	escribe(t, filepath.Join(dir, "GRANDE_10.0.0.2", "r001_20261106-100000.txt"), big)
	return dir
}

func TestArchivoGrandeEsAvisoDelEquipoNoFallaTodo(t *testing.T) {
	dir := dosEquipos(t)
	limites(t, 4096, 1<<30)
	res, err := Build(dir, Options{})
	if err != nil {
		t.Fatalf("un archivo grande no debe abortar el trabajo: %v", err)
	}
	var ok, grande *Device
	for i := range res.Devices {
		switch res.Devices[i].Hostname {
		case "SW1":
			ok = &res.Devices[i]
		case "GRANDE":
			grande = &res.Devices[i]
		}
	}
	if ok == nil || len(ok.CPU) != 3 {
		t.Fatalf("el equipo normal sale con sus series: %+v", res.Devices)
	}
	if grande == nil || len(grande.CPU) != 0 || !strings.Contains(strings.Join(grande.Warnings, "|"), "supera") {
		t.Fatalf("el equipo grande sale con un aviso: %+v", grande)
	}
	// el estado de puertos de uno normal tampoco falla por el otro
	if _, err := PortsFromJob(dir, "SW1"); err != nil {
		t.Fatalf("puertos: %v", err)
	}
	pd, err := PortsFromJob(dir, "GRANDE")
	if err != nil || !strings.Contains(strings.Join(pd.Warnings, "|"), "supera") {
		t.Fatalf("puertos del grande: %+v %v", pd, err)
	}
}

func TestTopeDeTextoEsPorEquipo(t *testing.T) {
	dir := dosEquipos(t)
	// cada archivo de SW1 pesa unos 200 B; GRANDE queda fuera por su tope de archivo, no por el total
	limites(t, 4096, 300)
	res, err := Build(dir, Options{Device: "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	d := res.Devices[0]
	if len(d.CPU) == 3 || !strings.Contains(strings.Join(d.Warnings, "|"), "tope") {
		t.Fatalf("pasado el tope del equipo se avisa y se detiene: cpu=%d %v", len(d.CPU), d.Warnings)
	}
}

func TestPedirUnEquipoNoLeeLosDemas(t *testing.T) {
	dir := dosEquipos(t)
	var leidos []string
	t.Cleanup(func() { readHook = nil })
	readHook = func(p string) { leidos = append(leidos, p) }
	if _, err := Build(dir, Options{Device: "SW1"}); err != nil {
		t.Fatal(err)
	}
	if len(leidos) != 3 {
		t.Fatalf("leyó %v", leidos)
	}
	for _, p := range leidos {
		if strings.Contains(p, "GRANDE") {
			t.Fatalf("leyó un archivo de otro equipo: %s", p)
		}
	}
	leidos = nil
	if _, err := PortsFromJob(dir, "GRANDE"); err != nil {
		t.Fatal(err)
	}
	for _, p := range leidos {
		if strings.Contains(p, "SW1") {
			t.Fatalf("puertos leyó otro equipo: %s", p)
		}
	}
}

func TestPuertosLeeSoloLaUltimaRonda(t *testing.T) {
	dir := t.TempDir()
	dd := filepath.Join(dir, "SW1_10.0.0.1")
	st := "Port      Name               Status       Vlan       Duplex  Speed Type\nGi1/0/1   a                  connected    1          a-full  a-1000 10/100/1000BaseTX\n"
	// 1000 rondas: «r1000» ordena antes que «r999» como texto
	for _, n := range []int{1, 2, 999, 1000} {
		escribe(t, filepath.Join(dd, fmt.Sprintf("r%03d_x.txt", n)),
			header(at(1).Add(time.Duration(n)*time.Minute), CmdPortStatus)+st+
				header(at(1).Add(time.Duration(n)*time.Minute), CmdTrunk)+"Port Mode Encapsulation Status Native vlan\nGi1/0/1 on 802.1q trunking 1\n"+
				header(at(1).Add(time.Duration(n)*time.Minute), CmdChannels)+"Number of channel-groups in use: 0\nNumber of aggregators:           0\n")
	}
	var leidos []string
	t.Cleanup(func() { readHook = nil })
	readHook = func(p string) { leidos = append(leidos, filepath.Base(p)) }
	pd, err := PortsFromJob(dir, "")
	if err != nil || len(pd.Ports) != 1 {
		t.Fatalf("%+v %v", pd, err)
	}
	if len(leidos) != 1 || leidos[0] != "r1000_x.txt" {
		t.Fatalf("debía leer solo la última ronda: %v", leidos)
	}
}

func TestPuertosSinTrunkBuscaPocosArchivosAtras(t *testing.T) {
	dir := t.TempDir()
	st := "Port      Name               Status       Vlan       Duplex  Speed Type\nGi1/0/1   a                  connected    1          a-full  a-1000 10/100/1000BaseTX\n"
	for n := 1; n <= 8; n++ {
		escribe(t, filepath.Join(dir, "SW1_10.0.0.1", fmt.Sprintf("r%03d_x.txt", n)), header(at(n), CmdPortStatus)+st)
	}
	var leidos int
	t.Cleanup(func() { readHook = nil })
	readHook = func(string) { leidos++ }
	pd, err := PortsFromJob(dir, "")
	if err != nil || len(pd.Ports) != 1 || leidos != portLookback {
		t.Fatalf("leyó %d archivos (quería %d): %+v %v", leidos, portLookback, pd, err)
	}
}

func TestEnlacesSimbolicosNoSeLeen(t *testing.T) {
	dir := writeJob(t, round{n: 1, cpu: cpuText(5, 4, 3)})
	fuera := filepath.Join(t.TempDir(), "secreto.txt")
	escribe(t, fuera, header(at(2), "show processes cpu sorted")+cpuText(99, 99, 99))
	if err := os.Symlink(fuera, filepath.Join(dir, "SW1_10.0.0.1", "r002_enlace.txt")); err != nil {
		t.Fatal(err)
	}
	// una carpeta de equipo que es un enlace tampoco
	if err := os.Symlink(filepath.Dir(fuera), filepath.Join(dir, "SW9_10.0.0.9")); err != nil {
		t.Fatal(err)
	}
	res, err := Build(dir, Options{})
	if err != nil || len(res.Devices) != 1 || len(res.Devices[0].CPU) != 1 || res.Devices[0].CPU[0].Five != 5 {
		t.Fatalf("%+v %v", res.Devices, err)
	}
}

func TestEquipoIPv6SaleDelManifest(t *testing.T) {
	dir := t.TempDir()
	// Patrol cambia los «:» por «_»: la carpeta no se puede deshacer
	escribe(t, filepath.Join(dir, "SW6_2001_db8__1", "r001_x.txt"), header(at(1), "show processes cpu sorted")+cpuText(5, 4, 3))
	escribe(t, filepath.Join(dir, "manifest.json"), `{"devices":[{"Target":{"Address":"2001:db8::1"},"Hostname":"SW6","State":"completed"}]}`)
	res, err := Build(dir, Options{Device: "2001:db8::1"})
	if err != nil || len(res.Devices) != 1 || res.Devices[0].Address != "2001:db8::1" || res.Devices[0].Hostname != "SW6" || len(res.Devices[0].CPU) != 1 {
		t.Fatalf("%+v %v", res.Devices, err)
	}
	st := "Port      Name               Status       Vlan       Duplex  Speed Type\nGi1/0/1   a                  connected    1          a-full  a-1000 10/100/1000BaseTX\n"
	escribe(t, filepath.Join(dir, "SW6_2001_db8__1", "r002_x.txt"), header(at(2), CmdPortStatus)+st)
	pd, err := PortsFromJob(dir, "2001:db8::1")
	if err != nil || pd.Address != "2001:db8::1" || pd.Hostname != "SW6" {
		t.Fatalf("%+v %v", pd, err)
	}
}
