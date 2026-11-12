// Package diag invoca ping, traceroute, nmap, iperf3 y dumpcap del sistema con
// argumentos validados y sin shell (spec §6.1, §9).
//
// No hace: correr como root ni incluir código privilegiado. nmap SYN y dumpcap
// dependen de las capacidades que el administrador les dé (ADR 0004).
package diag

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrNotInstalled = errors.New("diag: herramienta no instalada")

var packages = map[string]string{
	"ping": "iputils-ping", "traceroute": "traceroute", "tracepath": "iputils-tracepath",
	"nmap": "nmap", "iperf3": "iperf3", "dumpcap": "wireshark-common (y agrega tu usuario al grupo wireshark)",
}

type Result struct {
	ExitCode   int
	OutputPath string
	Bin        string   // binario que se ejecutó de verdad (p. ej. tracepath en vez de traceroute)
	Argv       []string // argv completo, incluido -w para la captura
}

// Runner ejecuta herramientas. LookPath nil usa exec.LookPath.
type Runner struct {
	LookPath func(string) (string, error)
	extraEnv []string // solo pruebas
}

func (r Runner) look(name string) (string, error) {
	lp := r.LookPath
	if lp == nil {
		lp = exec.LookPath
	}
	return lp(name)
}

// Run ejecuta la petición, manda cada línea de salida a onLine y guarda el resultado en
// OutputDir (texto, o .pcapng para la captura). Cancelar ctx termina el proceso.
func (r Runner) Run(ctx context.Context, req Request, onLine func(string)) (Result, error) {
	bin, argv, err := Build(req)
	if err != nil {
		return Result{}, fmt.Errorf("diag: %w", err)
	}
	if bin == "traceroute" {
		if _, err := r.look("traceroute"); err != nil {
			bin = "tracepath" // sin privilegios, siempre presente; acepta las mismas banderas -n -m
		}
	}
	path, err := r.look(bin)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s (instala: sudo apt install %s)", ErrNotInstalled, bin, packages[bin])
	}
	stamp := time.Now().Format("20060102-150405")
	var out *os.File
	res := Result{Bin: bin}
	if req.OutputDir != "" {
		if err := os.MkdirAll(req.OutputDir, 0o700); err != nil {
			return Result{}, fmt.Errorf("diag: %w", err)
		}
		ext := ".txt"
		if req.Tool == Pcap {
			ext = ".pcapng"
		}
		// Nombre único aunque dos ejecuciones caigan en el mismo segundo; el archivo lo crea
		// el núcleo con 0600 (también el pcap: dumpcap solo lo trunca y no sigue symlinks).
		if out, err = os.CreateTemp(req.OutputDir, fmt.Sprintf("diag_%s_%s_*%s", req.Tool, stamp, ext)); err != nil {
			return Result{}, fmt.Errorf("diag: %w", err)
		}
		res.OutputPath = out.Name()
		if req.Tool == Pcap {
			out.Close()
			out = nil
			argv = append(argv, "-w", res.OutputPath)
		} else {
			defer out.Close()
		}
	}
	res.Argv = argv

	cmd := exec.CommandContext(ctx, path, argv...)
	cmd.Env = append([]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C"}, r.extraEnv...)
	// Grupo de procesos propio: al cancelar, la señal alcanza también a los hijos de la
	// herramienta, que si no heredarían la tubería y la dejarían abierta.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 3 * time.Second // tras SIGTERM, SIGKILL al grupo entero y cierre de tuberías
	cmd.Cancel = func() error {
		pgid := -cmd.Process.Pid
		time.AfterFunc(cmd.WaitDelay, func() { syscall.Kill(pgid, syscall.SIGKILL) })
		return syscall.Kill(pgid, syscall.SIGTERM)
	}
	var mu sync.Mutex
	emit := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		onLine(line)
		if out != nil {
			out.WriteString(line + "\n")
		}
	}
	// Escritores propios en vez de StdoutPipe: así Wait espera a que toda la salida se haya
	// copiado y, si un hijo retiene la tubería, la cierra tras WaitDelay. dumpcap escribe el
	// pcap en el archivo (-w) y el progreso en stderr; stdout queda vacío.
	so, se := &lineWriter{emit: emit}, &lineWriter{emit: emit}
	cmd.Stdout, cmd.Stderr = so, se
	if err := cmd.Start(); err != nil {
		if res.OutputPath != "" {
			os.Remove(res.OutputPath)
		}
		return Result{}, fmt.Errorf("diag: %w", err)
	}
	err = cmd.Wait()
	so.flush()
	se.flush()
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
		if res.ExitCode < 0 {
			res.ExitCode = 143 // terminado por señal
		}
	default:
		return res, fmt.Errorf("diag: %w", err)
	}
	return res, nil
}

// lineWriter parte lo que escribe el proceso en líneas completas; sin límite de largo
// (nmap -oG pone todos los puertos de un host en una sola línea).
type lineWriter struct {
	emit func(string)
	buf  []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			return len(p), nil
		}
		w.emit(strings.TrimRight(string(w.buf[:i]), "\r"))
		w.buf = w.buf[i+1:]
	}
}

func (w *lineWriter) flush() {
	if len(w.buf) > 0 {
		w.emit(strings.TrimRight(string(w.buf), "\r"))
		w.buf = nil
	}
}
