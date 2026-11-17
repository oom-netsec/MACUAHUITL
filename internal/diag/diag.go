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
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var ErrNotInstalled error = i18n.New("diag.err.not_installed", nil)

var packages = map[string]string{
	"ping": "iputils-ping", "traceroute": "traceroute", "tracepath": "iputils-tracepath",
	"nmap": "nmap", "iperf3": "iperf3", "dumpcap": "wireshark-common (y agrega tu usuario al grupo wireshark)",
}

type Result struct {
	ExitCode   int
	OutputPath string
	Bin        string       // binario que se ejecutó de verdad (p. ej. tracepath en vez de traceroute)
	Argv       []string     // argv completo, incluido -w para la captura
	Ping       *PingSummary // solo ping: resumen calculado de las respuestas
}

// Límites del ping continuo (Review Focus 2). pingLimits devuelve la duración total pedida (0 = sin ella);
// shortcut: devuelve los valores fijos hasta que 200-2 lo reemplace por el PingPlan (duration y continuous).
var (
	pingMaxRun  = 24 * time.Hour
	pingMaxSent = int64(86400)
	pingLimits  = func(Request) (duration time.Duration) { return 0 }
)

// iperfServerMax es el tope de vida del servidor de iperf3 (-s -1 espera un cliente indefinidamente).
var iperfServerMax = 10 * time.Minute

// discard cierra el .txt y lo borra (en Windows no se borra un archivo abierto).
func discard(out *os.File, path string) {
	if out != nil {
		out.Close()
	}
	if path != "" {
		os.Remove(path)
	}
}

// Runner ejecuta herramientas. LookPath nil usa exec.LookPath en Linux y winLook (rutas absolutas conocidas) en Windows.
type Runner struct {
	LookPath func(string) (string, error)
	extraEnv []string // solo pruebas
	// Stop, al cerrarse, detiene la herramienta de forma ordenada (SIGINT en Linux: ping imprime su resumen y
	// sale) y Run vuelve con el resultado; cancelar ctx, en cambio, la mata sin más.
	Stop <-chan struct{}
}

func (r Runner) look(name string) (string, error) {
	lp := r.LookPath
	if lp == nil {
		lp = lookPath // Linux: PATH del sistema; Windows: rutas absolutas conocidas (ADR 0012, f)
	}
	return lp(name)
}

// Run ejecuta la petición, manda cada línea de salida a onLine y guarda el resultado en
// OutputDir (texto, o .pcapng para la captura). Cancelar ctx termina el proceso.
func (r Runner) Run(ctx context.Context, req Request, onLine func(string)) (Result, error) {
	bin, argv, err := Build(req)
	if err != nil {
		return Result{}, i18n.Wrap("diag.err.wrap", err, nil)
	}
	if bin == "traceroute" { // en Windows Build ya devolvió tracert
		if _, err := r.look("traceroute"); err != nil {
			bin = "tracepath" // sin privilegios, siempre presente; acepta las mismas banderas -n -m
		}
	}
	path, err := r.look(bin)
	if err != nil {
		return Result{}, installErr(runtime.GOOS, bin)
	}
	stamp := time.Now().Format("20060102-150405")
	var out *os.File
	res := Result{Bin: bin}
	if req.OutputDir != "" {
		if err := os.MkdirAll(req.OutputDir, 0o700); err != nil {
			return Result{}, i18n.Wrap("diag.err.wrap", err, nil)
		}
		ext := ".txt"
		if req.Tool == Pcap {
			ext = ".pcapng"
		}
		// Nombre único aunque dos ejecuciones caigan en el mismo segundo; el archivo lo crea
		// el núcleo con 0600 (también el pcap: dumpcap solo lo trunca y no sigue symlinks).
		if out, err = os.CreateTemp(req.OutputDir, fmt.Sprintf("diag_%s_%s_*%s", req.Tool, stamp, ext)); err != nil {
			return Result{}, i18n.Wrap("diag.err.wrap", err, nil)
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
	if req.Tool == Iperf3 && argv[0] == "-s" { // un servidor olvidado no debe quedar escuchando
		var stop context.CancelFunc
		ctx, stop = context.WithTimeout(ctx, iperfServerMax)
		defer stop()
	}

	cmd := exec.CommandContext(ctx, path, argv...)
	cmd.Env = append(childEnv(path), r.extraEnv...)
	// El hijo y sus nietos se cancelan juntos (grupo de procesos en Linux, Job Object en Windows).
	started, done, err := confine(cmd)
	if err != nil {
		discard(out, res.OutputPath)
		return Result{}, i18n.Wrap("diag.err.wrap", err, nil)
	}
	defer done()
	var mu sync.Mutex
	stopc := make(chan struct{}) // lo cierran Stop, la duración o el tope de envíos
	var stopOnce sync.Once
	stopNow := func() { stopOnce.Do(func() { close(stopc) }) }
	var stats *PingStats
	if req.Tool == Ping {
		stats = NewPingStats(runtime.GOOS == "windows")
	}
	emit := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		if stats != nil && stats.Feed(line) >= pingMaxSent {
			stopNow()
		}
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
		discard(out, res.OutputPath)
		return Result{}, i18n.Wrap("diag.err.wrap", err, nil)
	}
	if err := started(); err != nil {
		cmd.Wait()
		discard(out, res.OutputPath)
		return Result{}, i18n.Wrap("diag.err.wrap", err, nil)
	}
	finished := make(chan struct{})
	if stats != nil {
		d := pingMaxRun
		if want := pingLimits(req); want > 0 {
			d = min(d, want)
		}
		defer time.AfterFunc(d, stopNow).Stop()
	}
	go func() {
		select {
		case <-r.Stop:
			stopNow()
		case <-stopc:
		case <-finished:
			return
		}
		select {
		case <-finished:
			return
		default:
		}
		interrupt(cmd)
		select { // si no sale sola, se cancela como siempre
		case <-finished:
		case <-time.After(3 * time.Second):
			cmd.Cancel()
		}
	}()
	err = cmd.Wait()
	close(finished)
	so.flush()
	se.flush()
	if stats != nil {
		mu.Lock()
		sum := stats.Summary()
		mu.Unlock()
		res.Ping = &sum
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &ee):
		res.ExitCode = ee.ExitCode()
		if res.ExitCode < 0 {
			res.ExitCode = 143 // terminado por señal
		}
	default:
		return res, i18n.Wrap("diag.err.wrap", err, nil)
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
