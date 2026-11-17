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
	"strconv"
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

// Límites del ping continuo (Review Focus 2): el tope de seguridad vale para todo ping.
var (
	pingMaxRun  = 24 * time.Hour
	pingMaxSent = int64(86400)
)

// pingLimits es la duración total pedida (option duration del PingPlan); 0 = sin ella. Build ya la validó.
func pingLimits(r Request) time.Duration {
	p, err := Plan(r)
	if err != nil {
		return 0
	}
	return time.Duration(p.Duration) * time.Second
}

// goos es el sistema en el que corre Run; las pruebas lo cambian para ejercitar el comportamiento de Windows.
var goos = runtime.GOOS

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
	// OnSweep recibe el resultado de cada tamaño del barrido de ping.
	OnSweep func(SweepPoint)

	// Solo sweep: la duración y el tope de envíos son del barrido entero, no de cada ping.
	sweepHalt func()
	sentBase  int64
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
	bin, argv, plan, err := buildPlan(req, runtime.GOOS == "windows")
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

	if req.Tool == Ping {
		if plan.Sweep != nil {
			return r.sweep(ctx, req, path, argv, *plan.Sweep, out, res, onLine)
		}
		stats := NewPingStats(goos == "windows")
		code, err := r.exec(ctx, req, path, argv, out, res.OutputPath, stats, onLine)
		sum := stats.Summary()
		res.ExitCode, res.Ping = code, &sum
		return res, err
	}
	code, err := r.exec(ctx, req, path, argv, out, res.OutputPath, nil, onLine)
	res.ExitCode = code
	return res, err
}

// SweepPoint es el resultado de un tamaño del barrido: ok (volvieron todas), frag (el sistema pidió fragmentar con DF) o loss.
type SweepPoint struct {
	Size           int
	Sent, Received int64
	Result         string
}

// sweepArgv inserta el tamaño antes del host (último argumento) y vuelve a pasar el argv por checkFlagLike.
func sweepArgv(argv []string, size int, win bool) ([]string, error) {
	flag := "-s"
	if win {
		flag = "-l"
	}
	n := len(argv) - 1
	a := append(append(append([]string{}, argv[:n]...), flag, strconv.Itoa(size)), argv[n])
	if err := checkFlagLike("ping", a, win); err != nil {
		return nil, i18n.Wrap("diag.err.wrap", err, nil)
	}
	return a, nil
}

func (r Runner) stopped() bool {
	select {
	case <-r.Stop:
		return true
	default:
		return false
	}
}

// sweep corre un ping por tamaño y manda un SweepPoint por cada uno; el resumen es el total. Stop interrumpe el ping
// en curso (cuyo punto no se manda, quedó incompleto) y el resumen cubre lo alcanzado.
func (r Runner) sweep(ctx context.Context, req Request, path string, argv []string, sw Sweep, out *os.File, res Result, onLine func(string)) (Result, error) {
	stop := make(chan struct{})
	var once sync.Once
	halt := func() { once.Do(func() { close(stop) }) }
	defer halt()
	d := pingMaxRun
	if want := pingLimits(req); want > 0 {
		d = min(d, want)
	}
	defer time.AfterFunc(d, halt).Stop()
	go func(user <-chan struct{}) {
		select {
		case <-user:
			halt()
		case <-stop:
		}
	}(r.Stop)
	if r.stopped() { // un Stop ya cerrado se ve de inmediato, sin esperar a la goroutine
		halt()
	}
	r.Stop, r.sweepHalt = stop, halt
	win := runtime.GOOS == "windows"
	total := NewPingStats(goos == "windows")
	for i, size := range sw.Sizes() {
		if r.stopped() || ctx.Err() != nil {
			break
		}
		// Un tamaño que no arranca borra el .txt solo si todavía no tiene nada.
		outPath := res.OutputPath
		if i > 0 {
			outPath = ""
		}
		a, err := sweepArgv(argv, size, win)
		if err != nil {
			discard(out, outPath)
			return res, err
		}
		stats := NewPingStats(goos == "windows")
		r.sentBase = total.Summary().Sent
		if _, err := r.exec(ctx, req, path, a, out, outPath, stats, onLine); err != nil {
			return res, err
		}
		if r.stopped() || ctx.Err() != nil { // el ping interrumpido no entra al resumen ni manda punto
			break
		}
		s := stats.Summary()
		total.Add(stats)
		pt := SweepPoint{Size: size, Sent: s.Sent, Received: s.Received, Result: "loss"}
		switch {
		case s.Sent > 0 && s.Received >= s.Sent:
			pt.Result = "ok"
		case stats.Frag():
			pt.Result = "frag"
		}
		if r.OnSweep != nil {
			r.OnSweep(pt)
		}
	}
	sum := total.Summary()
	res.Ping = &sum
	switch {
	case ctx.Err() != nil:
		res.ExitCode = 143 // cancelado: como un ping suelto terminado por señal
	case sum.Received == 0:
		res.ExitCode = 1
	}
	return res, nil
}

// exec corre un proceso y manda sus líneas a onLine y a out; cuenta las respuestas en stats (nil si no es ping).
// Devuelve el código de salida. Si no arranca, borra el archivo de salida.
func (r Runner) exec(ctx context.Context, req Request, path string, argv []string, out *os.File, outPath string, stats *PingStats, onLine func(string)) (int, error) {
	cmd := exec.CommandContext(ctx, path, argv...)
	cmd.Env = append(childEnv(path), r.extraEnv...)
	// El hijo y sus nietos se cancelan juntos (grupo de procesos en Linux, Job Object en Windows).
	started, done, err := confine(cmd)
	if err != nil {
		discard(out, outPath)
		return 0, i18n.Wrap("diag.err.wrap", err, nil)
	}
	defer done()
	var mu sync.Mutex
	stopc := make(chan struct{}) // lo cierran Stop, la duración o el tope de envíos
	var stopOnce sync.Once
	stopNow := func() { stopOnce.Do(func() { close(stopc) }) }
	emit := func(line string) {
		mu.Lock()
		defer mu.Unlock()
		if stats != nil && r.sentBase+stats.Feed(line) >= pingMaxSent {
			stopNow()
			if r.sweepHalt != nil {
				r.sweepHalt()
			}
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
		discard(out, outPath)
		return 0, i18n.Wrap("diag.err.wrap", err, nil)
	}
	if err := started(); err != nil {
		cmd.Wait()
		discard(out, outPath)
		return 0, i18n.Wrap("diag.err.wrap", err, nil)
	}
	finished := make(chan struct{})
	if stats != nil && r.sweepHalt == nil {
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
	var ee *exec.ExitError
	code := 0
	select {
	case <-stopc:
		if stats != nil && goos == "windows" { // el Job Object sale con 143: tras una parada pedida es éxito, como iputils
			mu.Lock()
			rcv := stats.Summary().Received
			mu.Unlock()
			if rcv > 0 {
				return 0, nil
			}
			return 1, nil
		}
	default:
	}
	switch {
	case err == nil:
	case errors.As(err, &ee):
		code = ee.ExitCode()
		if code < 0 {
			code = 143 // terminado por señal
		}
	default:
		return 0, i18n.Wrap("diag.err.wrap", err, nil)
	}
	return code, nil
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
