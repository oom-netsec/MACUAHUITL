package transfer

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

// progressEvery es cada cuánto `transfer serve` consulta el avance (plan 45b, decisión 12); las pruebas lo reducen.
var progressEvery = 5 * time.Second

// clean cambia los controles (\p{Cc}) y los caracteres de formato (\p{Cf}) por «?»: un nombre crudo (el de un paquete UDP)
// con secuencias ANSI o U+202E no debe escribirle a la terminal. Local porque cmd/mctl no puede importar internal/diag
// (trae net); es la misma regla que SanitizeName del núcleo.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.In(r, unicode.Cc, unicode.Cf) {
			return '?'
		}
		return r
	}, s)
}

// sessionLine: ESTADO  SERVIDOR  PROTO  CLIENTE  in|out  NOMBRE  bytes/total (pct)  tasa  [motivo]
func sessionLine(s *v1.TransferSession) string {
	prog := fmt.Sprintf("%d/%d", s.Bytes, s.Total)
	if s.Total > 0 {
		prog += fmt.Sprintf(" (%d%%)", s.Bytes*100/s.Total)
	}
	f := []string{clean(s.State), clean(s.ServerId), clean(s.Protocol), clean(s.Client), clean(s.Direction), clean(s.Name), prog, fmt.Sprintf("%.0f B/s", s.BytesPerSec)}
	if s.Error != "" {
		f = append(f, clean(s.Error))
	}
	return strings.Join(f, "  ")
}

// renderStatus imprime las sesiones y, debajo, los rechazos agrupados.
func renderStatus(w io.Writer, r *v1.ListTransferSessionsResponse, now time.Time) {
	if len(r.Sessions) == 0 && len(r.Rejections) == 0 {
		fmt.Fprintln(w, cli.T("mctl.transfer.status_none"))
		return
	}
	for _, s := range r.Sessions {
		fmt.Fprintln(w, sessionLine(s))
	}
	if len(r.Rejections) == 0 {
		return
	}
	fmt.Fprintln(w, cli.T("mctl.transfer.rejections_header"))
	for _, j := range r.Rejections {
		ago := max(now.UnixMilli()-j.Last, 0) / 1000
		fmt.Fprintf(w, "%s  %s  %s  ×%d  %s  %s\n", clean(j.Ip), clean(j.Protocol), clean(j.Cause), j.Count, cli.T("mctl.transfer.ago", "n", ago), clean(j.Name))
	}
}

func status(c *cli.Env, args []string) error {
	var asJSON bool
	fs, err := cli.Flags("transfer status", args, func(fs *flag.FlagSet) { fs.BoolVar(&asJSON, "json", false, "salida JSON") })
	if err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return cli.Err("mctl.transfer.status_usage")
	}
	r, err := v1.NewTransferServiceClient(c.Conn).ListTransferSessions(context.Background(), &v1.ListTransferSessionsRequest{ServerId: fs.Arg(0)})
	if err != nil {
		return err
	}
	if asJSON {
		b, err := protojson.MarshalOptions{Indent: "  ", EmitUnpopulated: true}.Marshal(r)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.Out, string(b))
		return nil
	}
	renderStatus(c.Out, r, time.Now())
	return nil
}

// transferEvent es el JSON que el núcleo manda por transferencia terminada.
type transferEvent struct {
	Proto, Dir, DirCode, Client, File, Path, SHA256, Result, Error string
	Bytes                                                          int64
	Duration                                                       time.Duration
	Rejected                                                       bool
}

// serveLine es la línea de fin de cada sesión; el sentido y el resultado salen en el idioma de mctl y el nombre, saneado.
func serveLine(t transferEvent, at time.Time, tr func(string, ...any) string) string {
	code := t.DirCode
	switch {
	case code != "":
	case t.Dir == "lectura":
		code = "read"
	case t.Dir == "escritura":
		code = "write"
	}
	dir := clean(t.Dir)
	if code == "read" || code == "write" {
		dir = tr("mctl.transfer.dir." + code)
	}
	res := clean(t.Result)
	if t.Result == "ok" || t.Result == "error" {
		res = tr("mctl.transfer.result." + t.Result)
	}
	mark := ""
	if t.Rejected {
		mark = tr("mctl.transfer.rejected")
	}
	return fmt.Sprintf("%s  %s %s %s  %s  %d bytes  %s  %s %s%s", at.Format("15:04:05"), clean(t.Proto), dir, clean(t.Client), clean(t.File), t.Bytes, t.Duration.Round(time.Millisecond), res, clean(t.Error), mark)
}

// progressLoop imprime una línea `progreso` (word, ya en el idioma de mctl: no toca el idioma global desde otra goroutine) por sesión activa cada `every`, hasta que ctx termina. Un error de la consulta
// no corta nada: el siguiente ciclo lo reintenta. out ya viene serializado con el bucle del stream (lockedWriter).
func progressLoop(ctx context.Context, word string, every time.Duration, list func() (*v1.ListTransferSessionsResponse, error), out io.Writer) {
	tk := time.NewTicker(every)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
		r, err := list()
		if err != nil {
			continue
		}
		for _, s := range r.Sessions {
			if s.State == "active" {
				fmt.Fprintln(out, word+"  "+sessionLine(s))
			}
		}
	}
}

// lockedWriter serializa las escrituras de dos goroutines (cada Fprintln es una sola Write).
type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}
