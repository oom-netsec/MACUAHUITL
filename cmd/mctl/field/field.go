package field

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/oom-netsec/MACUAHUITL/cmd/mctl/cli"
	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const escKey = 0x1d // Ctrl-]

func consoleHelp() string { return cli.T("mctl.field.console_help") }

// escaper separa lo que va al equipo de las órdenes Ctrl-] <letra>.
type escaper struct{ pending bool }

// feed devuelve los bytes para el equipo y las órdenes: q (salir), b (BREAK), ? (ayuda).
func (e *escaper) feed(in []byte) (data, acts []byte) {
	for _, b := range in {
		switch {
		case !e.pending && b == escKey:
			e.pending = true
		case !e.pending:
			data = append(data, b)
		default:
			e.pending = false
			switch b {
			case escKey:
				data = append(data, escKey)
			case 'q', 'Q', '.':
				return data, append(acts, 'q')
			case 'b', 'B':
				acts = append(acts, 'b')
			default:
				acts = append(acts, '?')
			}
		}
	}
	return data, acts
}

func console(c *cli.Env, args []string) error {
	var baud, dataBits, stopBits int
	var parity, flow string
	var listOnly bool
	fs, err := cli.Flags("console", args, func(fs *flag.FlagSet) {
		fs.IntVar(&baud, "baud", 9600, "velocidad")
		fs.IntVar(&dataBits, "databits", 8, "bits de datos")
		fs.StringVar(&parity, "parity", "none", "paridad: none, even, odd")
		fs.IntVar(&stopBits, "stopbits", 1, "bits de parada")
		fs.StringVar(&flow, "flow", "none", "control de flujo: none, rtscts, xonxoff")
		fs.BoolVar(&listOnly, "list", false, "solo listar los puertos")
	})
	if err != nil {
		return err
	}
	port := fs.Arg(0)
	if port == "" || listOnly {
		r, err := v1.NewFieldServiceClient(c.Conn).ListSerialPorts(context.Background(), &v1.ListSerialPortsRequest{})
		if err != nil {
			return err
		}
		if listOnly || len(r.Ports) != 1 {
			for _, p := range r.Ports {
				fmt.Fprintln(c.Out, p)
			}
			if listOnly {
				return nil
			}
			if len(r.Ports) == 0 {
				return cli.Err("mctl.field.no_adapters")
			}
			return cli.Err("mctl.field.many_ports")
		}
		port = r.Ports[0]
	}
	st, err := v1.NewFieldServiceClient(c.Conn).Console(context.Background())
	if err != nil {
		return err
	}
	if err := st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Open{Open: &v1.ConsoleOpen{Port: port, Baud: int32(baud),
		DataBits: int32(dataBits), Parity: parity, StopBits: int32(stopBits), Flow: flow}}}); err != nil {
		return err
	}
	first, err := st.Recv()
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Out, "%s\r\n%s\r\n", cli.T("mctl.field.connected", "opened", first.Opened, "path", first.OutputPath), consoleHelp())
	if c.TTY != nil { // modo crudo: cada tecla viaja al equipo sin eco local
		old, err := term.MakeRaw(int(c.TTY.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(c.TTY.Fd()), old)
	}
	recvDone := make(chan error, 1)
	go func() {
		for {
			r, err := st.Recv()
			if err != nil {
				recvDone <- err
				return
			}
			c.Out.Write(r.Data)
		}
	}()
	keys := make(chan []byte)
	go func() { // stdin bloquea: va aparte para salir si el puerto se pierde
		defer close(keys)
		buf := make([]byte, 1024)
		for {
			n, err := c.In.Read(buf)
			if n > 0 {
				keys <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()
	var esc escaper
	for {
		select {
		case err := <-recvDone:
			if err == io.EOF {
				return nil
			}
			return err
		case k, ok := <-keys:
			if !ok {
				st.CloseSend()
				return endConsole(c, recvDone)
			}
			data, acts := esc.feed(k)
			if len(data) > 0 {
				st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_Data{Data: data}})
			}
			for _, a := range acts {
				switch a {
				case 'q':
					st.CloseSend()
					return endConsole(c, recvDone)
				case 'b':
					st.Send(&v1.ConsoleRequest{Msg: &v1.ConsoleRequest_SendBreak{SendBreak: true}})
					fmt.Fprint(c.Out, "\r\n["+cli.T("mctl.field.break_sent")+"]\r\n")
				case '?':
					fmt.Fprint(c.Out, "\r\n["+consoleHelp()+"]\r\n")
				}
			}
		}
	}
}

func endConsole(c *cli.Env, recvDone chan error) error {
	err := <-recvDone
	fmt.Fprint(c.Out, "\r\n["+cli.T("mctl.field.console_close")+"]\r\n")
	if err == io.EOF {
		return nil
	}
	return err
}

func serve(proto string) func(*cli.Env, []string) error {
	return func(c *cli.Env, args []string) error {
		var addr string
		var files cli.List
		var any bool
		var secs int
		fs, err := cli.Flags("serve "+proto, args, func(fs *flag.FlagSet) {
			fs.StringVar(&addr, "addr", "", "IP:PUERTO de escucha (o solo IP)")
			fs.Var(&files, "file", "archivo a publicar (repetible)")
			fs.BoolVar(&any, "any", false, "escuchar en todas las interfaces")
			fs.IntVar(&secs, "for", 0, "segundos (0 = 1 h; máximo 24 h)")
		})
		if err != nil {
			return err
		}
		var abs []string
		for _, f := range append(files, fs.Args()...) {
			p, err := filepath.Abs(f)
			if err != nil {
				return err
			}
			abs = append(abs, p)
		}
		st, err := v1.NewFieldServiceClient(c.Conn).ServeFiles(context.Background(), &v1.ServeFilesRequest{Protocol: proto, Addr: addr, AllowAny: any, Files: abs, DurationSeconds: int32(secs)})
		if err != nil {
			return err
		}
		for {
			r, err := st.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if r.Listening != "" {
				fmt.Fprintf(c.Out, "%s\n%s", cli.T("mctl.field.serving", "listen", r.Listening, "proto", proto), r.Hint)
				continue
			}
			var t struct {
				Client, File, Result, Error string
				Bytes                       int64
				Duration                    time.Duration
			}
			json.Unmarshal([]byte(r.TransferJson), &t)
			fmt.Fprintf(c.Out, "%s  %s  %s  %d bytes  %s  %s %s\n", time.Now().Format("15:04:05"), t.Client, t.File, t.Bytes, t.Duration.Round(time.Millisecond), t.Result, t.Error)
		}
	}
}

func hash(c *cli.Env, args []string) error {
	var md5, sha string
	fs, err := cli.Flags("hash", args, func(fs *flag.FlagSet) {
		fs.StringVar(&md5, "md5", "", "MD5 publicado por Cisco")
		fs.StringVar(&sha, "sha512", "", "SHA-512 publicado por Cisco")
	})
	if err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: mctl hash ARCHIVO [--md5 VALOR] [--sha512 VALOR]")
	}
	p, err := filepath.Abs(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := v1.NewFieldServiceClient(c.Conn).HashFile(context.Background(), &v1.HashFileRequest{Path: p, Md5: strings.TrimSpace(md5), Sha512: strings.TrimSpace(sha)})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.Out, r.Report.Text)
	if !r.Ok {
		return cli.Err("mctl.field.hash_mismatch")
	}
	return nil
}

// help son las líneas de este área en mctl --help.
const help = `  console [PUERTO] [--baud N] [--parity none|even|odd] [--flow none|rtscts|xonxoff] [--list]
        (Ctrl-] q sale, Ctrl-] b envía BREAK; se graba en outputs/console)
  serve tftp|http --addr IP[:PUERTO] --file RUTA... [--for SEGUNDOS] [--any]
        (TFTP en 6969: IOS usa el 69, redirige con nftables; HTTP en 8080)
  hash  ARCHIVO [--md5 VALOR] [--sha512 VALOR]`

// Area registra console (sesión cruda), serve y hash.
func Area() cli.Area {
	return cli.Area{Usage: help, Commands: []cli.Command{
		{Name: "console", Run: console, Raw: true},
		{Name: "serve tftp", Run: serve("tftp")},
		{Name: "serve http", Run: serve("http")},
		{Name: "hash", Run: hash},
	}}
}
