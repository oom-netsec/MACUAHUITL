package fileserve

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	opRRQ   = 1
	opWRQ   = 2
	opDATA  = 3
	opACK   = 4
	opERROR = 5
	opOACK  = 6
)

type request struct {
	op   uint16
	file string
	opts [][2]string // en el orden recibido; nombres en minúsculas
}

// parseRequest interpreta RRQ/WRQ: op, archivo\0, modo\0, [opción\0valor\0]*.
func parseRequest(b []byte) (request, error) {
	if len(b) < 4 {
		return request{}, errors.New("corto")
	}
	r := request{op: binary.BigEndian.Uint16(b)}
	if r.op != opRRQ && r.op != opWRQ {
		return request{}, errors.New("no es una solicitud")
	}
	f := bytes.Split(b[2:], []byte{0})
	if len(f) < 3 || len(f[len(f)-1]) != 0 { // debe terminar en \0
		return request{}, errors.New("mal terminada")
	}
	f = f[:len(f)-1]
	mode := strings.ToLower(string(f[1]))
	if mode != "octet" && mode != "netascii" {
		return request{}, errors.New("modo")
	}
	r.file = string(f[0])
	for i := 2; i+1 < len(f); i += 2 {
		r.opts = append(r.opts, [2]string{strings.ToLower(string(f[i])), string(f[i+1])})
	}
	return r, nil
}

func errPacket(code uint16, msg string) []byte {
	b := binary.BigEndian.AppendUint16([]byte{0, opERROR}, code)
	return append(append(b, msg...), 0)
}

func serveTFTP(ctx context.Context, c Config, src *source, rcv *receiver) error {
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", c.Addr)
	if err != nil {
		return fmt.Errorf("fileserve: %w", err)
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	host, _, _ := net.SplitHostPort(pc.LocalAddr().String())
	c.ready(Ready{Addr: pc.LocalAddr().String()})
	sem := make(chan struct{}, maxTransfers)
	var mu sync.Mutex
	perIP := map[string]int{} // el origen de un RRQ es falsificable: nadie acapara los cupos
	var wg sync.WaitGroup
	defer wg.Wait()
	buf := make([]byte, 2048)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("fileserve: %w", err)
		}
		req, err := parseRequest(buf[:n])
		if err != nil {
			continue // basura: ni respuesta ni registro, para no amplificar
		}
		fail := func(code uint16, msg string) {
			pc.WriteTo(errPacket(code, msg), from)
			c.OnTransfer(Transfer{Proto: "tftp", Client: from.String(), File: req.file, Result: "error", Error: msg, Rejected: true})
		}
		if !c.permitsAddr(from) {
			c.OnTransfer(Transfer{Proto: "tftp", Client: from.String(), File: req.file, Result: "error", Error: "origen no permitido", Rejected: true})
			continue // sin respuesta: no se confirma a un origen ajeno que hay un servidor
		}
		var name string
		if req.op == opWRQ {
			if rcv == nil {
				fail(2, "escritura deshabilitada")
				continue
			}
			var err error
			if name, err = SafeName(req.file); err != nil {
				fail(2, err.Error())
				continue
			}
			if rcv.exists(name) {
				fail(6, errExists.Error())
				continue
			}
		} else {
			if !src.enabled() {
				fail(2, "lectura deshabilitada")
				continue
			}
			// Algunos clientes anteponen "/"; nada más se normaliza: el nombre debe coincidir exacto.
			name = strings.TrimPrefix(req.file, "/")
			if !src.exists(name) {
				fail(1, "archivo no publicado")
				continue
			}
		}
		ip := from.(*net.UDPAddr).IP.String()
		mu.Lock()
		busy := perIP[ip] >= perClient
		if !busy {
			perIP[ip]++
		}
		mu.Unlock()
		if busy {
			fail(0, "demasiadas transferencias simultáneas desde este cliente")
			continue
		}
		release := func() {
			mu.Lock()
			if perIP[ip]--; perIP[ip] == 0 {
				delete(perIP, ip)
			}
			mu.Unlock()
		}
		select {
		case sem <- struct{}{}:
		default:
			release()
			fail(0, "demasiadas transferencias simultáneas")
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem; release() }()
			if req.op == opWRQ {
				c.OnTransfer(recvFileTFTP(ctx, host, from, name, req.opts, rcv))
				return
			}
			c.OnTransfer(sendFile(ctx, host, from, name, src, req.opts))
		}()
	}
}

type xfer struct {
	conn    net.PacketConn
	peer    net.Addr
	timeout time.Duration
	tries   int
}

var errPeer = errors.New("el cliente abortó")

// exchange envía pkt y espera el ACK del bloque indicado; reenvía al vencer el plazo.
// Los ACK duplicados se ignoran sin reenviar (síndrome del aprendiz de brujo, RFC 1123).
func (x *xfer) exchange(pkt []byte, block uint16) error {
	buf := make([]byte, 1024)
	for try := 0; try < x.tries; try++ {
		if _, err := x.conn.WriteTo(pkt, x.peer); err != nil {
			return err
		}
		x.conn.SetReadDeadline(time.Now().Add(x.timeout))
		for {
			n, from, err := x.conn.ReadFrom(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				return err
			}
			if from.String() != x.peer.String() {
				x.conn.WriteTo(errPacket(5, "TID desconocido"), from)
				continue
			}
			if n < 4 {
				continue
			}
			switch binary.BigEndian.Uint16(buf) {
			case opACK:
				if binary.BigEndian.Uint16(buf[2:]) == block {
					return nil
				}
			case opERROR:
				return fmt.Errorf("%w: %s", errPeer, strings.TrimRight(string(buf[4:n]), "\x00"))
			}
		}
	}
	return fmt.Errorf("sin respuesta tras %d intentos", x.tries)
}

func sendFile(ctx context.Context, host string, peer net.Addr, name string, src *source, opts [][2]string) Transfer {
	t := Transfer{Proto: "tftp", Dir: "lectura", Client: peer.String(), File: name, Result: "error"}
	start := time.Now()
	defer func() { t.Duration = time.Since(start) }()
	// Cada transferencia usa un puerto propio (TID) en la misma IP de escucha.
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Error = err.Error()
		return t
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	// Hasta el primer ACK el par no está verificado: plazo corto y un solo reenvío.
	x := &xfer{conn: conn, peer: peer, timeout: 2 * time.Second, tries: firstTries}
	want := x.timeout
	verified := func() { x.timeout, x.tries = want, retries }
	f, st, err := src.open(name)
	if err != nil {
		conn.WriteTo(errPacket(1, "no se pudo abrir"), peer)
		t.Error = err.Error()
		return t
	}
	defer f.Close()
	t.Path = f.Name()
	blk := 512
	oack := []byte{0, opOACK}
	for _, o := range opts {
		v, err := strconv.Atoi(o[1])
		if err != nil {
			continue
		}
		switch o[0] {
		case "blksize":
			if v < 8 {
				continue
			}
			blk = min(v, maxBlksize)
			v = blk
		case "tsize":
			v = int(st.Size())
		case "timeout":
			if v < 1 || v > maxTimeout { // fuera de rango: se omite del OACK y el cliente usa el suyo
				continue
			}
			want = time.Duration(v) * time.Second
		default:
			continue // opción desconocida (windowsize…): se omite del OACK
		}
		oack = append(append(append(append(oack, o[0]...), 0), strconv.Itoa(v)...), 0)
	}
	if len(oack) > 2 {
		if err := x.exchange(oack, 0); err != nil {
			t.Error = err.Error()
			return t
		}
		verified()
	}
	buf := make([]byte, 4+blk)
	buf[1] = opDATA
	for block := uint16(1); ; block++ { // el número da la vuelta a 0 tras 65535
		n, err := io.ReadFull(f, buf[4:])
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			conn.WriteTo(errPacket(0, "error de lectura"), peer)
			t.Error = err.Error()
			return t
		}
		binary.BigEndian.PutUint16(buf[2:], block)
		if err := x.exchange(buf[:4+n], block); err != nil {
			if ctx.Err() != nil {
				err = errors.New("servidor detenido")
			}
			t.Error = err.Error()
			return t
		}
		verified()
		t.Bytes += int64(n)
		if n < blk {
			t.Result = "ok"
			return t
		}
	}
}

func ackPacket(block uint16) []byte { return binary.BigEndian.AppendUint16([]byte{0, opACK}, block) }

// awaitData envía pkt (ACK u OACK) y espera el DATA del bloque indicado; reenvía pkt al
// vencer el plazo. Un DATA más largo que blk viola el acuerdo y aborta.
func (x *xfer) awaitData(pkt []byte, block uint16, blk int) ([]byte, error) {
	buf := make([]byte, 4+blk+1)
	for try := 0; try < x.tries; try++ {
		if _, err := x.conn.WriteTo(pkt, x.peer); err != nil {
			return nil, err
		}
		x.conn.SetReadDeadline(time.Now().Add(x.timeout))
		for {
			n, from, err := x.conn.ReadFrom(buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				return nil, err
			}
			if from.String() != x.peer.String() {
				x.conn.WriteTo(errPacket(5, "TID desconocido"), from)
				continue
			}
			if n < 4 {
				continue
			}
			switch binary.BigEndian.Uint16(buf) {
			case opDATA:
				if binary.BigEndian.Uint16(buf[2:]) != block {
					continue // duplicado del anterior: el reenvío del ACK lo cubre el plazo
				}
				if n > 4+blk {
					x.conn.WriteTo(errPacket(4, "bloque mayor que blksize"), x.peer)
					return nil, errors.New("bloque mayor que blksize")
				}
				return append([]byte(nil), buf[4:n]...), nil
			case opERROR:
				return nil, fmt.Errorf("%w: %s", errPeer, strings.TrimRight(string(buf[4:n]), "\x00"))
			}
		}
	}
	return nil, fmt.Errorf("sin respuesta tras %d intentos", x.tries)
}

// recvFileTFTP atiende un WRQ. El archivo se crea hasta recibir el primer DATA: un WRQ con
// origen falsificado no deja archivos vacíos ni gasta nombres.
func recvFileTFTP(ctx context.Context, host string, peer net.Addr, name string, opts [][2]string, rcv *receiver) Transfer {
	t := Transfer{Proto: "tftp", Dir: "escritura", Client: peer.String(), File: name, Result: "error"}
	start := time.Now()
	defer func() { t.Duration = time.Since(start) }()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Error = err.Error()
		return t
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	x := &xfer{conn: conn, peer: peer, timeout: 2 * time.Second, tries: firstTries}
	want := x.timeout
	blk := 512
	var announced int64
	oack := []byte{0, opOACK}
	for _, o := range opts {
		v, err := strconv.Atoi(o[1])
		if err != nil {
			continue
		}
		switch o[0] {
		case "blksize":
			if v < 8 {
				continue
			}
			blk = min(v, maxBlksize)
			v = blk
		case "tsize":
			if v < 0 {
				continue
			}
			announced = int64(v)
		case "timeout":
			if v < 1 || v > maxTimeout {
				continue
			}
			want = time.Duration(v) * time.Second
		default:
			continue
		}
		oack = append(append(append(append(oack, o[0]...), 0), strconv.Itoa(v)...), 0)
	}
	if announced > rcv.maxFile { // se rechaza antes de aceptar un archivo que no cabría
		conn.WriteTo(errPacket(3, errTooBig.Error()), peer)
		t.Error = errTooBig.Error()
		return t
	}
	pkt := ackPacket(0)
	if len(oack) > 2 {
		pkt = oack
	}
	var rf *recvFile
	defer func() {
		if rf != nil {
			rf.abort() // no-op si ya se confirmó
		}
	}()
	for block := uint16(1); ; block++ { // el número da la vuelta a 0 tras 65535
		data, err := x.awaitData(pkt, block, blk)
		if err != nil {
			if ctx.Err() != nil {
				err = errors.New("servidor detenido")
			}
			t.Error = err.Error()
			return t
		}
		x.timeout, x.tries = want, retries // el par ya está verificado
		if rf == nil {
			if rf, err = rcv.create(name, announced); err != nil {
				conn.WriteTo(errPacket(tftpCode(err), err.Error()), peer)
				t.Error = err.Error()
				return t
			}
		}
		if _, err := rf.Write(data); err != nil {
			rf.abort() // antes de avisar: quien reciba el error ya no ve el archivo a medias
			conn.WriteTo(errPacket(3, err.Error()), peer)
			t.Error = err.Error()
			return t
		}
		pkt = ackPacket(block)
		if len(data) < blk {
			conn.WriteTo(pkt, peer)
			sum, size, err := rf.commit()
			t.Bytes, t.SHA256 = size, sum
			if err != nil {
				t.Error = err.Error()
				return t
			}
			t.Path, t.Result = rf.path, "ok"
			return t
		}
	}
}

// tftpCode traduce un error de recepción al código TFTP (RFC 1350): 6 ya existe, 3 sin espacio, 2 acceso.
func tftpCode(err error) uint16 {
	switch {
	case errors.Is(err, errExists):
		return 6
	case errors.Is(err, errTooBig), errors.Is(err, errTotal), errors.Is(err, errTooMany):
		return 3
	}
	return 2
}
