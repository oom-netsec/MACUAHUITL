package transfer

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

const (
	opRRQ, opWRQ, opDATA, opACK, opERROR, opOACK = 1, 2, 3, 4, 5, 6
	wantBlksize                                  = 1428
	tftpTimeout                                  = 3 * time.Second
	tftpTries                                    = 5
)

func tftpRequest(op uint16, file string, opts ...string) []byte {
	b := binary.BigEndian.AppendUint16(nil, op)
	for _, s := range append([]string{file, "octet"}, opts...) {
		b = append(append(b, s...), 0)
	}
	return b
}

func tftpAck(block uint16) []byte { return binary.BigEndian.AppendUint16([]byte{0, opACK}, block) }

func tftpErr(code uint16, msg string) []byte {
	return append(binary.BigEndian.AppendUint16([]byte{0, opERROR}, code), append([]byte(msg), 0)...)
}

type tftpConn struct {
	pc   net.PacketConn
	srv  *net.UDPAddr
	peer *net.UDPAddr // TID del servidor, tras su primera respuesta
	buf  []byte
}

// trip envía pkt y espera una respuesta que handle dé por buena; reenvía al vencer el plazo.
// Lo que llega de otro puerto una vez fijado el TID se rechaza con error 5.
func (c *tftpConn) trip(pkt []byte, handle func(op uint16, b []byte) (bool, error)) error {
	for try := 0; try < tftpTries; try++ {
		to := c.srv
		if c.peer != nil {
			to = c.peer
		}
		if _, err := c.pc.WriteTo(pkt, to); err != nil {
			return err
		}
		c.pc.SetReadDeadline(time.Now().Add(tftpTimeout))
		for {
			n, from, err := c.pc.ReadFrom(c.buf)
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			}
			if err != nil {
				return err
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok || !ua.IP.Equal(c.srv.IP) { // solo contesta quien se autorizó
				continue
			}
			if c.peer == nil {
				c.peer = ua
			} else if ua.String() != c.peer.String() {
				c.pc.WriteTo(tftpErr(5, "TID desconocido"), from)
				continue
			}
			if n < 4 {
				continue
			}
			op := binary.BigEndian.Uint16(c.buf)
			if op == opERROR {
				return i18n.New("xfer.err.tftp_error", i18n.A("code", binary.BigEndian.Uint16(c.buf[2:]), "message", strings.TrimRight(string(c.buf[4:n]), "\x00")))
			}
			if done, err := handle(op, c.buf[:n]); err != nil || done {
				return err
			}
		}
	}
	return i18n.New("xfer.err.tftp_silent", i18n.A("n", tftpTries))
}

func (r *Request) tftpOpen(ctx context.Context) (*tftpConn, string, func(), error) {
	file, err := remotePath(r.URL)
	if err != nil {
		return nil, "", nil, err
	}
	port, _ := Port(r.URL)
	pc, srv, err := r.Net.Packet(ctx, r.URL.Hostname(), port)
	if err != nil {
		return nil, "", nil, err
	}
	stop := closeOnDone(ctx, pc)
	return &tftpConn{pc: pc, srv: srv, buf: make([]byte, 4+65464+1)}, file, func() { stop(); pc.Close() }, nil
}

// oackOpts lee las opciones de un OACK en minúsculas.
func oackOpts(b []byte) map[string]string {
	f := strings.Split(strings.TrimRight(string(b[2:]), "\x00"), "\x00")
	m := map[string]string{}
	for i := 0; i+1 < len(f); i += 2 {
		m[strings.ToLower(f[i])] = f[i+1]
	}
	return m
}

func (r *Request) tftpGet(ctx context.Context, w io.Writer) error {
	c, file, done, err := r.tftpOpen(ctx)
	if err != nil {
		return err
	}
	defer done()
	max, _ := r.limits()
	blk, want := 512, uint16(1)
	pkt := tftpRequest(opRRQ, file, "blksize", strconv.Itoa(wantBlksize), "tsize", "0")
	var data []byte
	for {
		isOack := false
		err := c.trip(pkt, func(op uint16, b []byte) (bool, error) {
			switch {
			case op == opOACK && want == 1:
				o := oackOpts(b)
				if v, err := strconv.Atoi(o["blksize"]); err == nil && v >= 8 && v <= wantBlksize {
					blk = v
				}
				if v, err := strconv.ParseInt(o["tsize"], 10, 64); err == nil && v > max {
					return false, errTooBig
				} else if err == nil {
					r.track.setTotal(v)
				}
				isOack = true
				return true, nil
			case op == opDATA && binary.BigEndian.Uint16(b[2:]) == want:
				if len(b)-4 > blk {
					return false, i18n.New("xfer.err.tftp_block", nil)
				}
				data = b[4:]
				return true, nil
			}
			return false, nil
		})
		if err != nil {
			return err
		}
		if isOack {
			pkt = tftpAck(0)
			continue
		}
		if _, err := w.Write(data); err != nil {
			c.pc.WriteTo(tftpErr(3, "tope de tamaño"), c.peer)
			return err
		}
		pkt = tftpAck(want)
		if len(data) < blk {
			c.pc.WriteTo(pkt, c.peer) // último ACK
			return nil
		}
		want++ // da la vuelta a 0 tras 65535
	}
}

func (r *Request) tftpPut(ctx context.Context, rd io.Reader, size int64) error {
	c, file, done, err := r.tftpOpen(ctx)
	if err != nil {
		return err
	}
	defer done()
	blk := 512
	pkt := tftpRequest(opWRQ, file, "blksize", strconv.Itoa(wantBlksize), "tsize", strconv.FormatInt(size, 10))
	err = c.trip(pkt, func(op uint16, b []byte) (bool, error) {
		switch {
		case op == opOACK:
			if v, err := strconv.Atoi(oackOpts(b)["blksize"]); err == nil && v >= 8 && v <= wantBlksize {
				blk = v
			}
			return true, nil
		case op == opACK && binary.BigEndian.Uint16(b[2:]) == 0:
			return true, nil
		}
		return false, nil
	})
	if err != nil {
		return err
	}
	buf := make([]byte, 4+blk)
	buf[1] = opDATA
	for block := uint16(1); ; block++ {
		n, err := io.ReadFull(rd, buf[4:])
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			c.pc.WriteTo(tftpErr(0, "error de lectura"), c.peer)
			return err
		}
		binary.BigEndian.PutUint16(buf[2:], block)
		b := block
		if err := c.trip(append([]byte(nil), buf[:4+n]...), func(op uint16, p []byte) (bool, error) {
			return op == opACK && binary.BigEndian.Uint16(p[2:]) == b, nil
		}); err != nil {
			return err
		}
		if n < blk {
			return nil
		}
	}
}
