package transfer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

func (r *Request) sshOpen(ctx context.Context) (*ssh.Client, string, func(), error) {
	file, err := remotePath(r.URL)
	if err != nil {
		return nil, "", nil, err
	}
	if r.SSH == nil {
		return nil, "", nil, i18n.New("xfer.err.no_ssh", nil)
	}
	sess, err := r.SSH(ctx)
	if err != nil {
		return nil, "", nil, err
	}
	c := sess.Client()
	stop := closeOnDone(ctx, c)
	return c, file, func() { stop(); sess.Close() }, nil
}

// ---- SFTP ----

func (r *Request) sftpGet(ctx context.Context, w io.Writer) error {
	c, file, done, err := r.sshOpen(ctx)
	if err != nil {
		return err
	}
	defer done()
	cl, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer cl.Close()
	f, err := cl.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	max, _ := r.limits()
	if st, err := f.Stat(); err == nil {
		if st.Size() > max {
			return errTooBig
		}
		r.track.setTotal(st.Size())
	}
	_, err = io.Copy(w, f)
	return err
}

func (r *Request) sftpPut(ctx context.Context, rd io.Reader) error {
	c, file, done, err := r.sshOpen(ctx)
	if err != nil {
		return err
	}
	defer done()
	cl, err := sftp.NewClient(c)
	if err != nil {
		return err
	}
	defer cl.Close()
	f, err := cl.Create(file)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, rd); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ---- SCP ----

type scpSession struct {
	in  io.WriteCloser
	out *bufio.Reader
	s   *ssh.Session
}

func scpStart(c *ssh.Client, flag, file string) (*scpSession, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	in, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	out, err := s.StdoutPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	if err := s.Start("scp " + flag + " " + file); err != nil { // file ya pasó remotePath: sin metacaracteres
		s.Close()
		return nil, err
	}
	return &scpSession{in: in, out: bufio.NewReaderSize(out, maxCtlLine), s: s}, nil
}

// maxCtlLine es el tope de una línea de control (scp y FTP): un servidor no nos hace leer sin fin.
const maxCtlLine = 4096

var errLineTooLong = i18n.New("xfer.err.line_long", nil)

// readLine lee una línea terminada en \n con tope de longitud (maxCtlLine).
func readLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errLineTooLong
	}
	return string(line), err
}

// ack lee la respuesta de control: 0 = bien; 1 o 2 = error con mensaje en una línea.
func (s *scpSession) ack() error {
	b, err := s.out.ReadByte()
	if err != nil {
		return err
	}
	if b == 0 {
		return nil
	}
	msg, err := readLine(s.out)
	if errors.Is(err, errLineTooLong) {
		return err
	}
	return fmt.Errorf("scp: %s", strings.TrimSpace(msg))
}

func (s *scpSession) send0() error { _, err := s.in.Write([]byte{0}); return err }

func (r *Request) scpGet(ctx context.Context, w io.Writer) error {
	c, file, done, err := r.sshOpen(ctx)
	if err != nil {
		return err
	}
	defer done()
	s, err := scpStart(c, "-f", file)
	if err != nil {
		return err
	}
	defer s.s.Close()
	max, _ := r.limits()
	if err := s.send0(); err != nil {
		return err
	}
	var size int64
	for {
		line, err := readLine(s.out)
		if err != nil {
			return fmt.Errorf("scp: %w", err)
		}
		switch {
		case strings.HasPrefix(line, "\x01") || strings.HasPrefix(line, "\x02"):
			return fmt.Errorf("scp: %s", strings.TrimSpace(line[1:]))
		case strings.HasPrefix(line, "T"):
			if err := s.send0(); err != nil {
				return err
			}
			continue
		case strings.HasPrefix(line, "C"):
			f := strings.SplitN(strings.TrimSpace(line[1:]), " ", 3)
			if len(f) != 3 {
				return i18n.New("xfer.err.scp_c_line", nil)
			}
			if size, err = strconv.ParseInt(f[1], 10, 64); err != nil || size < 0 {
				return i18n.New("xfer.err.scp_size", nil)
			}
		default:
			return i18n.New("xfer.err.scp_dir", nil)
		}
		break
	}
	if size > max {
		return errTooBig
	}
	r.track.setTotal(size)
	if err := s.send0(); err != nil {
		return err
	}
	if _, err := io.CopyN(w, s.out, size); err != nil {
		return err
	}
	if err := s.ack(); err != nil {
		return err
	}
	return s.send0()
}

func (r *Request) scpPut(ctx context.Context, rd io.Reader, size int64) error {
	c, file, done, err := r.sshOpen(ctx)
	if err != nil {
		return err
	}
	defer done()
	s, err := scpStart(c, "-t", file)
	if err != nil {
		return err
	}
	defer s.s.Close()
	if err := s.ack(); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(s.in, "C0644 %d %s\n", size, path.Base(file)); err != nil {
		return err
	}
	if err := s.ack(); err != nil {
		return err
	}
	if _, err := io.CopyN(s.in, rd, size); err != nil {
		return err
	}
	if err := s.send0(); err != nil {
		return err
	}
	if err := s.ack(); err != nil {
		return err
	}
	s.in.Close()
	return nil
}
