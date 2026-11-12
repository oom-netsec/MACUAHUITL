package tacacstest

import (
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// RFC 8907 §4.1.
const (
	typeAuthen = 1
	typeAuthor = 2
	typeAcct   = 3

	flagUnencrypted = 0x01
	headerLen       = 12
	maxBody         = 64 << 10 // las respuestas legítimas miden pocos cientos de bytes
)

type header struct {
	Version, Type, Seq, Flags byte
	Session                   uint32
	Length                    uint32
}

func (h header) bytes() []byte {
	b := []byte{h.Version, h.Type, h.Seq, h.Flags}
	b = binary.BigEndian.AppendUint32(b, h.Session)
	return binary.BigEndian.AppendUint32(b, h.Length)
}

// obfuscate aplica (y quita) el pseudo-pad MD5 de RFC 8907 §4.5 sobre body.
func obfuscate(h header, key, body []byte) {
	base := binary.BigEndian.AppendUint32(nil, h.Session)
	base = append(append(base, key...), h.Version, h.Seq)
	var prev []byte
	for i := 0; i < len(body); i += md5.Size {
		s := md5.New()
		s.Write(base)
		s.Write(prev)
		prev = s.Sum(nil)
		for j := 0; j < md5.Size && i+j < len(body); j++ {
			body[i+j] ^= prev[j]
		}
	}
	clear(base)
}

func writePacket(w io.Writer, h header, key, body []byte) error {
	h.Length = uint32(len(body))
	b := append([]byte(nil), body...)
	if h.Flags&flagUnencrypted == 0 {
		obfuscate(h, key, b)
	}
	_, err := w.Write(append(h.bytes(), b...))
	clear(b)
	return err
}

func readPacket(r io.Reader, key []byte) (header, []byte, error) {
	var hb [headerLen]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return header{}, nil, err
	}
	h := header{Version: hb[0], Type: hb[1], Seq: hb[2], Flags: hb[3],
		Session: binary.BigEndian.Uint32(hb[4:8]), Length: binary.BigEndian.Uint32(hb[8:12])}
	if h.Version>>4 != 0xc {
		return h, nil, fmt.Errorf("versión mayor 0x%x: no es TACACS+", h.Version>>4)
	}
	if h.Length > maxBody {
		return h, nil, fmt.Errorf("cuerpo de %d bytes excede el límite", h.Length)
	}
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(r, body); err != nil {
		return h, nil, err
	}
	if h.Flags&flagUnencrypted == 0 {
		obfuscate(h, key, body)
	}
	return h, body, nil
}

var errShort = errors.New("cuerpo truncado")

// fields corta b en trozos de las longitudes dadas, con verificación de límites.
func fields(b []byte, lens ...int) ([][]byte, error) {
	out := make([][]byte, len(lens))
	for i, l := range lens {
		if l > len(b) {
			return nil, errShort
		}
		out[i], b = b[:l], b[l:]
	}
	return out, nil
}

type authenReply struct {
	Status, Flags   byte
	ServerMsg, Data string
}

func parseAuthenReply(b []byte) (authenReply, error) {
	if len(b) < 6 {
		return authenReply{}, errShort
	}
	f, err := fields(b[6:], int(binary.BigEndian.Uint16(b[2:4])), int(binary.BigEndian.Uint16(b[4:6])))
	if err != nil {
		return authenReply{}, err
	}
	return authenReply{b[0], b[1], string(f[0]), string(f[1])}, nil
}

type authorResponse struct {
	Status          byte
	ServerMsg, Data string
	Args            []string
}

func parseAuthorResponse(b []byte) (authorResponse, error) {
	if len(b) < 6 {
		return authorResponse{}, errShort
	}
	n := int(b[1])
	if len(b) < 6+n {
		return authorResponse{}, errShort
	}
	lens := []int{int(binary.BigEndian.Uint16(b[2:4])), int(binary.BigEndian.Uint16(b[4:6]))}
	for _, l := range b[6 : 6+n] {
		lens = append(lens, int(l))
	}
	f, err := fields(b[6+n:], lens...)
	if err != nil {
		return authorResponse{}, err
	}
	r := authorResponse{Status: b[0], ServerMsg: string(f[0]), Data: string(f[1])}
	for _, a := range f[2:] {
		r.Args = append(r.Args, string(a))
	}
	return r, nil
}

type acctReply struct {
	Status          byte
	ServerMsg, Data string
}

func parseAcctReply(b []byte) (acctReply, error) {
	if len(b) < 5 {
		return acctReply{}, errShort
	}
	f, err := fields(b[5:], int(binary.BigEndian.Uint16(b[0:2])), int(binary.BigEndian.Uint16(b[2:4])))
	if err != nil {
		return acctReply{}, err
	}
	return acctReply{b[4], string(f[0]), string(f[1])}, nil
}

// requestBody arma el cuerpo común de author y acct: cabecera fija, longitudes y datos.
func requestBody(prefix []byte, user, port, rem string, args []string) []byte {
	b := append(prefix, byte(len(user)), byte(len(port)), byte(len(rem)), byte(len(args)))
	for _, a := range args {
		b = append(b, byte(len(a)))
	}
	b = append(append(append(b, user...), port...), rem...)
	for _, a := range args {
		b = append(b, a...)
	}
	return b
}
