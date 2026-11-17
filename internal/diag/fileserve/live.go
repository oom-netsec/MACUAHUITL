package fileserve

import (
	"io"
	"sync/atomic"
)

// Live es el avance de una transferencia en curso. Solo atómicos: el bucle de datos lo
// suma sin candados, canales ni asignaciones, y cualquiera puede leerlo mientras corre.
// Los métodos son seguros con un *Live nil.
type Live struct {
	Proto, Client, File, Dir string // fijos antes de OnStart
	bytes, total             atomic.Int64
}

func (l *Live) add(n int64) {
	if l != nil {
		l.bytes.Add(n)
	}
}

// atLeast sube el contador hasta n si es mayor (subidas y SFTP, que escribe fuera de orden).
func (l *Live) atLeast(n int64) {
	if l == nil {
		return
	}
	for {
		cur := l.bytes.Load()
		if n <= cur || l.bytes.CompareAndSwap(cur, n) {
			break
		}
	}
	// Si se escribe más de lo anunciado, el total pasa a desconocido: la barra no pasa de 100 %.
	if t := l.total.Load(); t > 0 && n > t {
		l.total.CompareAndSwap(t, 0)
	}
}

func (l *Live) setTotal(n int64) {
	if l != nil {
		l.total.Store(n)
	}
}

func (l *Live) Bytes() int64 {
	if l == nil {
		return 0
	}
	return l.bytes.Load()
}

func (l *Live) Total() int64 {
	if l == nil {
		return 0
	}
	return l.total.Load()
}

// start arma el Live de t, llama a OnStart (si hay) y lo devuelve. Quien lo llama debe
// terminar siempre con OnTransfer de una Transfer que lleve este Live.
func (c Config) start(t Transfer, total int64) *Live {
	l := &Live{Proto: t.Proto, Client: t.Client, File: t.File, Dir: t.Dir}
	l.total.Store(total)
	if c.OnStart != nil {
		c.OnStart(l)
	}
	return l
}

// liveWriter cuenta lo entregado al destino (descargas TCP).
type liveWriter struct {
	w io.Writer
	l *Live
}

func (w liveWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.l.add(int64(n))
	return n, err
}
