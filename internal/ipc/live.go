package ipc

import (
	"fmt"
	"slices"
	"strings"
	"sync"

	"google.golang.org/grpc"
)

// Live cuenta los streams gRPC abiertos por método: una escucha de syslog o traps, una captura, un servidor de
// archivos, una terminal o una consola son un stream que dura lo que dura el trabajo. Los métodos de ignore son
// pasivos (un suscriptor de eventos no es trabajo) y no cuentan.
type Live struct {
	mu     sync.Mutex
	n      map[string]int
	ignore map[string]bool
}

// NewLive arma el contador; ignore son métodos «Servicio/Método» (sin el prefijo del paquete).
func NewLive(ignore ...string) *Live {
	l := &Live{n: map[string]int{}, ignore: map[string]bool{}}
	for _, m := range ignore {
		l.ignore[m] = true
	}
	return l
}

// Options es el interceptor de streams del contador, para NewServer o Serve.
func (l *Live) Options() []ServerOption { return []ServerOption{grpc.ChainStreamInterceptor(l.stream)} }

func (l *Live) stream(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	m := shortMethod(info.FullMethod)
	if l.ignore[m] {
		return h(srv, ss)
	}
	l.mu.Lock()
	l.n[m]++
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		if l.n[m]--; l.n[m] == 0 {
			delete(l.n, m)
		}
		l.mu.Unlock()
	}()
	return h(srv, ss)
}

// shortMethod quita «/macuahuitl.v1.» de «/macuahuitl.v1.FieldService/ServeFiles».
func shortMethod(full string) string {
	return strings.TrimPrefix(strings.TrimPrefix(full, "/"), "macuahuitl.v1.")
}

// Active da una línea por método con streams abiertos («FieldService/ServeFiles», «… x2» si hay varios), ordenadas.
func (l *Live) Active() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for m, n := range l.n {
		if n > 1 {
			out = append(out, fmt.Sprintf("%s x%d", m, n))
		} else {
			out = append(out, m)
		}
	}
	slices.Sort(out)
	return out
}
