// Package ipc es dueño del canal local del núcleo: en Linux un socket Unix con permisos de solo-usuario que rechaza
// clientes de otro UID (SO_PEERCRED); en Windows un named pipe con DACL de solo-usuario que verifica el SID del cliente
// (ADR 0012 a). Ofrece el Dial que usan la UI y mctl (spec §5.2).
//
// No hace: escuchar en TCP.
package ipc

import (
	"context"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ErrAlreadyRunning es un error del catálogo (ipc.err.already_running): se compara con errors.Is, también envuelto.
var ErrAlreadyRunning = i18n.New("ipc.err.already_running", nil)

// ErrNotRunning: no hay un núcleo escuchando (sin socket o pipe, o el socket quedó de un núcleo muerto).
var ErrNotRunning = i18n.New("ipc.err.not_running", nil)

// MaxMsg es el tamaño máximo de un mensaje gRPC en los dos sentidos. El límite por omisión (4 MiB)
// no alcanza para el texto que pega la UI (hasta 8 MiB en Forense) ni para sus informes; los
// servicios que devuelven listas largas acotan su informe por debajo de este tope.
const MaxMsg = 16 << 20

// NewServer crea el servidor gRPC del núcleo. Sin TLS: el canal es un socket Unix local
// protegido por permisos y SO_PEERCRED.
func NewServer(opts ...grpc.ServerOption) *grpc.Server {
	base := []grpc.ServerOption{grpc.Creds(peerCreds{}), grpc.MaxRecvMsgSize(MaxMsg), grpc.MaxSendMsgSize(MaxMsg),
		grpc.ChainUnaryInterceptor(utf8Unary), grpc.ChainStreamInterceptor(utf8Stream)} // texto de equipos en UTF-8 válido
	return grpc.NewServer(append(base, opts...)...)
}

// Dial conecta al núcleo del usuario actual.
func Dial(ctx context.Context, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	p, err := SocketPath()
	if err != nil {
		return nil, err
	}
	return DialPath(p, opts...)
}

// baseDial son las opciones que comparten los dos sistemas.
func baseDial(opts []grpc.DialOption) []grpc.DialOption {
	return append([]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxMsg), grpc.MaxCallSendMsgSize(MaxMsg))}, opts...)
}

// DialOption y WithLanguage dejan a un cliente pedir el idioma del núcleo sin tocar cada llamada: toda llamada,
// unaria o de stream, lleva el metadato accept-language.
type DialOption = grpc.DialOption

func WithLanguage(lang string) []DialOption {
	add := func(ctx context.Context) context.Context {
		return metadata.AppendToOutgoingContext(ctx, "accept-language", lang)
	}
	return []DialOption{
		grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
			return invoker(add(ctx), method, req, reply, cc, opts...)
		}),
		grpc.WithChainStreamInterceptor(func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
			return streamer(add(ctx), desc, cc, method, opts...)
		}),
	}
}

// Alias para que el núcleo y los clientes usen gRPC sin importar red (noegress).
type (
	Listener   = net.Listener
	Registrar  = grpc.ServiceRegistrar
	ClientConn = grpc.ClientConn
)

// Serve registra los servicios y atiende l hasta que ctx termine. Al terminar espera
// a las llamadas en curso como máximo 2 s: un stream de eventos abierto no frena el apagado.
func Serve(ctx context.Context, l Listener, register func(Registrar), opts ...grpc.ServerOption) error {
	s := NewServer(opts...)
	register(s)
	go func() {
		<-ctx.Done()
		done := make(chan struct{})
		go func() { s.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			s.Stop()
		}
	}()
	return s.Serve(l)
}
