package ipc

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ServerOption es una opción del servidor gRPC (alias para que el núcleo no importe grpc).
type ServerOption = grpc.ServerOption

// LocaleOptions son los interceptores (unario y de stream) que leen el metadato accept-language y dejan el idioma en el
// contexto de cada llamada (i18n.Locale). Ausente o desconocido es es.
func LocaleOptions() []ServerOption {
	return []ServerOption{grpc.ChainUnaryInterceptor(localeUnary), grpc.ChainStreamInterceptor(localeStream)}
}

func localeOf(ctx context.Context) string {
	md, _ := metadata.FromIncomingContext(ctx)
	return i18n.Parse(strings.Join(md.Get("accept-language"), ","))
}

func localeUnary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	return h(i18n.WithLocale(ctx, localeOf(ctx)), req)
}

type localeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s localeServerStream) Context() context.Context { return s.ctx }

func localeStream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	ctx := ss.Context()
	return h(srv, localeServerStream{ss, i18n.WithLocale(ctx, localeOf(ctx))})
}
