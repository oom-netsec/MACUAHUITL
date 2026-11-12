package service

import (
	"context"
	"errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// ErrDomain es el dominio de los ErrorInfo del núcleo.
const ErrDomain = "macuahuitl"

// Err arma el error gRPC de un código del catálogo: el texto en el idioma del contexto y, como detalles,
// el ErrorInfo (reason, dominio y metadata) y el LocalizedMessage.
func Err(ctx context.Context, c codes.Code, code string, args i18n.Args) error {
	return ErrFrom(ctx, c, i18n.New(code, args))
}

// ErrFrom es Err para un error que ya trae código (i18n.Coded, aunque venga envuelto). Con es el texto es
// exactamente err.Error(), envoltorios incluidos; con en, el del catálogo. Un error sin código sale como
// status.Error(c, err.Error()), igual que antes.
func ErrFrom(ctx context.Context, c codes.Code, err error) error {
	var ce i18n.Coded
	if !errors.As(err, &ce) {
		return status.Error(c, err.Error())
	}
	loc := i18n.Locale(ctx)
	msg := err.Error()
	if loc != i18n.Es {
		msg = ce.Localize(loc)
	}
	st := status.New(c, msg)
	if d, derr := st.WithDetails(
		&errdetails.ErrorInfo{Reason: ce.Reason(), Domain: ErrDomain, Metadata: ce.Metadata()},
		&errdetails.LocalizedMessage{Locale: loc, Message: msg},
	); derr == nil {
		st = d
	}
	return st.Err()
}
