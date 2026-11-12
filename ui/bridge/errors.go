package bridge

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Error es todo error que el puente devuelve a TypeScript. Error() es el texto de siempre; además viaja como
// objeto {message, code, reason, metadata}: Wails lo entrega como la causa (cause) del error que recibe la
// promesa. code es el código gRPC por nombre ("InvalidArgument"; vacío si no vino del núcleo), reason el
// motivo estable del núcleo ("ingest.invalid"; vacío si no tiene) y metadata sus argumentos (nunca secretos).
type Error struct {
	err      error
	msg      string // si no está vacío, reemplaza el texto de err (el puente sabe el idioma de quien llama)
	Code     string
	Reason   string
	Metadata map[string]string
}

func (e *Error) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return e.err.Error()
}

func (e *Error) Unwrap() error { return e.err }

func (e *Error) MarshalJSON() ([]byte, error) {
	m := e.Metadata
	if m == nil {
		m = map[string]string{}
	}
	return json.Marshal(struct {
		Message  string            `json:"message"`
		Code     string            `json:"code"`
		Reason   string            `json:"reason"`
		Metadata map[string]string `json:"metadata"`
	}{e.Error(), e.Code, e.Reason, m})
}

// wrapErr envuelve el error de una llamada al núcleo: conserva su texto y le suma el código, el reason y la metadata
// de sus detalles gRPC (ErrorInfo). Lo que no es de gRPC queda con code, reason y metadata vacíos.
func wrapErr(err error) error {
	var be *Error
	if err == nil || errors.As(err, &be) {
		return err
	}
	out := &Error{err: err}
	if st, ok := status.FromError(err); ok {
		out.Code = st.Code().String()
		for _, d := range st.Details() {
			if ei, ok := d.(*errdetails.ErrorInfo); ok && ei.Domain == "macuahuitl" {
				out.Reason, out.Metadata = ei.Reason, ei.Metadata
			}
		}
	}
	return out
}

// Idioma: con la bandera Localize encendida el puente manda el metadato accept-language con la preferencia ui.language.
// Apagada (por omisión) no manda nada y el núcleo contesta en español, como antes.
const langPref = "ui.language"

type langCache struct {
	mu     sync.Mutex
	value  string
	loaded bool
}

// language devuelve el idioma de la interfaz (preferencia ui.language), o "" si no se pudo leer. Se guarda en memoria
// y SetPreference lo renueva.
func (b *Bridge) language() string {
	b.lang.mu.Lock()
	defer b.lang.mu.Unlock()
	if b.lang.loaded {
		return b.lang.value
	}
	c, err := b.client()
	if err != nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(b.ctx, 3*time.Second)
	defer cancel()
	r, err := v1.NewPrefsServiceClient(c).GetPreference(ctx, &v1.GetPreferenceRequest{Key: langPref})
	if err != nil {
		return ""
	}
	b.lang.value, b.lang.loaded = i18n.Normalize(r.GetValue()), true
	return b.lang.value
}

func (b *Bridge) setLanguage(v string) {
	b.lang.mu.Lock()
	b.lang.value, b.lang.loaded = i18n.Normalize(v), true
	b.lang.mu.Unlock()
}

// callCtx es el contexto de las llamadas al núcleo: el del puente más accept-language si Localize está encendida.
func (b *Bridge) callCtx() context.Context {
	if !b.Localize {
		return b.ctx
	}
	if l := b.language(); l != "" {
		return metadata.AppendToOutgoingContext(b.ctx, "accept-language", l)
	}
	return b.ctx
}

// locale es el idioma de los textos que arma el propio puente (es sin Localize).
func (b *Bridge) locale() string {
	if !b.Localize || strings.TrimSpace(b.language()) == "" {
		return i18n.Es
	}
	return b.language()
}

// errorInfo es el {code, reason, metadata} de un error para los eventos *:done; metadata nunca es nil.
func errorInfo(err error) map[string]any {
	var be *Error
	if !errors.As(wrapErr(err), &be) {
		return nil
	}
	m := be.Metadata
	if m == nil {
		m = map[string]string{}
	}
	return map[string]any{"code": be.Code, "reason": be.Reason, "metadata": m}
}
