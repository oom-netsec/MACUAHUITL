// Package gnmic es un cliente gNMI de solo lectura (Get y Subscribe) para
// telemetría de IOS-XE y NX-OS. Siempre con TLS verificado (sistema o CA propia);
// la conexión TCP la abre el Dialer que entrega el núcleo (EgressGuard).
// Nunca usa Set: la app no cambia configuración en los equipos.
package gnmic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

// ErrInvalid marca errores de parámetros (ruta, modo, CA): no se tocó la red.
var ErrInvalid = errors.New("gnmi: parámetros inválidos")

type Dialer func(ctx context.Context, network, host string, port uint16) (net.Conn, error)

// Rutas de ejemplo (OpenConfig) que entienden IOS-XE 17.x y NX-OS 9.3+.
var ExamplePaths = []string{
	"/interfaces/interface[name=GigabitEthernet1/0/1]/state/counters",
	"/system/cpus/cpu/state/total",
	"/system/memory/state",
}

type Target struct {
	Host       string
	Port       uint16 // 9339 por defecto (IOS-XE); NX-OS suele usar 50051
	Username   string
	Password   string
	CA         []byte // PEM; vacío = CAs del sistema
	ServerName string // nombre a verificar; vacío = Host
	Timeout    time.Duration
}

type Update struct {
	Time   time.Time `json:",omitempty"`
	Path   string    `json:",omitempty"`
	Value  any       `json:",omitempty"`
	Delete bool      `json:",omitempty"`
	Sync   bool      `json:",omitempty"` // el equipo terminó de enviar el estado inicial
}

func (t Target) conn(ctx context.Context, d Dialer) (*grpc.ClientConn, context.Context, error) {
	if strings.TrimSpace(t.Host) == "" || strings.HasPrefix(t.Host, "-") {
		return nil, nil, fmt.Errorf("%w: destino vacío", ErrInvalid)
	}
	port := t.Port
	if port == 0 {
		port = 9339
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: t.ServerName}
	if cfg.ServerName == "" {
		cfg.ServerName = t.Host
	}
	if len(t.CA) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(t.CA) {
			return nil, nil, fmt.Errorf("%w: la CA no contiene certificados PEM válidos", ErrInvalid)
		}
		cfg.RootCAs = pool
	}
	dial := func(ctx context.Context, _ string) (net.Conn, error) { return d(ctx, "tcp", t.Host, port) }
	// passthrough: gRPC no resuelve el nombre por su cuenta; el Dialer decide.
	cc, err := grpc.NewClient("passthrough:///"+net.JoinHostPort(t.Host, strconv.Itoa(int(port))),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)), grpc.WithContextDialer(dial))
	if err != nil {
		return nil, nil, fmt.Errorf("gnmi: %w", err)
	}
	if t.Username != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "username", t.Username, "password", t.Password)
	}
	return cc, ctx, nil
}

var encodings = map[string]gnmi.Encoding{"json_ietf": gnmi.Encoding_JSON_IETF, "json": gnmi.Encoding_JSON, "proto": gnmi.Encoding_PROTO, "ascii": gnmi.Encoding_ASCII}

func paths(ps []string) ([]*gnmi.Path, error) {
	if len(ps) == 0 {
		return nil, fmt.Errorf("%w: sin rutas", ErrInvalid)
	}
	out := make([]*gnmi.Path, 0, len(ps))
	for _, s := range ps {
		p, err := ParsePath(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// Get pide el estado actual de las rutas. encoding: json_ietf (por defecto), json, proto o ascii.
func Get(ctx context.Context, d Dialer, t Target, ps []string, encoding string) ([]Update, error) {
	enc, ok := encodings[strings.ToLower(encoding)]
	if encoding == "" {
		enc, ok = gnmi.Encoding_JSON_IETF, true
	}
	if !ok {
		return nil, fmt.Errorf("%w: codificación %q desconocida", ErrInvalid, encoding)
	}
	gp, err := paths(ps)
	if err != nil {
		return nil, err
	}
	if t.Timeout <= 0 {
		t.Timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	cc, ctx, err := t.conn(ctx, d)
	if err != nil {
		return nil, err
	}
	defer cc.Close()
	r, err := gnmi.NewGNMIClient(cc).Get(ctx, &gnmi.GetRequest{Path: gp, Encoding: enc, Type: gnmi.GetRequest_ALL})
	if err != nil {
		return nil, fmt.Errorf("gnmi: %w", err)
	}
	var out []Update
	for _, n := range r.Notification {
		out = append(out, notification(n)...)
	}
	return out, nil
}

// Subscribe abre una suscripción STREAM (modo sample con intervalo, o on_change) y
// llama a onUpdate hasta que ctx termine o el equipo cierre.
func Subscribe(ctx context.Context, d Dialer, t Target, ps []string, mode string, interval time.Duration, onUpdate func(Update)) error {
	m := map[string]gnmi.SubscriptionMode{"sample": gnmi.SubscriptionMode_SAMPLE, "": gnmi.SubscriptionMode_SAMPLE, "on_change": gnmi.SubscriptionMode_ON_CHANGE}
	sm, ok := m[strings.ToLower(mode)]
	if !ok {
		return fmt.Errorf("%w: modo %q desconocido (sample u on_change)", ErrInvalid, mode)
	}
	gp, err := paths(ps)
	if err != nil {
		return err
	}
	if sm == gnmi.SubscriptionMode_SAMPLE && interval < time.Second {
		interval = 10 * time.Second
	}
	cc, ctx, err := t.conn(ctx, d)
	if err != nil {
		return err
	}
	defer cc.Close()
	st, err := gnmi.NewGNMIClient(cc).Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("gnmi: %w", err)
	}
	sl := &gnmi.SubscriptionList{Mode: gnmi.SubscriptionList_STREAM, Encoding: gnmi.Encoding_JSON_IETF}
	for _, p := range gp {
		s := &gnmi.Subscription{Path: p, Mode: sm}
		if sm == gnmi.SubscriptionMode_SAMPLE {
			s.SampleInterval = uint64(interval)
		}
		sl.Subscription = append(sl.Subscription, s)
	}
	if err := st.Send(&gnmi.SubscribeRequest{Request: &gnmi.SubscribeRequest_Subscribe{Subscribe: sl}}); err != nil {
		return fmt.Errorf("gnmi: %w", err)
	}
	for {
		r, err := st.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("gnmi: %w", err)
		}
		switch v := r.Response.(type) {
		case *gnmi.SubscribeResponse_Update:
			for _, u := range notification(v.Update) {
				onUpdate(u)
			}
		case *gnmi.SubscribeResponse_SyncResponse:
			onUpdate(Update{Sync: true})
		}
	}
}

func notification(n *gnmi.Notification) []Update {
	ts := time.Unix(0, n.Timestamp)
	var out []Update
	for _, u := range n.Update {
		out = append(out, Update{Time: ts, Path: PathString(n.Prefix, u.Path), Value: value(u.Val)})
	}
	for _, p := range n.Delete {
		out = append(out, Update{Time: ts, Path: PathString(n.Prefix, p), Delete: true})
	}
	return out
}

func value(v *gnmi.TypedValue) any {
	switch x := v.GetValue().(type) {
	case *gnmi.TypedValue_StringVal:
		return x.StringVal
	case *gnmi.TypedValue_IntVal:
		return x.IntVal
	case *gnmi.TypedValue_UintVal:
		return x.UintVal
	case *gnmi.TypedValue_BoolVal:
		return x.BoolVal
	case *gnmi.TypedValue_DoubleVal:
		return x.DoubleVal
	case *gnmi.TypedValue_FloatVal:
		//lint:ignore SA1019 equipos viejos aún envían float_val
		return x.FloatVal
	case *gnmi.TypedValue_AsciiVal:
		return x.AsciiVal
	case *gnmi.TypedValue_BytesVal:
		return x.BytesVal
	case *gnmi.TypedValue_JsonVal:
		return decodeJSON(x.JsonVal)
	case *gnmi.TypedValue_JsonIetfVal:
		return decodeJSON(x.JsonIetfVal)
	case *gnmi.TypedValue_LeaflistVal:
		var out []any
		for _, e := range x.LeaflistVal.GetElement() {
			out = append(out, value(e))
		}
		return out
	case nil:
		return nil
	}
	return v.String()
}

func decodeJSON(b []byte) any {
	var out any
	if json.Unmarshal(b, &out) != nil {
		return string(b)
	}
	return out
}

// ParsePath entiende /a/b[k=v][k2=v2]/c; los valores de clave pueden llevar "/".
func ParsePath(s string) (*gnmi.Path, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("%w: ruta vacía", ErrInvalid)
	}
	p := &gnmi.Path{}
	var cur *gnmi.PathElem
	var name strings.Builder
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '/':
			if name.Len() > 0 || cur != nil {
				if cur == nil {
					cur = &gnmi.PathElem{Name: name.String()}
				}
				p.Elem = append(p.Elem, cur)
			}
			cur = nil
			name.Reset()
		case '[':
			end := strings.IndexByte(s[i:], ']')
			if end < 0 {
				return nil, fmt.Errorf("%w: falta ] en %q", ErrInvalid, s)
			}
			k, v, ok := strings.Cut(s[i+1:i+end], "=")
			if !ok || k == "" {
				return nil, fmt.Errorf("%w: clave inválida en %q", ErrInvalid, s)
			}
			if cur == nil {
				if name.Len() == 0 {
					return nil, fmt.Errorf("%w: clave sin elemento en %q", ErrInvalid, s)
				}
				cur = &gnmi.PathElem{Name: name.String(), Key: map[string]string{}}
			}
			cur.Key[k] = v
			i += end
		case ']':
			return nil, fmt.Errorf("%w: ] sin [ en %q", ErrInvalid, s)
		default:
			if cur != nil {
				return nil, fmt.Errorf("%w: texto tras una clave en %q", ErrInvalid, s)
			}
			name.WriteByte(c)
		}
	}
	if cur != nil || name.Len() > 0 {
		if cur == nil {
			cur = &gnmi.PathElem{Name: name.String()}
		}
		p.Elem = append(p.Elem, cur)
	}
	return p, nil
}

// PathString une prefijo y ruta en la notación de ParsePath, con claves ordenadas.
func PathString(prefix, p *gnmi.Path) string {
	var sb strings.Builder
	for _, e := range append(append([]*gnmi.PathElem(nil), prefix.GetElem()...), p.GetElem()...) {
		sb.WriteString("/" + e.Name)
		keys := make([]string, 0, len(e.Key))
		for k := range e.Key {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sb.WriteString("[" + k + "=" + e.Key[k] + "]")
		}
	}
	if sb.Len() == 0 {
		return "/"
	}
	return sb.String()
}
