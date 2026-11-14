package ipc

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	v1 "github.com/oom-netsec/MACUAHUITL/gen/macuahuitl/v1"
)

const latin1 = "Bienvenido a la se\xf1al\r\nUsuario:" // banner Latin-1 de un equipo: «ñ» como un solo byte 0xF1

// shared imita un historial que varios streams mandan a la vez: el saneo no debe tocarlo.
var shared = &v1.WatchRunResponse{Event: &v1.AssistEvent{Kind: "output", Device: "sw1", Text: latin1, Changed: []string{"sw\xff1"}}}

type assistEco struct {
	v1.UnimplementedAssistServiceServer
}

func (assistEco) WatchRun(_ *v1.WatchRunRequest, st v1.AssistService_WatchRunServer) error {
	return st.Send(shared)
}

type forensicEco struct {
	v1.UnimplementedForensicServiceServer
}

func (forensicEco) LogPatterns(context.Context, *v1.LogPatternsRequest) (*v1.LogPatternsResponse, error) {
	return &v1.LogPatternsResponse{Report: &v1.ToolReport{Text: latin1}}, nil
}

// Un texto con UTF-8 inválido (salida de un equipo) no rompe la serialización de proto3: el servidor lo sanea en el
// borde, en respuestas unarias y en streams (también en repetidos y anidados), y un mismo evento se puede ver dos veces.
func TestUTF8InvalidoSeSaneaEnElBorde(t *testing.T) {
	p := sockPath(t)
	l, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go Serve(ctx, l, func(r Registrar) {
		v1.RegisterAssistServiceServer(r, assistEco{})
		v1.RegisterForensicServiceServer(r, forensicEco{})
	})
	conn, err := DialPath(p)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 2; i++ { // cada watch nuevo reemite desde el evento 0: no debe chocar con el mismo evento
		st, err := v1.NewAssistServiceClient(conn).WatchRun(ctx, &v1.WatchRunRequest{RunId: "r"})
		if err != nil {
			t.Fatal(err)
		}
		e, err := st.Recv()
		if err != nil {
			t.Fatalf("watch %d: %v", i, err)
		}
		if !utf8.ValidString(e.Event.Text) || e.Event.Text != "Bienvenido a la se�al\r\nUsuario:" || e.Event.Changed[0] != "sw�1" {
			t.Fatalf("watch %d: %q %q", i, e.Event.Text, e.Event.Changed)
		}
	}
	if shared.Event.Text != latin1 {
		t.Fatal("el saneo modificó el mensaje compartido del servidor")
	}
	r, err := v1.NewForensicServiceClient(conn).LogPatterns(ctx, &v1.LogPatternsRequest{})
	if err != nil || !utf8.ValidString(r.Report.Text) {
		t.Fatalf("unario: %v %q", err, r.GetReport().GetText())
	}
}

// fillInvalid pone bytes inválidos en todo campo string de m (y en sus mensajes anidados, repetidos y mapas).
func fillInvalid(m protoreflect.Message, depth int) {
	const bad = "x\xf1\xff"
	fields := m.Descriptor().Fields()
	for i := 0; i < fields.Len(); i++ {
		fd := fields.Get(i)
		if fd.ContainingOneof() != nil && m.WhichOneof(fd.ContainingOneof()) != nil {
			continue // un solo campo por oneof
		}
		switch {
		case fd.IsMap():
			if fd.MapKey().Kind() != protoreflect.StringKind {
				continue
			}
			mp := m.Mutable(fd).Map()
			switch fd.MapValue().Kind() {
			case protoreflect.StringKind:
				mp.Set(protoreflect.ValueOfString(bad).MapKey(), protoreflect.ValueOfString(bad))
			case protoreflect.MessageKind:
				if depth > 0 {
					v := mp.NewValue()
					fillInvalid(v.Message(), depth-1)
					mp.Set(protoreflect.ValueOfString(bad).MapKey(), v)
				}
			}
		case fd.IsList():
			l := m.Mutable(fd).List()
			switch fd.Kind() {
			case protoreflect.StringKind:
				l.Append(protoreflect.ValueOfString(bad))
			case protoreflect.MessageKind:
				if depth > 0 {
					v := l.NewElement()
					fillInvalid(v.Message(), depth-1)
					l.Append(v)
				}
			}
		case fd.Kind() == protoreflect.StringKind:
			m.Set(fd, protoreflect.ValueOfString(bad))
		case fd.Kind() == protoreflect.MessageKind && depth > 0:
			fillInvalid(m.Mutable(fd).Message(), depth-1)
		}
	}
}

// Todo mensaje de la API (respuestas, eventos de streams, anidados, repetidos y mapas) con bytes inválidos en cada
// texto se puede serializar tras el saneo del borde: ningún RPC ni stream muere por la salida de un equipo.
func TestUTF8TodosLosMensajesDeLaAPI(t *testing.T) {
	n := 0
	protoregistry.GlobalTypes.RangeMessages(func(mt protoreflect.MessageType) bool {
		if !strings.HasPrefix(string(mt.Descriptor().FullName()), "macuahuitl.v1.") {
			return true
		}
		n++
		m := mt.New()
		fillInvalid(m, 3)
		if _, err := proto.Marshal(validUTF8(m.Interface()).(proto.Message)); err != nil {
			t.Errorf("%s: %v", mt.Descriptor().FullName(), err)
		}
		return true
	})
	if n < 100 {
		t.Fatalf("solo %d mensajes de la API recorridos", n)
	}
}

// Un mapa con clave o valor inválido conserva su entrada, saneada (no se pierde un argumento).
func TestUTF8MapaConservaLaEntrada(t *testing.T) {
	in := &v1.TextRef{Key: "k", Args: map[string]string{"a\xff": "v\xf1", "ok": "bien"}}
	out := validUTF8(in).(*v1.TextRef)
	if len(out.Args) != 2 || out.Args["a�"] != "v�" || out.Args["ok"] != "bien" {
		t.Fatalf("args = %q", out.Args)
	}
	if _, ok := in.Args["a\xff"]; !ok {
		t.Fatal("el original cambió")
	}
}
