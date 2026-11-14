package ipc

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Los campos string de proto3 deben ser UTF-8 válido: si no, Marshal falla y la llamada (o el stream entero) muere. El
// texto de los equipos (banners Latin-1, salida cruda) puede no serlo, así que todo lo que sale del núcleo se sanea
// aquí, en un solo borde: lo inválido pasa a U+FFFD. Lo válido no se copia; lo inválido se arregla en una copia, porque
// el mensaje puede estar compartido (el historial de una ejecución se manda a varios watch a la vez).

func utf8Unary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	resp, err := h(ctx, req)
	return validUTF8(resp), err
}

type utf8ServerStream struct{ grpc.ServerStream }

func (s utf8ServerStream) SendMsg(m any) error { return s.ServerStream.SendMsg(validUTF8(m)) }

func utf8Stream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	return h(srv, utf8ServerStream{ss})
}

// validUTF8 devuelve m tal cual si todos sus textos son UTF-8 válido, o una copia saneada.
func validUTF8(m any) any {
	pm, ok := m.(proto.Message)
	if !ok || pm == nil || !pm.ProtoReflect().IsValid() || walkUTF8(pm.ProtoReflect(), false) {
		return m
	}
	c := proto.Clone(pm)
	walkUTF8(c.ProtoReflect(), true)
	return c
}

// walkUTF8 recorre los textos de m (también anidados, repetidos y mapas). Sin fix dice si todos son válidos; con fix
// los arregla en m.
func walkUTF8(m protoreflect.Message, fix bool) bool {
	ok := true
	str := func(v protoreflect.Value) (protoreflect.Value, bool) {
		if s := v.String(); !utf8.ValidString(s) {
			return protoreflect.ValueOfString(strings.ToValidUTF8(s, "�")), false
		}
		return v, true
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList():
			l := v.List()
			for i := 0; i < l.Len(); i++ {
				switch fd.Kind() {
				case protoreflect.StringKind:
					if nv, good := str(l.Get(i)); !good {
						ok = false
						if fix {
							l.Set(i, nv)
						}
					}
				case protoreflect.MessageKind, protoreflect.GroupKind:
					ok = walkUTF8(l.Get(i).Message(), fix) && ok
				}
			}
		case fd.IsMap():
			mp := v.Map()
			type kv struct{ k, nk, nv protoreflect.Value }
			var bad []kv
			mp.Range(func(k protoreflect.MapKey, val protoreflect.Value) bool {
				nk, kGood := k.Value(), true
				if fd.MapKey().Kind() == protoreflect.StringKind {
					nk, kGood = str(k.Value())
				}
				nv, vGood := val, true
				switch fd.MapValue().Kind() {
				case protoreflect.StringKind:
					nv, vGood = str(val)
				case protoreflect.MessageKind, protoreflect.GroupKind:
					vGood = walkUTF8(val.Message(), fix)
				}
				if !kGood || !vGood {
					ok = false
					bad = append(bad, kv{k.Value(), nk, nv})
				}
				return true
			})
			if fix {
				// Primero se quitan todas y luego se ponen, en orden fijo: dos claves que sanean igual (o una igual a
				// otra válida) no se pisan; la repetida lleva un sufijo #2, #3…
				sort.Slice(bad, func(i, j int) bool { return bad[i].k.String() < bad[j].k.String() })
				for _, b := range bad {
					mp.Clear(b.k.MapKey())
				}
				for _, b := range bad {
					nk := b.nk
					for n := 2; fd.MapKey().Kind() == protoreflect.StringKind && mp.Has(nk.MapKey()); n++ {
						nk = protoreflect.ValueOfString(b.nk.String() + "#" + strconv.Itoa(n))
					}
					mp.Set(nk.MapKey(), b.nv)
				}
			}
		case fd.Kind() == protoreflect.StringKind:
			if nv, good := str(v); !good {
				ok = false
				if fix {
					m.Set(fd, nv)
				}
			}
		case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
			ok = walkUTF8(v.Message(), fix) && ok
		}
		return true
	})
	return ok
}
