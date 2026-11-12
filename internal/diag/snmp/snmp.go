// Package snmp consulta agentes SNMP v2c y v3 (solo authPriv) y recibe traps.
// Solo lectura: Get, GetNext/walk y GetBulk; nunca Set (no cambia equipos).
//
// La conexión la abre gosnmp, pero cada socket pasa por Target.Control, que el
// núcleo arma con EgressGuard.Control. Las comunidades y llaves nunca se
// registran: gosnmp queda sin logger.
package snmp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// ErrInvalid marca errores de parámetros (versión, protocolos, llaves): no se tocó la red.
var ErrInvalid = errors.New("snmp: parámetros inválidos")

// MaxWalk acota un walk sin límite explícito.
const MaxWalk = 50000

type Target struct {
	Host      string
	Port      uint16 // 161 por defecto
	Version   string // 2c o 3
	Community string
	// v3: solo authPriv. Auth: SHA, SHA224, SHA256, SHA384, SHA512. Priv: AES, AES192, AES256 (y sus variantes C de Cisco).
	User, AuthProto, AuthPass, PrivProto, PrivPass string
	Timeout                                        time.Duration // por intento; 2 s por defecto
	Retries                                        int
	Control                                        func(network, address string, c syscall.RawConn) error
}

// Var es un valor recibido. Value queda en el tipo Go natural (string, int, uint, uint32, uint64).
type Var struct {
	OID, Type string
	Value     any
}

var authProtos = map[string]gosnmp.SnmpV3AuthProtocol{"SHA": gosnmp.SHA, "SHA224": gosnmp.SHA224, "SHA256": gosnmp.SHA256, "SHA384": gosnmp.SHA384, "SHA512": gosnmp.SHA512}

var privProtos = map[string]gosnmp.SnmpV3PrivProtocol{"AES": gosnmp.AES, "AES192": gosnmp.AES192, "AES256": gosnmp.AES256, "AES192C": gosnmp.AES192C, "AES256C": gosnmp.AES256C}

func (t Target) client(ctx context.Context) (*gosnmp.GoSNMP, error) {
	if strings.TrimSpace(t.Host) == "" || strings.HasPrefix(t.Host, "-") {
		return nil, fmt.Errorf("%w: destino vacío", ErrInvalid)
	}
	x := &gosnmp.GoSNMP{Target: t.Host, Port: t.Port, Transport: "udp", Timeout: t.Timeout, Retries: t.Retries, Context: ctx,
		Control: t.Control, MaxOids: gosnmp.MaxOids, MaxRepetitions: 25}
	if x.Port == 0 {
		x.Port = 161
	}
	if x.Timeout <= 0 {
		x.Timeout = 2 * time.Second
	}
	switch t.Version {
	case "2c", "":
		if t.Community == "" {
			return nil, fmt.Errorf("%w: falta la comunidad", ErrInvalid)
		}
		x.Version, x.Community = gosnmp.Version2c, t.Community
	case "3":
		ap, ok := authProtos[strings.ToUpper(t.AuthProto)]
		if !ok {
			return nil, fmt.Errorf("%w: autenticación %q no soportada (SHA, SHA224, SHA256, SHA384, SHA512; MD5 no)", ErrInvalid, t.AuthProto)
		}
		pp, ok := privProtos[strings.ToUpper(t.PrivProto)]
		if !ok {
			return nil, fmt.Errorf("%w: privacidad %q no soportada (AES, AES192, AES256; DES no)", ErrInvalid, t.PrivProto)
		}
		if t.User == "" || len(t.AuthPass) < 8 || len(t.PrivPass) < 8 {
			return nil, fmt.Errorf("%w: v3 requiere usuario y llaves de al menos 8 caracteres (authPriv)", ErrInvalid)
		}
		x.Version, x.SecurityModel, x.MsgFlags = gosnmp.Version3, gosnmp.UserSecurityModel, gosnmp.AuthPriv
		x.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: t.User, AuthenticationProtocol: ap, AuthenticationPassphrase: t.AuthPass,
			PrivacyProtocol: pp, PrivacyPassphrase: t.PrivPass}
	default:
		return nil, fmt.Errorf("%w: versión %q no soportada (2c o 3)", ErrInvalid, t.Version)
	}
	if err := x.Connect(); err != nil {
		return nil, fmt.Errorf("snmp: %w", err)
	}
	return x, nil
}

func normOID(o string) string {
	o = strings.TrimSpace(o)
	if !strings.HasPrefix(o, ".") {
		o = "." + o
	}
	return o
}

func toVar(p gosnmp.SnmpPDU) Var {
	v := Var{OID: p.Name, Type: p.Type.String(), Value: p.Value}
	if b, ok := p.Value.([]byte); ok {
		if utf8.Valid(b) {
			v.Value = strings.TrimRight(string(b), "\x00")
		} else {
			v.Value = fmt.Sprintf("%x", b)
		}
	}
	return v
}

// Get consulta OIDs concretos (hasta 60 por petición, gosnmp parte el resto).
func Get(ctx context.Context, t Target, oids []string) ([]Var, error) {
	if len(oids) == 0 {
		return nil, fmt.Errorf("%w: sin OIDs", ErrInvalid)
	}
	x, err := t.client(ctx)
	if err != nil {
		return nil, err
	}
	defer x.Conn.Close()
	var out []Var
	for i := 0; i < len(oids); i += gosnmp.MaxOids {
		chunk := make([]string, 0, gosnmp.MaxOids)
		for _, o := range oids[i:min(i+gosnmp.MaxOids, len(oids))] {
			chunk = append(chunk, normOID(o))
		}
		r, err := x.Get(chunk)
		if err != nil {
			return out, fmt.Errorf("snmp: %w", err)
		}
		if r.Error != gosnmp.NoError {
			return out, fmt.Errorf("snmp: el agente respondió %s", r.Error)
		}
		for _, p := range r.Variables {
			out = append(out, toVar(p))
		}
	}
	return out, nil
}

var errLimit = errors.New("límite")

// Walk recorre un subárbol con GetNext o, si bulk, GetBulk. limit 0 = MaxWalk.
func Walk(ctx context.Context, t Target, root string, bulk bool, limit int) ([]Var, error) {
	if limit <= 0 || limit > MaxWalk {
		limit = MaxWalk
	}
	x, err := t.client(ctx)
	if err != nil {
		return nil, err
	}
	defer x.Conn.Close()
	var out []Var
	fn := func(p gosnmp.SnmpPDU) error {
		out = append(out, toVar(p))
		if len(out) >= limit {
			return errLimit
		}
		return nil
	}
	if bulk {
		err = x.BulkWalk(normOID(root), fn)
	} else {
		err = x.Walk(normOID(root), fn)
	}
	if err != nil && !errors.Is(err, errLimit) {
		return out, fmt.Errorf("snmp: %w", err)
	}
	return out, nil
}
