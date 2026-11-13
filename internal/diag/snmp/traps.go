package snmp

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"

	"github.com/oom-netsec/MACUAHUITL/internal/diag/ingest"
	"github.com/oom-netsec/MACUAHUITL/internal/diag/listen"
)

// MaxRawTrap es lo que se conserva (en hex) de un paquete que no se pudo decodificar.
const MaxRawTrap = 512

// DefaultTrapAddr: 162 es privilegiado (ADR 0004); se escucha en 1162 y, si el
// equipo no permite cambiar el puerto, se redirige con nftables.
const DefaultTrapAddr = "127.0.0.1:1162"

type TrapConfig struct {
	Addr        string
	AllowAny    bool
	V3          *Target // usuario USM para autenticar y descifrar traps v3; nil = v3 queda crudo
	Out         io.Writer
	OnTrap      func(Trap)
	OnListening func(addr string)
	Limits      ingest.Limits      // topes de tasa y cola; 0 = default
	Sink        *ingest.Sink       // archivo con rotación y retención; nil = sin archivo
	Now         func() time.Time   // reloj de cubos y rotación; nil = time.Now
	OnDrops     func(ingest.Drops) // acumulado; a lo más una vez por segundo y solo si cambió, más una al cerrar
}

// Trap es un trap o inform recibido. La comunidad no se conserva.
type Trap struct {
	Time      time.Time
	From      string
	Version   string    `json:",omitempty"`
	Inform    bool      `json:",omitempty"`
	Name      string    `json:",omitempty"` // coldStart, linkDown... o el OID si no es conocido
	TrapOID   string    `json:",omitempty"`
	Summary   string    `json:",omitempty"`
	Vars      []Var     `json:",omitempty"`
	Error     string    `json:",omitempty"`
	ErrorText i18n.Text `json:"-"`          // Error como texto, para darlo en otro idioma
	Raw       string    `json:",omitempty"` // hex, solo si no se pudo decodificar
}

// Origin, Text y Line hacen de Trap un ingest.Record.
func (t Trap) Origin() string { return t.From }

// Text es el trap decodificado en una línea (el «crudo» del archivo): versión, inform,
// resumen o nombre, y cada variable como OID=valor; sin saltos ni caracteres de control.
func (t Trap) Text() string {
	if t.Error != "" {
		s := "error: " + t.Error
		if t.Raw != "" {
			s += " raw=" + t.Raw
		}
		return oneLine(s)
	}
	f := []string{"v" + t.Version}
	if t.Inform {
		f = append(f, "inform")
	}
	if t.Summary != "" {
		f = append(f, strings.TrimSpace(t.Summary))
	} else {
		f = append(f, t.Name)
	}
	for _, v := range t.Vars {
		f = append(f, v.OID+"="+fmt.Sprint(v.Value))
	}
	return oneLine(strings.Join(f, " "))
}

// oneLine cambia los caracteres de control por «.» (evita saltos de línea y secuencias de terminal).
func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '.'
		}
		return r
	}, s)
}

// Line es la línea del archivo (con salto final): texto (hora, origen y Text), crudo (solo Text) o jsonl.
func (t Trap) Line(format string) []byte {
	switch format {
	case "crudo":
		return []byte(t.Text() + "\n")
	case "jsonl":
		b, _ := json.Marshal(t)
		return append(b, '\n')
	}
	return []byte(t.Time.Format(time.RFC3339) + " " + t.From + " " + t.Text() + "\n")
}

var trapNames = map[string]string{
	".1.3.6.1.6.3.1.1.5.1": "coldStart", ".1.3.6.1.6.3.1.1.5.2": "warmStart", ".1.3.6.1.6.3.1.1.5.3": "linkDown",
	".1.3.6.1.6.3.1.1.5.4": "linkUp", ".1.3.6.1.6.3.1.1.5.5": "authenticationFailure",
}

var genericV1 = []string{"coldStart", "warmStart", "linkDown", "linkUp", "authenticationFailure", "egpNeighborLoss"}

const (
	oidSnmpTrapOID = ".1.3.6.1.6.3.1.1.4.1.0"
	oidLocIfReason = ".1.3.6.1.4.1.9.2.2.1.1.20." // OLD-CISCO-INTERFACES-MIB: motivo que agrega IOS
)

// summarize describe linkDown/linkUp con interfaz, estado y motivo.
func summarize(t *Trap) {
	if t.Name != "linkDown" && t.Name != "linkUp" {
		return
	}
	var parts []string
	for _, v := range t.Vars {
		switch {
		case strings.HasPrefix(v.OID, ifDescr+"."), strings.HasPrefix(v.OID, ifName+"."):
			parts = append(parts, fmt.Sprint(v.Value))
		case strings.HasPrefix(v.OID, ".1.3.6.1.2.1.2.2.1.1."):
			parts = append(parts, fmt.Sprintf("ifIndex %v", v.Value))
		case strings.HasPrefix(v.OID, ifOperStatus+"."):
			parts = append(parts, "oper "+operNames[num(v.Value)])
		case strings.HasPrefix(v.OID, oidLocIfReason):
			parts = append(parts, fmt.Sprintf("(%v)", v.Value))
		}
	}
	t.Summary = t.Name + " " + strings.Join(parts, " ")
}

// trapErr es un trap que no se pudo decodificar, con su error como texto de catálogo.
func trapErr(key string, kv ...any) Trap {
	t := i18n.Tx(key, kv...)
	return Trap{Error: t.In(i18n.Es), ErrorText: t}
}

// Localize da el error del trap en el idioma pedido (lo demás son datos del equipo).
func (t Trap) Localize(loc string) Trap {
	if !t.ErrorText.Empty() {
		t.Error = t.ErrorText.In(loc)
	}
	return t
}

func decodeTrap(x *gosnmp.GoSNMP, b []byte) (t Trap, p *gosnmp.SnmpPacket) {
	defer func() {
		if r := recover(); r != nil { // gosnmp con un paquete hostil no debe tumbar el receptor
			t, p = trapErr("snmp.trap.malformed", "detail", fmt.Sprint(r)), nil
		}
	}()
	p, err := x.UnmarshalTrap(b, false)
	if err != nil {
		return Trap{Error: err.Error(), ErrorText: i18n.FromErr(err)}, nil
	}
	if p == nil {
		return trapErr("snmp.trap.empty"), nil
	}
	t.Version = map[gosnmp.SnmpVersion]string{gosnmp.Version1: "1", gosnmp.Version2c: "2c", gosnmp.Version3: "3"}[p.Version]
	t.Inform = p.PDUType == gosnmp.InformRequest
	if p.PDUType != gosnmp.Trap && p.PDUType != gosnmp.SNMPv2Trap && !t.Inform {
		bad := trapErr("snmp.trap.not_trap", "pdu", p.PDUType)
		bad.Version = t.Version
		return bad, nil
	}
	for _, v := range p.Variables {
		vv := toVar(v)
		if v.Name == oidSnmpTrapOID {
			t.TrapOID = fmt.Sprint(vv.Value)
		}
		t.Vars = append(t.Vars, vv)
	}
	if p.Version == gosnmp.Version1 {
		t.TrapOID = p.Enterprise
		if p.GenericTrap >= 0 && p.GenericTrap < len(genericV1) {
			t.Name = genericV1[p.GenericTrap]
		} else {
			t.Name = fmt.Sprintf("%s.0.%d", p.Enterprise, p.SpecificTrap)
		}
	} else if t.Name = trapNames[t.TrapOID]; t.Name == "" {
		t.Name = t.TrapOID
	}
	summarize(&t)
	return t, p
}

// berLen lee una longitud BER (forma corta o larga de hasta 4 bytes) en b[i:].
func berLen(b []byte, i int) (l, next int, ok bool) {
	if i >= len(b) {
		return 0, 0, false
	}
	if b[i] < 0x80 {
		return int(b[i]), i + 1, true
	}
	n := int(b[i] & 0x7f)
	if n == 0 || n > 4 || i+1+n > len(b) {
		return 0, 0, false
	}
	for _, c := range b[i+1 : i+1+n] {
		l = l<<8 | int(c)
	}
	return l, i + 1 + n, true
}

// snmpVersion lee la versión del mensaje SNMP (0 = v1, 1 = v2c, 3 = v3) y deja en next el byte que sigue.
func snmpVersion(pkt []byte) (version, next int, ok bool) {
	if len(pkt) < 2 || pkt[0] != 0x30 {
		return 0, 0, false
	}
	_, i, ok := berLen(pkt, 1)
	if !ok || i >= len(pkt) || pkt[i] != 0x02 {
		return 0, 0, false
	}
	vl, i, ok := berLen(pkt, i+1)
	if !ok || vl < 1 || vl > 4 || i+vl > len(pkt) {
		return 0, 0, false
	}
	for _, c := range pkt[i : i+vl] {
		version = version<<8 | int(c)
	}
	return version, i + vl, true
}

// blindCommunity devuelve una copia con la comunidad v1/v2c reemplazada por '*'.
// false si no se reconoce la cabecera o si es v3: ese paquete trae el usuario USM y los
// parámetros de autenticación, y no se conserva nunca.
func blindCommunity(pkt []byte) ([]byte, bool) {
	version, i, ok := snmpVersion(pkt)
	if !ok || version == 3 || i >= len(pkt) || pkt[i] != 0x04 {
		return nil, false
	}
	cl, i, ok := berLen(pkt, i+1)
	if !ok || i+cl > len(pkt) {
		return nil, false
	}
	out := append([]byte(nil), pkt...)
	for j := i; j < i+cl; j++ {
		out[j] = '*'
	}
	return out, true
}

// ListenTraps recibe traps e informs por UDP hasta que ctx termine. A los inform
// v1/v2c les responde (si no, el equipo reintenta); los inform v3 quedan sin
// respuesta porque exigirían que la app fuera motor autoritativo.
func ListenTraps(ctx context.Context, c TrapConfig) error {
	if c.Addr == "" {
		c.Addr = DefaultTrapAddr
	}
	if err := listen.ValidateAddr(c.Addr, c.AllowAny); err != nil {
		return fmt.Errorf("snmp traps: %w", err)
	}
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c}
	if c.V3 != nil {
		ap, pp := authProtos[strings.ToUpper(c.V3.AuthProto)], privProtos[strings.ToUpper(c.V3.PrivProto)]
		if ap == 0 || pp == 0 || c.V3.User == "" {
			return i18n.New("snmp.err.trap_v3", nil)
		}
		x = &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv,
			SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: c.V3.User, AuthenticationProtocol: ap, AuthenticationPassphrase: c.V3.AuthPass,
				PrivacyProtocol: pp, PrivacyPassphrase: c.V3.PrivPass}}
	}
	if err := c.Limits.Validate(); err != nil {
		return fmt.Errorf("snmp traps: %w", err)
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	var w *ingest.Writer
	if c.Sink != nil {
		if err := c.Sink.Validate(); err != nil {
			return fmt.Errorf("snmp traps: %w", err)
		}
		var err error
		if w, err = ingest.NewWriter(*c.Sink, c.Now); err != nil {
			return fmt.Errorf("snmp traps: %w", err)
		}
		defer w.Close()
	}
	ctx, cancel := context.WithCancel(ctx) // un fallo del archivo cancela la escucha
	defer cancel()
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", c.Addr)
	if err != nil {
		return fmt.Errorf("snmp traps: %w", err)
	}
	defer pc.Close()
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	defer stop()
	// Los lectores solo revisan los topes y encolan sin esperar; una gorutina aparte escribe y entrega.
	var p *ingest.Pipeline[Trap]
	p = ingest.NewPipeline(ingest.PipelineConfig[Trap]{Limits: c.Limits, Now: c.Now, Writer: w, Cancel: cancel, OnDrops: c.OnDrops,
		Handle: func(t Trap) {
			if c.Out != nil {
				b, _ := json.Marshal(t)
				c.Out.Write(append(b, '\n'))
			}
			p.Write(t)
			if c.OnTrap != nil {
				c.OnTrap(t)
			}
		}})
	p.Start()
	err = readTraps(ctx, pc, x, c, p)
	if sinkErr := p.Stop(); err == nil {
		err = sinkErr
	}
	return err
}

func readTraps(ctx context.Context, pc net.PacketConn, x *gosnmp.GoSNMP, c TrapConfig, pl *ingest.Pipeline[Trap]) error {
	if c.OnListening != nil {
		c.OnListening(pc.LocalAddr().String())
	}
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("snmp traps: %w", err)
		}
		key, ok := pl.Admit(from.String())
		if !ok {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		t, p := decodeTrap(x, pkt)
		t.Time, t.From = pl.Now(), from.String()
		if t.Error != "" {
			if v, _, ok := snmpVersion(pkt); ok && v == 3 {
				// v3 sin decodificar: nunca el paquete, que trae el usuario USM y los parámetros de autenticación.
				t.Version = "3"
				t.ErrorText = i18n.Tx("snmp.trap.v3_raw", "bytes", n).With("error", t.ErrorText)
				t.Error = t.ErrorText.In(i18n.Es)
			} else if b, ok := blindCommunity(pkt); ok {
				// Solo si se pudo ubicar y cegar la comunidad: el crudo va a eventos y a disco.
				t.Raw = hex.EncodeToString(b[:min(n, MaxRawTrap)])
			}
		}
		// Se responde al inform solo si el trap entró a la cola: si se descartó, el equipo lo reintenta.
		if !pl.Enqueue(key, t) {
			continue
		}
		if t.Inform && p.Version != gosnmp.Version3 {
			p.PDUType = gosnmp.GetResponse
			if out, err := p.MarshalMsg(); err == nil {
				pc.WriteTo(out, from)
			}
		}
	}
}
