// Package snmptest es un agente SNMP falso en loopback para las pruebas.
package snmptest

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gosnmp/gosnmp"
)

// Agent es un agente SNMP mínimo en loopback: v2c por comunidad o v3
// authPriv (SHA/AES) con descubrimiento de engine ID. Responde Get, GetNext y
// GetBulk desde un mapa OID → valor; los contadores de interfaz suben en cada Get.
type Agent struct {
	t         *testing.T
	conn      *net.UDPConn
	community string
	usm       *gosnmp.UsmSecurityParameters
	mu        sync.Mutex
	mib       map[string]gosnmp.SnmpPDU
	requests  int
}

// EngineID es el engine ID del agente v3.
const EngineID = "\x80\x00\x00\x09\x03\x00\x11\x22\x33\x44\x55"

func New(t *testing.T, community string, v3 *gosnmp.UsmSecurityParameters) *Agent {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{t: t, conn: c, community: community, mib: map[string]gosnmp.SnmpPDU{}}
	if v3 != nil {
		v3.AuthoritativeEngineID, v3.AuthoritativeEngineBoots, v3.AuthoritativeEngineTime = EngineID, 1, 100
		if err := v3.InitSecurityKeys(); err != nil {
			t.Fatal(err)
		}
		a.usm = v3
	}
	set := func(oid string, typ gosnmp.Asn1BER, v any) {
		a.mib[oid] = gosnmp.SnmpPDU{Name: oid, Type: typ, Value: v}
	}
	set(".1.3.6.1.2.1.1.1.0", gosnmp.OctetString, []byte("Cisco IOS XE Software, Version 17.09.04a"))
	set(".1.3.6.1.2.1.1.3.0", gosnmp.TimeTicks, uint32(123456))
	set(".1.3.6.1.2.1.1.5.0", gosnmp.OctetString, []byte("SW1"))
	for _, i := range []string{"1", "2"} {
		set(".1.3.6.1.2.1.31.1.1.1.1."+i, gosnmp.OctetString, []byte("Gi1/0/"+i))
		set(".1.3.6.1.2.1.2.2.1.8."+i, gosnmp.Integer, 1)
		set(".1.3.6.1.2.1.31.1.1.1.15."+i, gosnmp.Gauge32, uint(1000))
		set(".1.3.6.1.2.1.31.1.1.1.6."+i, gosnmp.Counter64, uint64(1_000_000))
		set(".1.3.6.1.2.1.31.1.1.1.10."+i, gosnmp.Counter64, uint64(2_000_000))
		set(".1.3.6.1.2.1.2.2.1.14."+i, gosnmp.Counter32, uint(3))
	}
	set(".1.3.6.1.4.1.9.9.109.1.1.1.1.6.1", gosnmp.Gauge32, uint(7))
	set(".1.3.6.1.4.1.9.9.109.1.1.1.1.7.1", gosnmp.Gauge32, uint(5))
	set(".1.3.6.1.4.1.9.9.109.1.1.1.1.8.1", gosnmp.Gauge32, uint(4))
	set(".1.3.6.1.4.1.9.9.48.1.1.1.2.1", gosnmp.OctetString, []byte("Processor"))
	set(".1.3.6.1.4.1.9.9.48.1.1.1.5.1", gosnmp.Gauge32, uint(300))
	set(".1.3.6.1.4.1.9.9.48.1.1.1.6.1", gosnmp.Gauge32, uint(700))
	go a.serve()
	t.Cleanup(func() { c.Close() })
	return a
}

// Port es el puerto UDP del agente.
func (a *Agent) Port() uint16 { return uint16(a.conn.LocalAddr().(*net.UDPAddr).Port) }

func oidLess(x, y string) bool {
	xs, ys := strings.Split(strings.Trim(x, "."), "."), strings.Split(strings.Trim(y, "."), ".")
	for i := 0; i < len(xs) && i < len(ys); i++ {
		a, _ := strconv.Atoi(xs[i])
		b, _ := strconv.Atoi(ys[i])
		if a != b {
			return a < b
		}
	}
	return len(xs) < len(ys)
}

func (a *Agent) next(oid string) (gosnmp.SnmpPDU, bool) {
	keys := make([]string, 0, len(a.mib))
	for k := range a.mib {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return oidLess(keys[i], keys[j]) })
	for _, k := range keys {
		if oidLess(oid, k) {
			return a.mib[k], true
		}
	}
	return gosnmp.SnmpPDU{Name: oid, Type: gosnmp.EndOfMibView}, false
}

func (a *Agent) serve() {
	buf := make([]byte, 65535)
	for {
		n, from, err := a.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if out := a.handle(buf[:n]); out != nil {
			a.conn.WriteToUDP(out, from)
		}
	}
}

func (a *Agent) handle(b []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	x := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: a.community}
	if a.usm != nil {
		x = &gosnmp.GoSNMP{Version: gosnmp.Version3, SecurityModel: gosnmp.UserSecurityModel, MsgFlags: gosnmp.AuthPriv, SecurityParameters: a.usm.Copy()}
	}
	req, err := x.SnmpDecodePacket(b)
	if a.usm != nil && req != nil && req.SecurityParameters != nil && req.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthoritativeEngineID == "" {
		// Descubrimiento: Report con usmStatsUnknownEngineIDs y el engine ID.
		sp := &gosnmp.UsmSecurityParameters{AuthoritativeEngineID: EngineID, AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 100}
		rep := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgFlags: gosnmp.NoAuthNoPriv, SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: sp,
			ContextEngineID: EngineID, PDUType: gosnmp.Report, MsgID: req.MsgID, RequestID: req.RequestID, MsgMaxSize: 65507,
			Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.15.1.1.4.0", Type: gosnmp.Counter32, Value: uint(1)}}}
		out, err := rep.MarshalMsg()
		if err != nil {
			a.t.Errorf("report: %v", err)
		}
		return out
	}
	if err != nil {
		return nil // comunidad o credenciales equivocadas: un agente real calla
	}
	if a.community != "" && req.Community != a.community {
		return nil
	}
	a.requests++
	var vars []gosnmp.SnmpPDU
	switch req.PDUType {
	case gosnmp.GetRequest:
		for _, v := range req.Variables {
			p, ok := a.mib[v.Name]
			if !ok {
				p = gosnmp.SnmpPDU{Name: v.Name, Type: gosnmp.NoSuchObject}
			}
			vars = append(vars, p)
		}
		for k, p := range a.mib { // tráfico entre muestras
			if p.Type == gosnmp.Counter64 {
				p.Value = p.Value.(uint64) + 125_000
				a.mib[k] = p
			}
		}
	case gosnmp.GetNextRequest:
		for _, v := range req.Variables {
			p, _ := a.next(v.Name)
			vars = append(vars, p)
		}
	case gosnmp.GetBulkRequest:
		oid := req.Variables[0].Name
		for i := 0; i < int(req.MaxRepetitions); i++ {
			p, ok := a.next(oid)
			vars = append(vars, p)
			if !ok {
				break
			}
			oid = p.Name
		}
	}
	resp := &gosnmp.SnmpPacket{Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID, Variables: vars}
	if a.usm != nil {
		resp.MsgFlags, resp.SecurityModel, resp.SecurityParameters, resp.MsgID = gosnmp.AuthPriv, gosnmp.UserSecurityModel, a.usm.Copy(), req.MsgID
		resp.ContextEngineID, resp.MsgMaxSize = EngineID, 65507
		if err := resp.SecurityParameters.InitPacket(resp); err != nil { // sal de AES
			a.t.Errorf("sal: %v", err)
		}
	}
	out, err := resp.MarshalMsg()
	if err != nil {
		a.t.Errorf("respuesta: %v", err)
	}
	return out
}

// Requests cuenta las consultas válidas que respondió.
func (a *Agent) Requests() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.requests
}
