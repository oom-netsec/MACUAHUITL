// Package ikedec interpreta salidas pegadas de IOS/IOS-XE y ASA: debug crypto
// isakmp/ikev2/ipsec y show crypto isakmp sa / ikev2 sa detail / ipsec sa.
// Identifica fases, propuestas ofrecidas y aceptadas, causas comunes de falla y
// contadores, con explicación y acción recomendada. Sin red.
//
// Las reglas siguen la documentación pública de Cisco y están SIN VALIDAR EN
// LABORATORIO (ver testdata/README.md).
package ikedec

import (
	"context"
	"fmt"
	"regexp"
	"regexp/syntax"
	"sort"
	"strconv"
	"strings"
)

const Note = "Reglas basadas en la documentación pública de Cisco, sin validar en laboratorio: confirma cada causa contra la configuración de ambos extremos."

type Finding struct {
	Severity    string // error, aviso, info
	Code        string
	Title       string
	Phase       int `json:",omitempty"`
	Explanation string
	Action      string
	Evidence    []string
}

type Proposal struct {
	Phase  int
	Source string // "transform 1 del par vs política 10", "recibida del par", "esperada (local)"…
	Detail string
	Result string `json:",omitempty"` // aceptada, rechazada
}

type SA struct {
	Kind, Peer, Local, State string
	Detail                   string `json:",omitempty"`
}

type IPsecSA struct {
	Peer, Local, Remote string
	Encaps, Decaps      int
	HasSA               bool
	PFS                 string `json:",omitempty"`
	Counters            map[string]int
}

type Report struct {
	Detected  []string
	Phase1    string // establecida, falló, mixta, incompleta, sin datos
	Phase2    string
	Proposals []Proposal
	SAs       []SA
	IPsec     []IPsecSA
	Findings  []Finding
	Note      string
}

// pre es una regex con prefiltro: solo se evalúa si la línea contiene (sin distinguir
// mayúsculas) alguno de los literales que la regex exige; así el resultado es idéntico.
type pre struct {
	*regexp.Regexp
	kw []string // vacío = sin prefiltro
}

// required devuelve literales en minúscula de los que al menos uno debe aparecer en toda coincidencia (nil si no hay).
func required(t *syntax.Regexp) []string {
	switch t.Op {
	case syntax.OpLiteral:
		l := strings.ToLower(string(t.Rune))
		for _, c := range l {
			if c > 127 {
				return nil
			}
		}
		return []string{l}
	case syntax.OpCapture, syntax.OpPlus:
		return required(t.Sub[0])
	case syntax.OpRepeat:
		if t.Min >= 1 {
			return required(t.Sub[0])
		}
	case syntax.OpAlternate:
		var all []string
		for _, c := range t.Sub {
			r := required(c)
			if r == nil {
				return nil
			}
			all = append(all, r...)
		}
		return all
	case syntax.OpConcat:
		var best []string
		score := func(l []string) int {
			m := 1 << 30
			for _, v := range l {
				m = min(m, len(v))
			}
			return m
		}
		for _, c := range t.Sub {
			if r := required(c); r != nil && (best == nil || score(r) > score(best)) {
				best = r
			}
		}
		return best
	}
	return nil
}

// match/find/findAll evalúan la regex solo si la línea (ya en minúscula en d.lo) trae alguno de sus literales.
func (d *decoder) may(p *pre) bool {
	if len(p.kw) == 0 {
		return true
	}
	for _, k := range p.kw {
		if strings.Contains(d.lo, k) {
			return true
		}
	}
	return false
}

// Una misma regex se consulta varias veces por línea (contexto, tablas, estado): se memoriza por línea.
func (d *decoder) match(p *pre, line string) bool { return d.find(p, line) != nil }

func (d *decoder) find(p *pre, line string) []string {
	if !d.may(p) {
		return nil
	}
	if m, ok := d.memo[p]; ok {
		return m
	}
	m := p.FindStringSubmatch(line)
	d.memo[p] = m
	return m
}

func (d *decoder) findAll(p *pre, line string) [][]string {
	if !d.may(p) {
		return nil
	}
	return p.FindAllStringSubmatch(line, -1)
}

type rule struct {
	code, sev, title string
	phase            int // 0 = la fase del contexto
	re               *pre
	expl, action     string
}

func re(s string) *pre {
	x := regexp.MustCompile("(?i)" + s)
	t, err := syntax.Parse("(?i)"+s, syntax.Perl)
	if err != nil {
		panic(err)
	}
	return &pre{x, required(t)}
}

var rules = []rule{
	{"p1-propuesta", "error", "Propuestas de fase 1 (IKE) no coinciden", 1,
		re(`phase 1 SA policy not acceptable|no offers accepted|Failed to find a matching policy|All SA proposals found unacceptable|Mismatched attribute types|offered does not match policy`),
		"Ninguna propuesta IKE del par coincide con las políticas locales (cifrado, hash/integridad, PRF, grupo DH, método de autenticación o lifetime).",
		"Compara 'crypto isakmp policy' / 'crypto ikev2 proposal' (ASA: 'crypto ikev1|ikev2 policy') en ambos extremos y deja al menos una idéntica; evita DES/3DES/MD5/grupos 1, 2 y 5."},
	{"p2-propuesta", "error", "Propuestas de fase 2 (IPsec) no coinciden", 2,
		re(`transform proposal not supported|All IPSec SA proposals found unacceptable`),
		"El transform-set / IPsec proposal ofrecido no coincide con el local (ESP cifrado, integridad, modo túnel/transporte).",
		"Iguala 'crypto ipsec transform-set' (IKEv2/ASA: 'crypto ipsec ikev2 ipsec-proposal') en ambos extremos, incluido el modo."},
	{"pfs", "error", "PFS o grupo DH de fase 2 distinto", 2,
		re(`INVALID_KE_PAYLOAD|PFS.*(mismatch|does not match)`),
		"Un extremo exige PFS (o un grupo DH distinto) para la fase 2 y el otro no; también falla el rekey de CREATE_CHILD_SA.",
		"Configura 'set pfs groupN' igual en ambos crypto maps / perfiles IPsec, o quítalo de ambos."},
	{"psk", "error", "Clave precompartida (PSK) incorrecta o falla de autenticación", 1,
		re(`IKMP_BAD_MESSAGE|failed its sanity check or is malformed|IKMP_NOT_ENCRYPTED|reserved not zero on|Hash payload verification failed|PAYLOAD_MALFORMED|AUTHENTICATION_FAILED|authentication data FAILED|Auth exchange failed`),
		"Los mensajes 5/6 de Main Mode (o IKE_AUTH en IKEv2) no se descifran o el hash/AUTH no verifica: casi siempre la PSK difiere, o el par usa otro método (certificados).",
		"Vuelve a escribir la PSK en ambos extremos ('crypto isakmp key', keyring IKEv2 o tunnel-group ipsec-attributes) cuidando espacios finales y mayúsculas; verifica el método de autenticación."},
	{"psk-ausente", "error", "No hay PSK configurada para el par", 1,
		re(`No pre-shared key with|pre-?shared key not found`),
		"El equipo no encuentra una clave para la dirección o identidad del par.",
		"Agrega la PSK para la IP real del par (ojo con NAT: la IP pública) en el keyring o 'crypto isakmp key'."},
	{"sin-respuesta", "error", "El par no responde (retransmisiones)", 1,
		re(`Death by retransmission|Maximum number of retransmissions|retransmission count exceeded`),
		"Se agotaron las retransmisiones sin respuesta: el par no recibe o no contesta IKE.",
		"Comprueba alcance a la IP del par, que UDP 500 (y 4500 con NAT) no esté filtrado en el camino, que el par tenga crypto map/perfil en esa interfaz y la dirección de peer correcta."},
	{"retrans-key-exch", "aviso", "Retransmisiones en MM_KEY_EXCH", 1,
		re(`retransmitting phase 1 MM_KEY_EXCH`),
		"La propuesta ya se aceptó y el DH terminó, pero los mensajes 5/6 no se completan: PSK distinta o, si hay NAT, UDP 4500 bloqueado.",
		"Revisa la PSK y que UDP 4500 pase entre los pares."},
	{"proxy-id", "error", "Proxy IDs / traffic selectors no coinciden", 2,
		re(`proxy identities not supported|no matching crypto map entry for remote proxy|TS_UNACCEPTABLE|INVALID_ID_INFO|Invalid ID info|traffic selectors?.*(unacceptable|not acceptable|mismatch)`),
		"Las redes protegidas (ACL de cripto / traffic selectors) que propone el par no son el espejo exacto de las locales.",
		"Haz la ACL de cripto de un lado espejo exacto de la del otro (mismas redes y máscaras, mismo protocolo/puerto); en VTI usa 'any any'."},
	{"identidad", "error", "Identidad del par no coincide con ningún perfil", 1,
		re(`peer matches \*none\* of the profiles|Failed to locate an item in the database|Profile not found|Failed to find (a )?matching (IKEv2 )?profile|Can't find a valid tunnel group|Failed to locate group|identity.*(does not match|mismatch)`),
		"La identidad que envía el par (IP, FQDN, DN) no coincide con 'match identity remote' de ningún perfil, o no existe el tunnel-group.",
		"Revisa 'match identity remote address|fqdn' del perfil IKEv2/ISAKMP (o el tunnel-group en ASA) y la 'identity local' del otro extremo."},
	{"nat-t", "info", "NAT-T: hay NAT entre los pares", 0,
		re(`NAT found|NAT detected|NAT-T is detected|float to init port 4500|[:/ ]4500\b`),
		"Se detectó NAT en el camino: IKE y ESP viajan encapsulados en UDP 4500.",
		"Permite UDP 500 y UDP 4500 entre los pares; con NAT no basta abrir ESP (IP 50). Usa la IP pública del par en PSK y peer."},
	{"lifetime", "info", "Lifetime distinto", 0,
		re(`class Life\b|life(time)?\b.*(mismatch|not acceptable)`),
		"Los lifetimes de fase 1 o 2 difieren; según la plataforma se toma el menor o se rechaza la propuesta.",
		"Iguala 'lifetime' de la política IKE y 'set security-association lifetime' en ambos extremos."},
}

// Atributos que IOS y ASA nombran al rechazar una propuesta de fase 1.
var attrMismatch = []struct {
	re   *pre
	name string
}{
	{re(`Encryption algorithm offered does not match|class Encryption`), "cifrado"},
	{re(`Hash algorithm offered does not match|class Hash`), "hash"},
	{re(`Diffie-Hellman group offered does not match|class Group`), "grupo DH"},
	{re(`Authentication method offered does not match|class Auth`), "método de autenticación"},
	{re(`class Life\b`), "lifetime"},
}

var (
	ctxP1      = re(`Checking ISAKMP transform|\bMM_|\bAG_|IKE_SA_INIT|Main Mode|New Phase 1|IKE_[IR]_MM`)
	ctxP2      = re(`Checking IPSec proposal|\bQM_|IPSEC\(|IKE_AUTH|CREATE_CHILD_SA|Quick Mode`)
	attsResult = re(`atts are (not )?acceptable`)
	noProposal = re(`NO_PROPOSAL_CHOSEN`)
	p1OK       = re(`IKE_P1_COMPLETE|authentication status:\s*authenticated|PHASE 1 COMPLETED|authentication data PASSED`)
	p2OK       = re(`IKE_QM_PHASE2_COMPLETE|PHASE 2 COMPLETED|IPSEC\(create_sa\)|Crypto tunnel is UP`)
	retransP1  = re(`retransmitting phase 1 (MM_NO_STATE|AG_INIT_EXCH)|Retransmitting packet`)
	dpdSent    = re(`R_U_THERE|Sending DPD/liveness query`)
	dpdAck     = re(`R_U_THERE_ACK|ACK to informational`)
	dpdDown    = re(`DPD.*(down|dead|not responding)`)
	pfsAttr    = re(`group is \d+`)

	openV1P1 = re(`Checking ISAKMP transform (\d+) against priority (\d+) policy`)
	openV1P2 = re(`Checking IPSec proposal (\d+)`)
	v1Attr   = re(`ISAKMP:\s{2,}(\S.*)$|ISAKMP:\s+(transform \d+, .+)$`)
	v2Mode   = re(`(Received|Expected) Policies:`)
	v2Prop   = re(`^\s*Proposal\s+\d+:\s+(.+)$`)

	ipsecLocal  = re(`local\s+ident \(addr/mask/prot/port\): \((.+)\)`)
	ipsecRemote = re(`remote ident \(addr/mask/prot/port\): \((.+)\)`)
	ipsecPeer   = re(`current_peer (\S+)`)
	ipsecCount  = re(`#([A-Za-z][A-Za-z .()-]*?):?\s+(\d+)`)
	ipsecPFS    = re(`PFS \(Y/N\): (\w)`)
	ipsecSPI    = re(`^\s*spi: 0x`)

	isakmpRow = re(`^\s*([0-9a-f.:]+)\s+([0-9a-f.:]+)\s+(MM_\w+|QM_IDLE|AG_\w+)\b`)
	asaPeer   = re(`IKE Peer: (\S+)`)
	asaState  = re(`State\s*:\s*(MM_\w+|AG_\w+|QM_\w+)`)
	ikev2Row  = re(`^\s*\d+\s+(\S+)/\d+\s+(\S+)/\d+\s+\S+\s+(READY|IN-NEG|DELETE|UP-ACTIVE|UP-IDLE|UP-NO-IKE|UP-WAITING)\b`)
	ikev2Det  = re(`^\s*Encr: `)

	sources = []struct {
		re   *pre
		name string
	}{
		{re(`ISAKMP[:(]|ISAKMP \(`), "debug crypto isakmp (IOS/IOS-XE)"}, {re(`IKEv2[:\-]`), "debug crypto ikev2 (IOS/IOS-XE)"},
		{re(`IPSEC\(`), "debug crypto ipsec"}, {re(`\[IKEv[12]`), "debug crypto ikev1/ikev2 (ASA)"},
		{ipsecLocal, "show crypto ipsec sa"}, {isakmpRow, "show crypto isakmp sa"}, {ikev2Row, "show crypto ikev2 sa"},
	}
)

var stateMeaning = map[string]string{
	"MM_NO_STATE":  "fase 1 detenida en el primer intercambio: el par no responde o rechaza la propuesta",
	"MM_WAIT_MSG2": "fase 1 detenida en el primer intercambio: el par no responde o rechaza la propuesta",
	"AG_INIT_EXCH": "Aggressive Mode sin respuesta: el par no contesta o rechaza la propuesta/identidad",
	"IN-NEG":       "IKEv2 en negociación sin terminar: sin respuesta, propuestas o autenticación",
	"MM_SA_SETUP":  "propuesta aceptada pero el intercambio DH no avanza",
	"MM_WAIT_MSG3": "propuesta aceptada pero el intercambio DH no avanza",
	"MM_WAIT_MSG4": "propuesta aceptada pero el intercambio DH no avanza",
	"MM_KEY_EXCH":  "falla en la autenticación: PSK distinta o UDP 4500 bloqueado con NAT",
	"MM_WAIT_MSG5": "falla en la autenticación: PSK distinta o UDP 4500 bloqueado con NAT",
	"MM_WAIT_MSG6": "falla en la autenticación: PSK distinta o UDP 4500 bloqueado con NAT",
	"DELETE":       "SA en borrado",
}

const maxEvidence = 5

type decoder struct {
	r        Report
	idx      map[string]int
	phase    int
	attrs    []string // atributos de fase 1 que no coinciden
	pfsLine  string
	retrans  []string
	dpdSent  []string
	dpdAcks  int
	ok       [3]bool
	activity [3]bool
	open     *Proposal
	v2Source string
	ipsec    *IPsecSA
	asaPeer  string
	lo       string // línea actual en minúscula
	memo     map[*pre][]string

	omitSA, omitIPsec int
	skipDet           bool
}

func (d *decoder) add(code, sev, title string, phase int, expl, action, ev string) {
	if i, ok := d.idx[code]; ok {
		f := &d.r.Findings[i]
		if len(f.Evidence) < maxEvidence {
			f.Evidence = append(f.Evidence, ev)
		}
		return
	}
	d.idx[code] = len(d.r.Findings)
	d.r.Findings = append(d.r.Findings, Finding{Severity: sev, Code: code, Title: title, Phase: phase, Explanation: expl, Action: action, Evidence: []string{ev}})
}

func (d *decoder) addRule(code string, phase int, ev string) {
	for _, r := range rules {
		if r.code == code {
			d.add(r.code, r.sev, r.title, phase, r.expl, r.action, ev)
			return
		}
	}
}

func (d *decoder) closeProposal(result string) {
	if d.open != nil {
		d.open.Result = result
		d.r.Proposals = append(d.r.Proposals, *d.open)
		d.open = nil
	}
}

// Topes del resultado: SAs IKE e IPsec listadas.
const maxSAs = 500

func Decode(text string) Report {
	r, _ := DecodeContext(context.Background(), text)
	return r
}

// DecodeContext es Decode cancelable: revisa ctx cada 256 líneas.
func DecodeContext(ctx context.Context, text string) (Report, error) {
	d := &decoder{idx: map[string]int{}, memo: map[*pre][]string{}}
	seen := map[string]bool{}
	for n, raw := range strings.Split(text, "\n") {
		if n&255 == 0 && ctx.Err() != nil {
			return Report{}, ctx.Err()
		}
		line := strings.TrimRight(raw, "\r ")
		ev := strings.TrimSpace(line)
		d.lo = strings.ToLower(line)
		clear(d.memo)
		if ev == "" {
			continue
		}
		for _, s := range sources {
			if !seen[s.name] && d.match(s.re, line) {
				seen[s.name] = true
				d.r.Detected = append(d.r.Detected, s.name)
			}
		}
		switch {
		case d.match(isakmpRow, line) || d.match(ikev2Row, line): // tablas show: no cambian el contexto del debug
		case d.match(ctxP2, line):
			d.phase = 2
		case d.match(ctxP1, line):
			d.phase = 1
		}
		if d.phase > 0 {
			d.activity[d.phase] = true
		}
		d.proposals(line)
		d.tables(line, ev)
		for _, r := range rules {
			if d.match(r.re, line) {
				p := r.phase
				if p == 0 {
					p = d.phase
				}
				d.add(r.code, r.sev, r.title, p, r.expl, r.action, ev)
			}
		}
		for _, a := range attrMismatch {
			if d.match(a.re, line) && !contains(d.attrs, a.name) {
				d.attrs = append(d.attrs, a.name)
			}
		}
		if (d.match(attsResult, line) && strings.Contains(strings.ToLower(line), "not")) || d.match(noProposal, line) {
			if d.phase == 2 {
				d.addRule("p2-propuesta", 2, ev)
			} else {
				d.addRule("p1-propuesta", 1, ev)
			}
		}
		if d.phase == 2 && d.match(pfsAttr, line) {
			d.pfsLine = ev
		}
		if d.match(retransP1, line) {
			d.retrans = append(d.retrans, ev)
		}
		if d.match(dpdAck, line) {
			d.dpdAcks++
		} else if d.match(dpdSent, line) {
			d.dpdSent = append(d.dpdSent, ev)
		}
		if d.match(dpdDown, line) {
			d.add("dpd", "aviso", "DPD: el par dejó de responder", 1, "", "", ev)
		}
		d.ok[1] = d.ok[1] || d.match(p1OK, line)
		d.ok[2] = d.ok[2] || d.match(p2OK, line)
	}
	d.closeProposal("")
	d.finishIPsec()
	d.aggregate()
	d.r.Note = Note
	if d.omitSA+d.omitIPsec > 0 {
		d.r.Findings = append(d.r.Findings, Finding{Severity: "aviso", Code: "limite-sas", Title: "Se omitieron SAs por exceder el tope",
			Explanation: fmt.Sprintf("El resultado lista como máximo %d SAs IKE y %d SAs IPsec; se omitieron %d SAs IKE y %d SAs IPsec.", maxSAs, maxSAs, d.omitSA, d.omitIPsec),
			Action:      "Pega solo la salida del par o túnel que investigas."})
	}
	return d.r, nil
}

func (d *decoder) addSA(s SA) {
	if d.skipDet = len(d.r.SAs) >= maxSAs; d.skipDet {
		d.omitSA++
		return
	}
	d.r.SAs = append(d.r.SAs, s)
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

func (d *decoder) proposals(line string) {
	if m := d.find(openV1P1, line); m != nil {
		d.closeProposal("")
		d.open = &Proposal{Phase: 1, Source: fmt.Sprintf("transform %s del par vs política %s", m[1], m[2])}
		return
	}
	if m := d.find(openV1P2, line); m != nil {
		d.closeProposal("")
		d.open = &Proposal{Phase: 2, Source: "propuesta " + m[1] + " del par"}
		return
	}
	if d.open != nil {
		if m := d.find(attsResult, line); m != nil {
			d.closeProposal(map[bool]string{true: "rechazada", false: "aceptada"}[m[1] != ""])
			return
		}
		if m := d.find(v1Attr, line); m != nil && !strings.Contains(line, "attributes in transform") && len(d.open.Detail) < 400 {
			a := strings.Join(strings.Fields(m[1]+m[2]), " ")
			if d.open.Detail != "" {
				a = "; " + a
			}
			d.open.Detail += a
		}
	}
	if m := d.find(v2Mode, line); m != nil {
		d.v2Source = map[string]string{"received": "recibida del par", "expected": "esperada (local)"}[strings.ToLower(m[1])]
		return
	}
	if m := d.find(v2Prop, line); m != nil && d.v2Source != "" && len(d.r.Proposals) < 100 {
		d.r.Proposals = append(d.r.Proposals, Proposal{Phase: max(d.phase, 1), Source: d.v2Source, Detail: strings.Join(strings.Fields(m[1]), " ")})
	}
}

func (d *decoder) tables(line, ev string) {
	if m := d.find(ipsecLocal, line); m != nil {
		d.finishIPsec()
		d.ipsec = &IPsecSA{Local: m[1], Counters: map[string]int{}}
	}
	if d.ipsec != nil {
		if m := d.find(ipsecRemote, line); m != nil {
			d.ipsec.Remote = m[1]
		}
		if m := d.find(ipsecPeer, line); m != nil {
			d.ipsec.Peer = m[1]
		}
		if strings.HasPrefix(ev, "#") {
			for _, m := range d.findAll(ipsecCount, line) {
				n, _ := strconv.Atoi(m[2])
				d.ipsec.Counters[strings.TrimSpace(m[1])] = n
			}
		}
		if m := d.find(ipsecPFS, line); m != nil {
			d.ipsec.PFS = m[1]
		}
		if d.match(ipsecSPI, line) {
			d.ipsec.HasSA = true
		}
	}
	if m := d.find(isakmpRow, line); m != nil {
		d.addSA(SA{Kind: "isakmp", Peer: m[1], Local: m[2], State: strings.ToUpper(m[3])})
		d.stateFinding(strings.ToUpper(m[3]), ev)
	}
	if m := d.find(asaPeer, line); m != nil {
		d.asaPeer = m[1]
	}
	if m := d.find(asaState, line); m != nil && d.asaPeer != "" {
		d.addSA(SA{Kind: "isakmp", Peer: d.asaPeer, State: strings.ToUpper(m[1])})
		d.stateFinding(strings.ToUpper(m[1]), d.asaPeer+" "+ev)
		d.asaPeer = ""
	}
	if m := d.find(ikev2Row, line); m != nil {
		d.addSA(SA{Kind: "ikev2", Local: m[1], Peer: m[2], State: strings.ToUpper(m[3])})
		d.stateFinding(strings.ToUpper(m[3]), ev)
	}
	if d.match(ikev2Det, line) && !d.skipDet && len(d.r.SAs) > 0 && d.r.SAs[len(d.r.SAs)-1].Kind == "ikev2" {
		d.r.SAs[len(d.r.SAs)-1].Detail = ev
	}
	switch s := strings.ToUpper(ev); {
	case strings.Contains(s, "QM_IDLE"), strings.Contains(s, "MM_ACTIVE"), strings.HasSuffix(s, " READY"):
		if d.match(isakmpRow, line) || d.match(ikev2Row, line) || d.match(asaState, line) {
			d.ok[1] = true
		}
	}
}

func (d *decoder) stateFinding(state, ev string) {
	if m, ok := stateMeaning[state]; ok {
		d.add("sa-estado", "aviso", "SA atascadas en negociación", 1,
			"Estados que no son QM_IDLE/MM_ACTIVE/READY indican en qué paso se detuvo la negociación.",
			"Corre el debug de la fase indicada en ambos extremos mientras generas tráfico, y pégalo aquí.", ev+"  → "+m)
	}
}

func (d *decoder) finishIPsec() {
	s := d.ipsec
	if s == nil {
		return
	}
	d.ipsec = nil
	s.Encaps, s.Decaps = s.Counters["pkts encaps"], s.Counters["pkts decaps"]
	if len(d.r.IPsec) >= maxSAs {
		d.omitIPsec++
	} else {
		d.r.IPsec = append(d.r.IPsec, *s)
	}
	ev := fmt.Sprintf("peer %s  %s → %s  encaps %d / decaps %d", s.Peer, s.Local, s.Remote, s.Encaps, s.Decaps)
	switch {
	case !s.HasSA:
		d.add("ipsec-sin-sa", "aviso", "Sin SA de IPsec para estas redes", 2,
			"La entrada existe en el crypto map pero no hay SPI de entrada ni salida: la fase 2 no se ha negociado para este par de redes.",
			"Genera tráfico interesante desde la LAN (ping con origen en la red protegida) y revisa el debug de fase 2 (proxy IDs, transform-set, PFS).", ev)
	case s.Encaps > 0 && s.Decaps == 0:
		d.add("ipsec-unidireccional", "error", "Tráfico cifrado sale pero no regresa", 2,
			"Se encapsula hacia el par pero no llega nada de vuelta: el otro extremo no responde por el túnel o el ESP de regreso se pierde.",
			"En el par: ruta de regreso hacia esta LAN, NAT exemption (no NATear el tráfico del túnel), ACL de cripto espejo y sus contadores; en el camino: ESP (IP 50) o UDP 4500 filtrados.", ev)
	case s.Decaps > 0 && s.Encaps == 0:
		d.add("ipsec-solo-entrada", "aviso", "Llega tráfico del túnel pero no sale nada", 2,
			"Se desencapsula lo que manda el par pero las respuestas locales no entran al túnel.",
			"Revisa que la ruta hacia la red remota salga por la interfaz con el crypto map / túnel, la NAT exemption local y la ACL de cripto.", ev)
	case s.Encaps == 0 && s.Decaps == 0:
		d.add("ipsec-sin-trafico", "info", "SA arriba sin tráfico", 2,
			"La fase 2 está negociada pero no pasa tráfico en ningún sentido.",
			"Confirma que el tráfico de prueba coincide con la ACL de cripto y que se enruta hacia la interfaz del túnel.", ev)
	}
	var errs []string
	for k, v := range s.Counters {
		lk := strings.ToLower(k)
		if v > 0 && (strings.Contains(lk, "error") || strings.Contains(lk, "fail") || strings.Contains(lk, "invalid") || strings.Contains(lk, "replay")) {
			errs = append(errs, fmt.Sprintf("%s=%d", k, v))
		}
	}
	if len(errs) > 0 {
		sort.Strings(errs)
		d.add("ipsec-errores", "aviso", "Contadores de error de IPsec", 2,
			"Hay errores de envío/recepción, de integridad o de anti-replay en la SA.",
			"send errors suele ser falta de SA o de ruta; recv/verify/replay failed apuntan a pérdidas, reordenamiento (QoS) o llaves desincronizadas: limpia la SA y observa si vuelven a subir.",
			"peer "+s.Peer+" "+s.Local+": "+strings.Join(errs, ", "))
	}
}

func (d *decoder) aggregate() {
	if i, ok := d.idx["p1-propuesta"]; ok && len(d.attrs) > 0 {
		d.r.Findings[i].Explanation += " Atributos que no coinciden según el equipo: " + strings.Join(d.attrs, ", ") + "."
	}
	if _, ok := d.idx["p2-propuesta"]; ok && d.pfsLine != "" {
		d.addRule("pfs", 2, d.pfsLine)
		d.r.Findings[d.idx["pfs"]].Severity = "aviso"
		d.r.Findings[d.idx["pfs"]].Explanation = "El par propone PFS (atributo 'group is N') en fase 2 y la propuesta fue rechazada: si el transform-set coincide, la causa es el PFS. " + d.r.Findings[d.idx["pfs"]].Explanation
	}
	if len(d.retrans) >= 3 {
		for _, ev := range d.retrans[len(d.retrans)-min(len(d.retrans), maxEvidence):] {
			d.addRule("sin-respuesta", 1, ev)
		}
	}
	if _, down := d.idx["dpd"]; (len(d.dpdSent) >= 3 && d.dpdAcks == 0) || down {
		for _, ev := range d.dpdSent[:min(len(d.dpdSent), maxEvidence)] {
			d.add("dpd", "aviso", "DPD: el par dejó de responder", 1, "", "", ev)
		}
		f := &d.r.Findings[d.idx["dpd"]]
		f.Explanation = "Se enviaron consultas DPD (R_U_THERE / liveness) sin respuesta: el par se reinició, perdió la SA o el camino se cortó."
		f.Action = "Verifica alcance UDP 500/4500 y el estado de la SA en el par; con 'crypto isakmp keepalive' / 'dpd' en ambos lados la SA huérfana se limpia sola."
	}
	d.r.Phase1 = d.phaseStatus(1, []string{"p1-propuesta", "psk", "psk-ausente", "sin-respuesta", "identidad"})
	d.r.Phase2 = d.phaseStatus(2, []string{"p2-propuesta", "pfs", "proxy-id"})
	if d.r.Phase2 != "falló" && d.r.Phase2 != "mixta" {
		for _, s := range d.r.IPsec {
			if s.HasSA {
				d.r.Phase2 = "establecida"
			}
		}
	}
	sort.SliceStable(d.r.Findings, func(i, j int) bool { return sevRank[d.r.Findings[i].Severity] < sevRank[d.r.Findings[j].Severity] })
}

var sevRank = map[string]int{"error": 0, "aviso": 1, "info": 2}

func (d *decoder) phaseStatus(p int, fails []string) string {
	failed := false
	for _, c := range fails {
		if _, ok := d.idx[c]; ok {
			failed = true
		}
	}
	switch {
	case failed && d.ok[p]:
		return "mixta"
	case failed:
		return "falló"
	case d.ok[p]:
		return "establecida"
	case d.activity[p]:
		return "incompleta"
	}
	return "sin datos"
}

func (r Report) Text() string {
	var b strings.Builder
	if len(r.Detected) == 0 {
		b.WriteString("No se reconoció salida de IKE/IPsec. Pega debug crypto isakmp/ikev2/ipsec o show crypto isakmp sa / ikev2 sa detail / ipsec sa.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "Detectado: %s\nFase 1: %s   Fase 2: %s\n", strings.Join(r.Detected, ", "), r.Phase1, r.Phase2)
	if len(r.Proposals) > 0 {
		b.WriteString("\nPropuestas:\n")
		for _, p := range r.Proposals {
			fmt.Fprintf(&b, "  F%d %s: %s", p.Phase, p.Source, p.Detail)
			if p.Result != "" {
				fmt.Fprintf(&b, "  → %s", p.Result)
			}
			b.WriteString("\n")
		}
	}
	if len(r.SAs) > 0 {
		b.WriteString("\nSA:\n")
		for _, s := range r.SAs {
			fmt.Fprintf(&b, "  %-6s %-18s %s %s\n", s.Kind, s.Peer, s.State, s.Detail)
		}
	}
	for _, s := range r.IPsec {
		fmt.Fprintf(&b, "\nIPsec peer %s  %s → %s  encaps %d / decaps %d  SA=%t", s.Peer, s.Local, s.Remote, s.Encaps, s.Decaps, s.HasSA)
		if s.PFS != "" {
			fmt.Fprintf(&b, "  PFS=%s", s.PFS)
		}
		b.WriteString("\n")
	}
	if len(r.Findings) > 0 {
		b.WriteString("\nHallazgos:\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n[%s] %s\n  %s\n  Acción: %s\n", f.Severity, f.Title, f.Explanation, f.Action)
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "    > %s\n", e)
		}
	}
	fmt.Fprintf(&b, "\nNota: %s\n", r.Note)
	return b.String()
}
