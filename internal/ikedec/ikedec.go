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
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Note es la nota fija del informe, en español (en otro idioma, ike.note).
var Note = i18n.Msg(i18n.Es, "ike.note", nil)

type Finding struct {
	Severity    string // error, aviso, info
	Code        string
	Title       string
	Phase       int `json:",omitempty"`
	Explanation string
	Action      string
	Evidence    []string
	x           findingX // texto de catálogo; no viaja en el JSON
}

// findingX es lo que hace falta para escribir el hallazgo en otro idioma: su clave (ike.finding.<código>), la
// de su explicación si no es la normal, los argumentos y, por cada evidencia, la línea del equipo y la clave del
// significado que se le agregó (vacía si no lleva).
type findingX struct {
	key, explKey string
	args         i18n.Args
	base         []string
	meaning      []string
}

// Key es la clave de catálogo del hallazgo: Key()+".title", ".explanation" (o ExplanationKey) y ".action".
func (f Finding) Key() string { return f.x.key }

// ExplanationKey es la clave del catálogo de la explicación (con variantes: atributos que no coinciden, PFS).
func (f Finding) ExplanationKey() string { return f.x.explKey }

// Args son los argumentos de las claves del hallazgo (vacío si no lleva).
func (f Finding) Args() i18n.Args { return f.x.args }

// In escribe el hallazgo en el idioma dado; la evidencia es salida del equipo y solo cambia el significado que se
// le agregó.
func (f Finding) In(loc string) Finding {
	f.Title = i18n.Msg(loc, f.x.key+".title", f.x.args)
	f.Explanation = i18n.Msg(loc, f.x.explKey, f.x.args)
	f.Action = i18n.Msg(loc, f.x.key+".action", f.x.args)
	if f.Evidence != nil { // nulo sigue nulo: el JSON en español no cambia
		ev := make([]string, len(f.Evidence))
		for i := range ev {
			ev[i] = f.Evidence[i]
			if f.x.meaning[i] != "" {
				ev[i] = f.x.base[i] + "  → " + i18n.Msg(loc, f.x.meaning[i], nil)
			}
		}
		f.Evidence = ev
	}
	return f
}

type Proposal struct {
	Phase   int
	Source  string // "transform 1 del par vs política 10", "recibida del par", "esperada (local)"…
	Detail  string
	Result  string `json:",omitempty"` // aceptada, rechazada
	srcKey  string
	srcArgs i18n.Args
	resKey  string
}

// SourceKey y SourceArgs son la clave de catálogo del origen de la propuesta y sus argumentos; ResultKey es
// la del resultado (ike.val.result.accepted o rejected; vacía si no hubo).
func (p Proposal) SourceKey() string     { return p.srcKey }
func (p Proposal) SourceArgs() i18n.Args { return p.srcArgs }
func (p Proposal) ResultKey() string     { return p.resKey }

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
	Detected       []string
	Phase1         string // establecida, falló, mixta, incompleta, sin datos
	Phase2         string
	Proposals      []Proposal
	SAs            []SA
	IPsec          []IPsecSA
	Findings       []Finding
	Note           string
	phase1, phase2 string // claves ike.val.phase.* de Phase1 y Phase2
}

// PhaseKeys son las claves de catálogo (ike.val.phase.*) del estado de las fases 1 y 2.
func (r Report) PhaseKeys() (string, string) { return r.phase1, r.phase2 }

// In devuelve el informe escrito en el idioma dado (es es el de siempre); lo que es salida del equipo no cambia.
func (r Report) In(loc string) Report {
	r.Phase1, r.Phase2 = i18n.Msg(loc, r.phase1, nil), i18n.Msg(loc, r.phase2, nil)
	r.Proposals = slices.Clone(r.Proposals)
	for i, p := range r.Proposals {
		r.Proposals[i].Source = i18n.Msg(loc, p.srcKey, p.srcArgs)
		if p.resKey != "" {
			r.Proposals[i].Result = i18n.Msg(loc, p.resKey, nil)
		}
	}
	if r.Findings != nil {
		fs := make([]Finding, len(r.Findings))
		for i, f := range r.Findings {
			fs[i] = f.In(loc)
		}
		r.Findings = fs
	}
	r.Note = i18n.Msg(loc, "ike.note", nil)
	return r
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
	code, sev string
	phase     int // 0 = la fase del contexto
	re        *pre
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
	{"p1-propuesta", "error", 1,
		re(`phase 1 SA policy not acceptable|no offers accepted|Failed to find a matching policy|All SA proposals found unacceptable|Mismatched attribute types|offered does not match policy`)},
	{"p2-propuesta", "error", 2,
		re(`transform proposal not supported|All IPSec SA proposals found unacceptable`)},
	{"pfs", "error", 2,
		re(`INVALID_KE_PAYLOAD|PFS.*(mismatch|does not match)`)},
	{"psk", "error", 1,
		re(`IKMP_BAD_MESSAGE|failed its sanity check or is malformed|IKMP_NOT_ENCRYPTED|reserved not zero on|Hash payload verification failed|PAYLOAD_MALFORMED|AUTHENTICATION_FAILED|authentication data FAILED|Auth exchange failed`)},
	{"psk-ausente", "error", 1,
		re(`No pre-shared key with|pre-?shared key not found`)},
	{"sin-respuesta", "error", 1,
		re(`Death by retransmission|Maximum number of retransmissions|retransmission count exceeded`)},
	{"retrans-key-exch", "aviso", 1,
		re(`retransmitting phase 1 MM_KEY_EXCH`)},
	{"proxy-id", "error", 2,
		re(`proxy identities not supported|no matching crypto map entry for remote proxy|TS_UNACCEPTABLE|INVALID_ID_INFO|Invalid ID info|traffic selectors?.*(unacceptable|not acceptable|mismatch)`)},
	{"identidad", "error", 1,
		re(`peer matches \*none\* of the profiles|Failed to locate an item in the database|Profile not found|Failed to find (a )?matching (IKEv2 )?profile|Can't find a valid tunnel group|Failed to locate group|identity.*(does not match|mismatch)`)},
	{"nat-t", "info", 0,
		re(`NAT found|NAT detected|NAT-T is detected|float to init port 4500|[:/ ]4500\b`)},
	{"lifetime", "info", 0,
		re(`class Life\b|life(time)?\b.*(mismatch|not acceptable)`)},
}

// Atributos que IOS y ASA nombran al rechazar una propuesta de fase 1.
var attrMismatch = []struct {
	re   *pre
	name string
}{
	{re(`Encryption algorithm offered does not match|class Encryption`), "ike.val.attr.encryption"},
	{re(`Hash algorithm offered does not match|class Hash`), "ike.val.attr.hash"},
	{re(`Diffie-Hellman group offered does not match|class Group`), "ike.val.attr.dh_group"},
	{re(`Authentication method offered does not match|class Auth`), "ike.val.attr.auth_method"},
	{re(`class Life\b`), "ike.val.attr.lifetime"},
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

// stateMeaning da, por estado de SA, la clave del catálogo (ike.state.*) de lo que significa.
var stateMeaning = map[string]string{
	"MM_NO_STATE":  "ike.state.phase1_stalled",
	"MM_WAIT_MSG2": "ike.state.phase1_stalled",
	"AG_INIT_EXCH": "ike.state.aggressive",
	"IN-NEG":       "ike.state.ikev2_neg",
	"MM_SA_SETUP":  "ike.state.dh_stalled",
	"MM_WAIT_MSG3": "ike.state.dh_stalled",
	"MM_WAIT_MSG4": "ike.state.dh_stalled",
	"MM_KEY_EXCH":  "ike.state.auth_failed",
	"MM_WAIT_MSG5": "ike.state.auth_failed",
	"MM_WAIT_MSG6": "ike.state.auth_failed",
	"DELETE":       "ike.state.deleting",
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

// mk arma un hallazgo con los textos de catálogo ike.finding.<código>.* en español.
func mk(code, sev string, phase int, args i18n.Args) Finding {
	key := "ike.finding." + strings.ReplaceAll(code, "-", "_")
	f := Finding{Severity: sev, Code: code, Phase: phase, x: findingX{key: key, explKey: key + ".explanation", args: args}}
	f.Title, f.Explanation, f.Action = i18n.Msg(i18n.Es, key+".title", args), i18n.Msg(i18n.Es, f.x.explKey, args), i18n.Msg(i18n.Es, key+".action", args)
	return f
}

// add suma el hallazgo (o una evidencia más a uno que ya existe). meaning es la clave del significado que se
// agrega a la línea de evidencia, o vacía.
func (d *decoder) add(code, sev string, phase int, ev, meaning string) {
	line := ev
	if meaning != "" {
		line = ev + "  → " + i18n.Msg(i18n.Es, meaning, nil)
	}
	if i, ok := d.idx[code]; ok {
		f := &d.r.Findings[i]
		if len(f.Evidence) < maxEvidence {
			f.Evidence, f.x.base, f.x.meaning = append(f.Evidence, line), append(f.x.base, ev), append(f.x.meaning, meaning)
		}
		return
	}
	d.idx[code] = len(d.r.Findings)
	f := mk(code, sev, phase, nil)
	f.Evidence, f.x.base, f.x.meaning = []string{line}, []string{ev}, []string{meaning}
	d.r.Findings = append(d.r.Findings, f)
}

func (d *decoder) addRule(code string, phase int, ev string) {
	for _, r := range rules {
		if r.code == code {
			d.add(r.code, r.sev, phase, ev, "")
			return
		}
	}
}

// closeProposal cierra la propuesta abierta; result es ike.val.result.accepted, rejected o vacío.
func (d *decoder) closeProposal(result string) {
	if d.open != nil {
		d.open.resKey = result
		if result != "" {
			d.open.Result = i18n.Msg(i18n.Es, result, nil)
		}
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
				d.add(r.code, r.sev, p, ev, "")
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
			d.add("dpd", "aviso", 1, ev, "")
		}
		d.ok[1] = d.ok[1] || d.match(p1OK, line)
		d.ok[2] = d.ok[2] || d.match(p2OK, line)
	}
	d.closeProposal("")
	d.finishIPsec()
	d.aggregate()
	d.r.Note = Note
	if d.omitSA+d.omitIPsec > 0 {
		d.r.Findings = append(d.r.Findings, mk("limite-sas", "aviso", 0, i18n.A("max", maxSAs, "sa", d.omitSA, "ipsec", d.omitIPsec)))
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

func newProposal(phase int, key string, args i18n.Args) *Proposal {
	return &Proposal{Phase: phase, Source: i18n.Msg(i18n.Es, key, args), srcKey: key, srcArgs: args}
}

func (d *decoder) proposals(line string) {
	if m := d.find(openV1P1, line); m != nil {
		d.closeProposal("")
		d.open = newProposal(1, "ike.proposal.source.v1_transform", i18n.A("transform", m[1], "policy", m[2]))
		return
	}
	if m := d.find(openV1P2, line); m != nil {
		d.closeProposal("")
		d.open = newProposal(2, "ike.proposal.source.v1_proposal", i18n.A("n", m[1]))
		return
	}
	if d.open != nil {
		if m := d.find(attsResult, line); m != nil {
			d.closeProposal(map[bool]string{true: "ike.val.result.rejected", false: "ike.val.result.accepted"}[m[1] != ""])
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
		d.v2Source = "ike.proposal.source." + strings.ToLower(m[1])
		return
	}
	if m := d.find(v2Prop, line); m != nil && d.v2Source != "" && len(d.r.Proposals) < 100 {
		p := newProposal(max(d.phase, 1), d.v2Source, nil)
		p.Detail = strings.Join(strings.Fields(m[1]), " ")
		d.r.Proposals = append(d.r.Proposals, *p)
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
		d.add("sa-estado", "aviso", 1, ev, m)
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
		d.add("ipsec-sin-sa", "aviso", 2, ev, "")
	case s.Encaps > 0 && s.Decaps == 0:
		d.add("ipsec-unidireccional", "error", 2, ev, "")
	case s.Decaps > 0 && s.Encaps == 0:
		d.add("ipsec-solo-entrada", "aviso", 2, ev, "")
	case s.Encaps == 0 && s.Decaps == 0:
		d.add("ipsec-sin-trafico", "info", 2, ev, "")
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
		d.add("ipsec-errores", "aviso", 2, "peer "+s.Peer+" "+s.Local+": "+strings.Join(errs, ", "), "")
	}
}

func (d *decoder) aggregate() {
	if i, ok := d.idx["p1-propuesta"]; ok && len(d.attrs) > 0 {
		f := &d.r.Findings[i]
		f.x.explKey, f.x.args = f.x.key+".explanation_attrs", i18n.A("attrs", strings.Join(d.attrs, ","))
		f.Explanation = i18n.Msg(i18n.Es, f.x.explKey, f.x.args)
	}
	if _, ok := d.idx["p2-propuesta"]; ok && d.pfsLine != "" {
		d.addRule("pfs", 2, d.pfsLine)
		f := &d.r.Findings[d.idx["pfs"]]
		f.Severity, f.x.explKey = "aviso", f.x.key+".explanation_rejected"
		f.Explanation = i18n.Msg(i18n.Es, f.x.explKey, nil)
	}
	if len(d.retrans) >= 3 {
		for _, ev := range d.retrans[len(d.retrans)-min(len(d.retrans), maxEvidence):] {
			d.addRule("sin-respuesta", 1, ev)
		}
	}
	if _, down := d.idx["dpd"]; (len(d.dpdSent) >= 3 && d.dpdAcks == 0) || down {
		for _, ev := range d.dpdSent[:min(len(d.dpdSent), maxEvidence)] {
			d.add("dpd", "aviso", 1, ev, "")
		}
	}
	d.r.Phase1, d.r.phase1 = d.phaseStatus(1, []string{"p1-propuesta", "psk", "psk-ausente", "sin-respuesta", "identidad"})
	d.r.Phase2, d.r.phase2 = d.phaseStatus(2, []string{"p2-propuesta", "pfs", "proxy-id"})
	if d.r.Phase2 != "falló" && d.r.Phase2 != "mixta" {
		for _, s := range d.r.IPsec {
			if s.HasSA {
				d.r.Phase2, d.r.phase2 = i18n.Msg(i18n.Es, "ike.val.phase.established", nil), "ike.val.phase.established"
			}
		}
	}
	sort.SliceStable(d.r.Findings, func(i, j int) bool { return sevRank[d.r.Findings[i].Severity] < sevRank[d.r.Findings[j].Severity] })
}

var sevRank = map[string]int{"error": 0, "aviso": 1, "info": 2}

// phaseStatus da el estado de la fase en español y su clave ike.val.phase.*.
func (d *decoder) phaseStatus(p int, fails []string) (string, string) {
	failed := false
	for _, c := range fails {
		if _, ok := d.idx[c]; ok {
			failed = true
		}
	}
	key := "ike.val.phase.no_data"
	switch {
	case failed && d.ok[p]:
		key = "ike.val.phase.mixed"
	case failed:
		key = "ike.val.phase.failed"
	case d.ok[p]:
		key = "ike.val.phase.established"
	case d.activity[p]:
		key = "ike.val.phase.incomplete"
	}
	return i18n.Msg(i18n.Es, key, nil), key
}

// Text es el informe legible en español.
func (r Report) Text() string { return r.TextIn(i18n.Es) }

// TextIn es el informe legible en el idioma dado; el texto en español es el de siempre.
func (r Report) TextIn(loc string) string {
	var b strings.Builder
	if len(r.Detected) == 0 {
		b.WriteString(i18n.Msg(loc, "ike.text.unrecognized", nil) + "\n")
		return b.String()
	}
	b.WriteString(i18n.Msg(loc, "ike.text.detected", i18n.A("sources", strings.Join(r.Detected, ", "), "phase1", r.phase1, "phase2", r.phase2)) + "\n")
	if len(r.Proposals) > 0 {
		b.WriteString("\n" + i18n.Msg(loc, "ike.text.proposals", nil) + "\n")
		for _, p := range r.Proposals {
			fmt.Fprintf(&b, "  %s", i18n.Msg(loc, "ike.text.proposal", i18n.A("phase", p.Phase, "source", i18n.Msg(loc, p.srcKey, p.srcArgs), "detail", p.Detail)))
			if p.resKey != "" {
				fmt.Fprintf(&b, "  %s", i18n.Msg(loc, "ike.text.result", i18n.A("result", p.resKey)))
			}
			b.WriteString("\n")
		}
	}
	if len(r.SAs) > 0 {
		b.WriteString("\n" + i18n.Msg(loc, "ike.text.sas", nil) + "\n")
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
		b.WriteString("\n" + i18n.Msg(loc, "ike.text.findings", nil) + "\n")
	}
	for _, f := range r.Findings {
		f = f.In(loc)
		fmt.Fprintf(&b, "\n[%s] %s\n  %s\n  %s\n", i18n.Msg(loc, "ike.val.severity."+f.Severity, nil), f.Title, f.Explanation, i18n.Msg(loc, "ike.text.action", i18n.A("action", f.Action)))
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "    > %s\n", e)
		}
	}
	fmt.Fprintf(&b, "\n%s\n", i18n.Msg(loc, "ike.text.note", i18n.A("note", i18n.Msg(loc, "ike.note", nil))))
	return b.String()
}
