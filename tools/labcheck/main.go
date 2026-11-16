// labcheck revisa la evidencia de un trabajo de Patrol para el día de laboratorio (docs/plans/validacion-labs.md):
// por playbook, los comandos rechazados, incompletos, truncados, vacíos, lentos o que no corrieron, y las líneas que
// parecen secretos sin enmascarar. Solo lee archivos: no habla con el núcleo ni con los equipos.
//
// Uso: go run ./tools/labcheck -pack packs/<paquete> [-pack ...] [-lento 30s] <carpeta del trabajo>
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/analyze"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
	"github.com/oom-netsec/MACUAHUITL/internal/mask"
	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
	"github.com/oom-netsec/MACUAHUITL/internal/playbook"
)

type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

func main() {
	var packs list
	flag.Var(&packs, "pack", "carpeta de un paquete (packs/<nombre>); repetible")
	slow := flag.Duration("lento", 30*time.Second, "un comando que tarda más que esto se reporta")
	flag.Parse()
	if flag.NArg() != 1 || len(packs) == 0 {
		fmt.Fprintln(os.Stderr, "uso: labcheck -pack packs/<paquete> [-pack ...] [-lento 30s] <carpeta del trabajo>")
		os.Exit(2)
	}
	if err := report(os.Stdout, flag.Arg(0), packs, *slow); err != nil {
		fmt.Fprintln(os.Stderr, "labcheck:", err)
		os.Exit(1)
	}
}

// Respuestas de rechazo conocidas de IOS, IOS-XE, NX-OS, AireOS, ISE, ASA/FTD y AAA; las más largas primero. El
// reporte imprime solo la marca, nunca la línea del equipo (podría traer un secreto, p. ej. un %PARSER con el comando
// registrado). Toda otra línea que empieza con «%» cuenta como rechazo sin texto. Se buscan en las primeras líneas
// (más abajo podrían ser texto de un log y no la respuesta).
var rejectMarks = []string{"% Invalid input", "% Invalid command", "% Invalid parameter", "% Incomplete command", "% Ambiguous command",
	"% Permission denied", "% Unrecognized", "% Invalid", "% Incomplete", "% Ambiguous", "Incorrect usage", "Syntax error", "ERROR: %",
	"Authorization failed", "Unsupported command", "% No such", "% No matching"}

// unknownPercent es la etiqueta de una línea con «%» que no es ni un rechazo conocido ni una función apagada: puede ser
// salida normal («% Key pair was generated at...»), así que no se presenta como rechazo.
const unknownPercent = "aviso % del equipo (revisar)"

// inactiveRe: el equipo dice que la función no está activa («% LLDP is not enabled», «% BGP not active», «%SNMP manager
// not enabled», «% Switch is not in mst mode»). No es un error del paquete: el comando existe y la función está apagada.
var inactiveRe = regexp.MustCompile(`(?i)^%.*\b(not enabled|not active|not configured|not running|is not in)\b`)

// noneRe: «%No Secure Channels» (MACsec), «% no ipv6 snooping policy attached»: nada configurado, tampoco es error.
// Acotada a esos casos: «% No such interface», «% No matching…» son rechazos (un dato que no existe en el equipo).
var noneRe = regexp.MustCompile(`(?i)^%\s*(No Secure Channels|no\s.*\bpolicy attached\b)`)

// normalPercentRe: líneas con «%» que son salida normal, no un mensaje: top (%Cpu(s)) y la fecha de la llave RSA.
var normalPercentRe = regexp.MustCompile(`^%(Cpu\(s\)|\s*Key pair was generated)`)

// inactiveOnly es inactive solo si no hay nada más que reportar: ni una marca de rechazo en las primeras líneas, ni lo
// que marcó el driver (inválido, incompleto) o el lector (truncado). Así una función apagada nunca tapa un error.
func inactiveOnly(s analyze.Section) (string, bool) {
	if s.Invalid || s.Incomplete || s.Truncated {
		return "", false
	}
	for _, p := range problems(s, s.At, time.Hour) { // sin «lento»: end = At
		if strings.HasPrefix(p, "rechazado") {
			return "", false
		}
	}
	return inactive(s.Text)
}

// inactive da la frase fija (nunca la línea del equipo) si alguna de las primeras líneas dice que la función está apagada.
func inactive(text string) (string, bool) {
	n := 0
	for _, ln := range strings.Split(text, "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		if n++; n > 5 {
			break
		}
		if m := inactiveRe.FindStringSubmatch(ln); m != nil {
			return strings.TrimPrefix(strings.ToLower(m[1]), "is "), true
		}
		if noneRe.MatchString(ln) {
			return "not configured", true
		}
	}
	return "", false
}

// Valores con pinta de secreto: tras una palabra clave (con su número de tipo opcional), key/message-digest-key con
// tipo, auth/priv 0x de SNMPv3 (NX-OS), un hash crypt ($1$, $8$, $9$...) o una llave privada. Cada alternativa
// captura el valor; los que son <MASKED:...> no cuentan. Da candidatos para revisar a mano, no veredictos.
var secretRe = regexp.MustCompile(`(?i)\b(?:password|secret|key-string|pre-shared-key|shared-secret|passphrase|community|server-key|authentication-key|wpa-psk|psk)\s+(?:[0-9]\s+)?(\S+)` +
	`|\bmessage-digest-key\s+\d+\s+md5\s+(?:[0-9]\s+)?(\S+)|\bkey\s+[0-9]\s+(\S+)|\b(?:(?:tacacs|radius)-server\s+(?:host\s+\S+\s+)?|crypto\s+isakmp\s+)key\s+(?:[0-9]\s+)?(\S+)|\b(?:auth|priv)\s+(?:\S+\s+)?(0x[0-9a-f]+)` +
	`|(\$[1-9][a-z]?\$\S{4,})|(BEGIN [A-Z ]*PRIVATE KEY)` +
	// Sin tipo de cifrado: «key X» y «token X» solo al inicio de línea (submodo; «Press any key», «Token Ring» no cuentan) y
	// «authentication text X». «key 1» (un número solo) y «key chain …» no son un valor.
	`|^\s*key\s+([A-Za-z_<*]\S*|\d+[^\s\d]\S*)|^\s*(?-i:token)\s+(\S+)|\bauthentication\s+text\s+(\S+)`)

// labelRe: un contador o estado de show, «Etiqueta de palabras : valor» con espacio a los dos lados del «:» y una
// etiqueta sin dígitos (así no calza «password 0 abc:123» ni «Community name: 123456», que sí pueden ser claves);
// benignValueRe: valores que no pueden ser una clave (un PSK WPA tiene al menos 8 caracteres).
var (
	labelRe       = regexp.MustCompile(`^\s*[A-Za-z][A-Za-z \-/().]*?\s+:\s+(\S+)\s*$`)
	benignValueRe = regexp.MustCompile(`(?i)^(enabled|disabled|yes|no|none|n/a|true|false|on|off|\d{1,7})$`)
	// structuralRe: tokens de sintaxis que pueden ir entre la palabra clave y el <MASKED:...> (tipo, formato, dirección).
	structuralRe = regexp.MustCompile(`(?i)^(\d|set-key|ascii|hex|aes|des|md5|sha|encrypted|unencrypted|key|address|local|remote|\d+\.\d+\.\d+\.\d+)$`)
)

// benignFollow: palabras que siguen a la palabra clave y no son un valor («password encryption aes», «psk provisioning»,
// «Mesh PSK Config»). «name» va aparte (maskedNear y nameCounter).
var benignFollow = map[string]bool{"encryption": true, "provisioning": true, "config": true, "configuration": true,
	"keychain(s)": true, "keychain": true, "keychains": true, "chain": true, "config-key": true, "generate": true, "zeroize": true, "exchange": true, "pubkey-chain": true, // «MKA PSK Keychain(s) Summary» (show mka keychains)
	// prosa de show password-policy y el contador de show crypto accelerator statistics (ASAv de CML, 2026-11-14)
	"length": true, "must": true, "policy": true, "complexity": true, "lifetime": true, "keys": true}

// hiddenRe: el ASA ya oculta el valor con asteriscos («enable password ***** pbkdf2»).
var hiddenRe = regexp.MustCompile(`^\*+$`)

// pcRe: «:dirección+desplazamiento» en hexadecimal, el PC de show memory allocating-process («Ion Password  :7F3A…+1A2B»).
var pcRe = regexp.MustCompile(`^:[0-9A-Fa-f]+\+[0-9A-Fa-f]+$`)

// maskedNear: tras la palabra clave solo hay tokens de sintaxis y luego un <MASKED:...> («psk set-key ascii 8 <MASKED:...>»):
// el enmascarado ya tapó el valor. Un token cualquiera antes del <MASKED: (S3cret, hunter2) puede ser la clave.
func maskedNear(after []string) bool {
	for _, t := range after[:min(len(after), 4)] {
		if strings.HasPrefix(t, "<MASKED:") {
			return true
		}
		if !structuralRe.MatchString(t) {
			return false
		}
	}
	return false
}

// nameCounter: «community name» al final de la línea o seguido de «supplied» es un contador de show snmp
// («0 Unknown community name»), no una comunidad; «community name S3cret» sí se marca.
func nameCounter(ln string, a, b int) bool {
	rest := strings.TrimSpace(ln[b:])
	return strings.EqualFold(ln[a:b], "name") && (rest == "" || rest == "supplied")
}

// secretAt dice si la línea trae un valor con pinta de secreto que no sea <MASKED:...>, con la palabra clave y el
// largo de lo que la sigue hasta el fin de línea. El reporte imprime solo eso: el regex captura un token y el secreto
// puede ser otro de la misma línea (ntp authentication-key 1 md5 X, pre-shared-key local X...), así que nada del
// texto de la línea sale, ni lo que va antes.
func secretAt(ln string) (kw string, n int, ok bool) {
	// Lo citado entre comillas (show tech del ASA: «*** Output from config line N, "…"», ERROR:/WARNING: que repiten
	// una línea de configuración) se revisa sin los descartes de la salida normal: ahí pueden esconder una clave real.
	for _, q := range quotedRe.FindAllStringSubmatch(ln, -1) {
		if kw, n, ok := scan(q[1], true); ok {
			return kw, n, true
		}
	}
	if l := labelRe.FindStringSubmatch(ln); l != nil && benignValueRe.MatchString(l[1]) {
		return "", 0, false // «Wrong PSK : 132», «PSK : Enabled»: contador o estado, no una clave
	}
	return scan(ln, false)
}

// quotedRe: un segmento entre comillas dobles.
var quotedRe = regexp.MustCompile(`"([^"]*)"`)

// scan busca un valor con pinta de secreto sin <MASKED:...>; strict deja fuera los descartes de la salida normal
// (palabras de configuración, PC de show memory, contadores de community, <MASKED: cercano).
func scan(ln string, strict bool) (kw string, n int, ok bool) {
	for _, m := range secretRe.FindAllStringSubmatchIndex(ln, -1) {
		if !strict && maskedNear(strings.Fields(ln[m[0]:])[1:]) {
			continue
		}
		for g := 2; g < len(m); g += 2 {
			if m[g] < 0 || strings.HasPrefix(ln[m[g]:], "<MASKED:") {
				continue
			}
			if hiddenRe.MatchString(ln[m[g]:m[g+1]]) { // asteriscos: ya oculto, también dentro de una cita
				continue
			}
			if !strict && (benignFollow[strings.ToLower(ln[m[g]:m[g+1]])] || pcRe.MatchString(ln[m[g]:m[g+1]]) || nameCounter(ln, m[g], m[g+1])) {
				continue
			}
			word := strings.Fields(ln[m[0]:m[1]])[0]
			switch {
			case strings.HasPrefix(word, "$"):
				kw = "hash"
			case strings.EqualFold(word, "begin"):
				kw = "llave privada"
			default:
				kw = strings.ToLower(word) // una de las palabras del regex
			}
			return kw, utf8.RuneCountInString(strings.TrimSpace(ln[m[0]+len(word):])), true
		}
	}
	return "", 0, false
}

// Cabecera de sección que escribe patrol.Writer; una línea del equipo que la imita viene escapada con «\».
var headerRe = regexp.MustCompile(`^===== (?:(?:ronda|round) \d+ · )?\S+ · (.*?)(?: · (?:comando inválido|invalid command))?(?: · (?:incompleto|incomplete))? =====$`)

// secretsIn busca candidatos a secreto en los .txt de la carpeta de un equipo, con archivo y número de línea para que
// el dueño los abra él mismo. Los iguales (comando, palabra clave y largo) salen en una línea con todas sus ubicaciones.
func secretsIn(jobDir, dev string) (out []string, err error) {
	ents, err := os.ReadDir(filepath.Join(jobDir, dev))
	if err != nil {
		return nil, err
	}
	var keys []string
	locs := map[string][]string{}
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".txt" {
			continue
		}
		rel := filepath.Join(dev, e.Name())
		f, err := os.Open(filepath.Join(jobDir, rel))
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 16<<20)
		cmd := ""
		for n := 1; sc.Scan(); n++ {
			ln := sc.Text()
			if m := headerRe.FindStringSubmatch(ln); m != nil {
				cmd = m[1] // texto del playbook, no del equipo
				continue
			}
			kw, size, ok := secretAt(ln)
			if !ok {
				continue
			}
			k := fmt.Sprintf("`%s` · %s ⟦secreto? %d car.⟧", cmd, kw, size)
			if locs[k] == nil {
				keys = append(keys, k)
			}
			locs[k] = append(locs[k], fmt.Sprintf("%s:%d", rel, n))
		}
		err = sc.Err()
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
	}
	for _, k := range keys {
		out = append(out, "- "+k+" · "+strings.Join(locs[k], ", "))
	}
	return out, nil
}

// align empareja cada sección de la evidencia con un comando esperado (en orden) maximizando los emparejamientos: la
// subsecuencia común más larga. Una búsqueda hacia adelante sin más se iba hasta otra aparición lejana de un comando que
// la versión del paquete ya no trae en su lugar, y dejaba como «no corrió» todo lo de en medio. Marca exp[j].done y da,
// por sección, los playbooks que la pidieron (vacío = fuera de playbook).
func align(secs []analyze.Section, exp []expected) [][]string {
	n, m := len(secs), len(exp)
	dp := make([][]int32, n+1) // dp[i][j]: emparejamientos posibles entre secs[i:] y exp[j:]
	for i := range dp {
		dp[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			switch {
			case secs[i].Command == exp[j].cmd:
				dp[i][j] = dp[i+1][j+1] + 1
			case dp[i+1][j] >= dp[i][j+1]:
				dp[i][j] = dp[i+1][j]
			default:
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	pbOf := make([][]string, n)
	for i, j := 0, 0; i < n && j < m; {
		switch {
		case secs[i].Command == exp[j].cmd && dp[i][j] == dp[i+1][j+1]+1:
			exp[j].done, pbOf[i] = true, exp[j].pbs
			i, j = i+1, j+1
		case dp[i][j+1] >= dp[i+1][j]: // ante un empate, saltar lo esperado: la sección puede emparejar más adelante
			j++
		default:
			i++
		}
	}
	return pbOf
}

// expected es un comando que debió correr y los playbooks que lo pidieron (con la deduplicación de patrol, varios).
type expected struct {
	pbs  []string
	cmd  string
	done bool
}

// expect da los comandos esperados en orden. Patrol corre cada uno una sola vez por equipo y ronda (patrol.Dedupe):
// se aplica la misma regla y cada uno se atribuye a todos los playbooks que lo pidieron. Una evidencia con secciones
// repetidas es de antes de la deduplicación: se espera la lista cruda, un comando por playbook, como entonces.
func expect(items []patrol.Item, secs []analyze.Section) (exp []expected) {
	seen := map[string]bool{}
	legacy := false
	for _, s := range secs {
		legacy = legacy || seen[s.Command]
		seen[s.Command] = true
	}
	if legacy {
		for _, it := range items {
			exp = append(exp, expected{pbs: []string{it.PB}, cmd: it.Cmd.Text})
		}
		return exp
	}
	cmds, req := patrol.Dedupe(items)
	first := map[string]string{}
	for _, it := range items {
		if _, ok := first[it.Cmd.Text]; !ok {
			first[it.Cmd.Text] = it.PB
		}
	}
	for _, c := range cmds {
		pbs := req[c.Text]
		if pbs == nil {
			pbs = []string{first[c.Text]}
		}
		exp = append(exp, expected{pbs: pbs, cmd: c.Text})
	}
	return exp
}

func report(w io.Writer, jobDir string, packDirs []string, slow time.Duration) error {
	raw, err := os.ReadFile(filepath.Join(jobDir, "manifest.json"))
	if err != nil {
		return fmt.Errorf("%w (el trabajo debe estar cerrado: el manifest se escribe al final)", err)
	}
	var m patrol.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("manifest.json: %w", err)
	}
	pbs := map[string]playbook.Playbook{}
	for _, d := range packDirs {
		if fi, err := os.Stat(filepath.Join(d, "playbooks")); err == nil && fi.IsDir() {
			d = filepath.Join(d, "playbooks")
		}
		got, err := playbook.Load(os.DirFS(d))
		if err != nil {
			return fmt.Errorf("%s: %w", d, err)
		}
		for _, p := range got {
			pbs[p.ID] = p
		}
	}
	fmt.Fprintf(w, "# labcheck · %s\n\n", filepath.Base(jobDir))
	if !m.Masked { // el manifest siempre trae masked; false = el trabajo corrió con disable_masking
		fmt.Fprintf(w, "AVISO: %s\n\n", i18n.Msg(i18n.Es, "evidence.unmasked", nil))
	}
	if len(m.Devices) == 0 {
		return errors.New("el manifest no trae equipos: no corrió ninguna ronda")
	}
	for _, r := range m.Devices {
		fmt.Fprintf(w, "- %s (%s) ronda %d: %s · %d comandos, %d inválidos según el driver", r.Hostname, r.Target.Address, r.Round, r.State, r.Commands, r.Invalid)
		if _, _, secret := secretAt(r.Detail); secret {
			fmt.Fprint(w, " · (detalle omitido: parece traer un secreto; míralo en la auditoría)")
		} else if r.Detail != "" {
			fmt.Fprintf(w, " · %s", r.Detail)
		}
		if len(r.CutCommands) > 0 { // los comandos cortados no tienen salida: se listan para repetirlos a mano
			q := make([]string, len(r.CutCommands))
			for i, c := range r.CutCommands {
				if m.Masked {
					c = mask.Cmd(r.Platform, c)
				}
				q[i] = fmt.Sprintf("%q", c)
			}
			fmt.Fprintf(w, " · comandos cortados: %s · %d reconexiones", strings.Join(q, ", "), r.Reconnects)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "- enmascarado: %v · conteos: %v\n", m.Masked, m.MaskCounts)

	issues := map[string][]string{} // playbook -> líneas
	var order, outside, notes, secrets, inactives []string
	// Sin salidas (el equipo falló al conectar) analyze da error: el estado ya salió arriba y lo demás queda «no corrió».
	b, err := analyze.Load(jobDir)
	if err != nil {
		notes, b = append(notes, "- "+err.Error()), &analyze.Bundle{}
	}
	if zips, _ := filepath.Glob(filepath.Join(jobDir, "*.zip")); len(zips) > 0 {
		notes = append(notes, "- hay .zip en la carpeta: labcheck no busca secretos dentro (usa zip: ZIP_POLICY_NONE)")
	}
	for _, wn := range b.Warnings { // lo que el lector no pudo leer entero: lo que sigue puede salir como «no corrió»
		notes = append(notes, fmt.Sprintf("- %s · `%s`: %s", wn.Device, wn.Command, wn.Msg))
	}
	for _, r := range m.Devices {
		// shortcut: sin Ran se toman todos los playbooks del manifest; en un trabajo con varios equipos y gemelos
		// (ios/ios-xe) los del otro equipo saldrían como «no corrió». El runbook usa un equipo por trabajo.
		ids := r.Ran
		if ids == nil {
			for _, p := range m.Playbooks {
				ids = append(ids, p.ID)
			}
		}
		var items []patrol.Item
		for _, id := range ids {
			if !slices.Contains(order, id) {
				order = append(order, id)
			}
			p, ok := pbs[id]
			if !ok {
				issues[id] = append(issues[id], "- no está en los paquetes dados (-pack): no se revisó")
				continue
			}
			vals := map[string]string{}
			for _, q := range p.Params {
				if v, ok := m.Params[q.Name]; ok {
					vals[q.Name] = v
				}
			}
			cmds, err := p.Expand(vals)
			if err != nil {
				issues[id] = append(issues[id], fmt.Sprintf("- sus datos no sirven (%v): no se revisó", err))
				continue
			}
			for _, c := range p.Pre {
				items = append(items, patrol.Item{Cmd: playbook.Command{Text: c, Timeout: 60 * time.Second}, PB: id})
			}
			for _, c := range cmds {
				if c.Applies(r.Platform) { // como patrol.commands: los de otra plataforma no corren ni se esperan
					items = append(items, patrol.Item{Cmd: c, PB: id})
				}
			}
		}
		dev := patrol.DeviceDirOf(r.Hostname, r.Target)
		var secs []analyze.Section
		for _, s := range b.Sections {
			if s.Device == dev && s.Round == r.Round {
				secs = append(secs, s)
			}
		}
		exp := expect(items, secs)
		pbOf := align(secs, exp)
		for i, s := range secs {
			pbs := pbOf[i]
			end := m.EndedAt
			if i+1 < len(secs) {
				end = secs[i+1].At
			}
			if phrase, ok := inactiveOnly(s); ok { // función apagada en el equipo: no es un problema del paquete
				if line := fmt.Sprintf("- `%s` — %s", s.Command, phrase); !slices.Contains(inactives, line) { // el mismo comando en varios playbooks
					inactives = append(inactives, line)
				}
				continue
			}
			for _, prob := range problems(s, end, slow) {
				line := fmt.Sprintf("- `%s` — %s", s.Command, prob)
				if len(pbs) == 0 {
					outside = append(outside, line)
				}
				for _, pb := range pbs { // un comando pedido por varios playbooks falla en todos
					issues[pb] = append(issues[pb], line)
				}
			}
			if len(pbs) == 0 && len(problems(s, end, slow)) == 0 {
				outside = append(outside, fmt.Sprintf("- `%s`", s.Command))
			}
		}
		if sec, err := secretsIn(jobDir, dev); err == nil {
			secrets = append(secrets, sec...)
		} else if !errors.Is(err, fs.ErrNotExist) {
			notes = append(notes, "- secretos sin revisar: "+err.Error())
		}
		for _, e := range exp {
			if !e.done {
				for _, pb := range e.pbs {
					issues[pb] = append(issues[pb], fmt.Sprintf("- `%s` — no corrió (sin salida en la evidencia)", e.cmd))
				}
			}
		}
	}

	clean := 0
	for _, id := range order {
		if len(issues[id]) == 0 {
			clean++
			continue
		}
		name := pbs[id].NameEn
		if name == "" {
			name = pbs[id].Name
		}
		fmt.Fprintf(w, "\n## %s · %s\n\n%s\n", id, name, strings.Join(issues[id], "\n"))
	}
	fmt.Fprintf(w, "\n%d de %d playbooks sin problemas.\n", clean, len(order))
	for _, part := range []struct {
		title string
		lines []string
	}{{"Fuera de playbook", outside}, {"Funciones no activas en el equipo (no son errores del paquete)", inactives}, {"Avisos", notes}, {"Posibles secretos sin enmascarar (revisar a mano)", secrets}} {
		if len(part.lines) > 0 {
			fmt.Fprintf(w, "\n## %s\n\n%s\n", part.title, strings.Join(part.lines, "\n"))
		}
	}
	return nil
}

// problems da lo que falla en la salida de un comando; end es cuándo empezó el siguiente (o el fin del trabajo).
func problems(s analyze.Section, end time.Time, slow time.Duration) (out []string) {
	rejected := ""
	n := 0
	for _, ln := range strings.Split(s.Text, "\n") {
		if ln = strings.TrimSpace(ln); ln == "" {
			continue
		}
		if n++; n > 5 {
			break
		}
		if normalPercentRe.MatchString(ln) {
			continue
		}
		if i := slices.IndexFunc(rejectMarks, func(mk string) bool { return strings.Contains(strings.ToLower(ln), strings.ToLower(mk)) }); i >= 0 {
			rejected = rejectMarks[i]
			break
		}
		if strings.HasPrefix(ln, "%") {
			rejected = unknownPercent
			break
		}
	}
	switch {
	case rejected == unknownPercent:
		out = append(out, unknownPercent)
	case rejected != "":
		out = append(out, "rechazado: "+rejected)
	case s.Invalid:
		out = append(out, "rechazado (marcado por el driver)")
	}
	if s.Incomplete {
		out = append(out, "incompleto (se cortó o falló)")
	}
	if s.Truncated {
		out = append(out, "truncado al leer (tope de analyze)")
	}
	if strings.TrimSpace(s.Text) == "" {
		out = append(out, "salida vacía")
	}
	if d := end.Sub(s.At); !s.At.IsZero() && d > slow {
		out = append(out, fmt.Sprintf("lento: %d s", int(d.Round(time.Second)/time.Second)))
	}
	return out
}
