package assist

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Catálogo de plantillas (fase 28b): cada snippet declara sus campos tipados para que la UI arme el formulario sin código por snippet,
// su lista cerrada (Function) y cómo se planea. La validación de ValidateValues es la autoritativa; la de la UI solo ayuda.

// FieldType es el tipo de un campo; la UI lo mapea a un control.
type FieldType string

const (
	TypeText       FieldType = "text"
	TypeInt        FieldType = "int"
	TypeDecimal    FieldType = "decimal" // hasta dos decimales
	TypeBool       FieldType = "bool"    // "true" o "false"
	TypeChoice     FieldType = "choice"
	TypeIPv4       FieldType = "ipv4"
	TypeIPv4Mask   FieldType = "ipv4_mask" // máscara decimal con puntos, contigua
	TypeInterface  FieldType = "interface" // un puerto físico o un Port-channel
	TypeInterfaces FieldType = "interfaces"
	TypeVlanID     FieldType = "vlan_id"
	TypeSecret     FieldType = "secret"
)

// FieldTypes son todos los tipos conocidos.
var FieldTypes = []FieldType{TypeText, TypeInt, TypeDecimal, TypeBool, TypeChoice, TypeIPv4, TypeIPv4Mask, TypeInterface, TypeInterfaces, TypeVlanID, TypeSecret}

// TechOrder es el orden de las tecnologías en el catálogo.
var TechOrder = []string{"l2", "l3", "gestion", "seguridad", "qos", "etherchannel"}

// maxText es el largo máximo de un texto cuando el campo no fija otro.
const maxText = 200

// Field es un campo del formulario de una plantilla. Min y Max acotan el valor de un int, decimal o vlan_id (Max 0 = sin tope) y el largo de
// un text o secret. Un valor vacío cuenta como ausente. Default es solo una sugerencia para la UI.
type Field struct {
	Name, Label string
	Type        FieldType
	Required    bool
	Min, Max    float64
	Pattern     string
	Choices     []string
	Default     string
	Help        string
}

// Values son los valores de un formulario, por nombre de campo.
type Values map[string]string

// Str, Int, Bool y Has leen un valor ya validado (ausente = vacío, 0, false).
func (v Values) Str(name string) string { return strings.TrimSpace(v[name]) }
func (v Values) Has(name string) bool   { return v.Str(name) != "" }
func (v Values) Int(name string) int    { n, _ := strconv.Atoi(v.Str(name)); return n }
func (v Values) Bool(name string) bool  { return v.Str(name) == "true" }

// Float lee un decimal ya validado.
func (v Values) Float(name string) float64 { f, _ := strconv.ParseFloat(v.Str(name), 64); return f }

// Template es un snippet del catálogo.
type Template struct {
	ID, Tech, Name string
	Platforms      []string
	Fields         []Field
	Fn             Function
	// Pre da los comandos de lectura que hay que correr para planear; Plan arma el plan de un equipo con sus salidas.
	// Ambos reciben valores que ya pasaron ValidateValues y aun así rechazan lo que su reversa no sabría deshacer.
	Pre  func(Values) ([]string, error)
	Plan func(device string, v Values, outs map[string]string) (DevicePlan, error)
}

// ErrInvalidValues envuelve todo rechazo de ValidateValues.
var ErrInvalidValues = errors.New("assist: valores del snippet inválidos")

func compilePattern(p string) (*regexp.Regexp, error) { return regexp.Compile(p) }

var decimalRe = regexp.MustCompile(`^\d{1,3}(\.\d{1,2})?$`)

// ValidateValues revisa los valores de un formulario contra los campos de la plantilla: claves desconocidas, obligatorias que faltan,
// tipo, rango, patrón y ASCII imprimible. Junta todos los problemas en un error. El valor de un secret jamás aparece en un mensaje.
func ValidateValues(t Template, v Values) error {
	var bad []string
	byName := map[string]Field{}
	for _, f := range t.Fields {
		byName[f.Name] = f
	}
	for _, k := range sortedKeys(v) {
		if _, ok := byName[k]; !ok {
			bad = append(bad, fmt.Sprintf("campo desconocido %q", k)) // solo el nombre, nunca el valor
		}
	}
	for _, f := range t.Fields {
		val, has := v[f.Name], strings.TrimSpace(v[f.Name]) != ""
		if !has {
			if f.Required {
				bad = append(bad, fmt.Sprintf("falta %s (%s)", f.Label, f.Name))
			}
			continue
		}
		if err := checkValue(f, val); err != nil {
			bad = append(bad, fmt.Sprintf("%s (%s): %v", f.Label, f.Name, err))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrInvalidValues, strings.Join(bad, "; "))
}

func sortedKeys(v Values) []string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// checkValue valida un valor no vacío. Los errores de un secret no citan el valor.
func checkValue(f Field, val string) error {
	if f.Type == TypeSecret {
		return checkSecretField(f, val)
	}
	if err := asciiOnly(val); err != nil {
		return err
	}
	if strings.ContainsAny(val, "?\t") {
		return fmt.Errorf("%q: '?' y el tabulador no se admiten", val)
	}
	if strings.TrimSpace(val) != val && f.Type != TypeText {
		return fmt.Errorf("%q: sin espacios al inicio ni al final", val)
	}
	switch f.Type {
	case TypeText:
		hi := maxText
		if f.Max > 0 {
			hi = int(f.Max)
		}
		if n := len(strings.TrimSpace(val)); n < int(f.Min) || n > hi {
			return fmt.Errorf("mide %d caracteres y debe medir entre %d y %d", n, int(f.Min), hi)
		}
		if f.Pattern != "" {
			re, err := compilePattern(f.Pattern)
			if err != nil {
				return errors.New("patrón interno inválido")
			}
			if !re.MatchString(strings.TrimSpace(val)) {
				return fmt.Errorf("%q no cumple el formato esperado", val)
			}
		}
	case TypeInt, TypeVlanID:
		n, err := strconv.Atoi(val)
		if err != nil || ntoa(n) != val {
			return fmt.Errorf("%q no es un entero (sin signo ni ceros a la izquierda)", val)
		}
		lo, hi := f.Min, f.Max
		if f.Type == TypeVlanID {
			lo, hi = max(lo, 1), 4094
			if f.Max > 0 {
				hi = min(f.Max, 4094)
			}
		}
		if float64(n) < lo || (hi > 0 && float64(n) > hi) {
			return fmt.Errorf("%d fuera de %s", n, rangeText(lo, hi))
		}
	case TypeDecimal:
		if !decimalRe.MatchString(val) {
			return fmt.Errorf("%q no es un número con hasta dos decimales", val)
		}
		x, _ := strconv.ParseFloat(val, 64)
		if x < f.Min || (f.Max > 0 && x > f.Max) {
			return fmt.Errorf("%s fuera de %s", val, rangeText(f.Min, f.Max))
		}
	case TypeBool:
		if val != "true" && val != "false" {
			return fmt.Errorf("%q: solo true o false", val)
		}
	case TypeChoice:
		if !slices.Contains(f.Choices, val) {
			return fmt.Errorf("%q: elige una de %s", val, strings.Join(f.Choices, ", "))
		}
	case TypeIPv4:
		a, err := netip.ParseAddr(val)
		if err != nil || !a.Is4() {
			return fmt.Errorf("dirección IPv4 inválida %q", val)
		}
	case TypeIPv4Mask:
		if _, err := maskBits(val); err != nil {
			return err
		}
	case TypeInterface:
		if !ValidTrunkInterface(val) {
			return fmt.Errorf("%q no es un puerto físico ni un Port-channel", val)
		}
	case TypeInterfaces:
		if _, err := ParseInterfaceList(val); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tipo de campo desconocido %q", f.Type)
	}
	return nil
}

func rangeText(lo, hi float64) string {
	if hi > 0 {
		return fmt.Sprintf("%g-%g", lo, hi)
	}
	return fmt.Sprintf("%g o más", lo)
}

// checkSecretField: ASCII visible sin espacios ni '?', del largo pedido; el error no cita el valor.
func checkSecretField(f Field, val string) error {
	hi := 64
	if f.Max > 0 {
		hi = int(f.Max)
	}
	for _, r := range val {
		if r <= 0x20 || r > 0x7e || r == '?' {
			return errors.New("el secreto lleva caracteres no permitidos (solo ASCII visible, sin espacios ni '?')")
		}
	}
	if len(val) < int(f.Min) || len(val) > hi {
		return fmt.Errorf("el secreto debe medir entre %d y %d caracteres", int(f.Min), hi)
	}
	return nil
}

// maskBits lee una máscara decimal con puntos contigua de /1 a /32 y devuelve sus bits.
func maskBits(m string) (int, error) {
	a, err := netip.ParseAddr(m)
	if err != nil || !a.Is4() {
		return 0, fmt.Errorf("máscara inválida %q (usa la forma 255.255.255.0)", m)
	}
	b := a.As4()
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	ones := 0
	for ones < 32 && v&(1<<(31-ones)) != 0 {
		ones++
	}
	if ones == 0 || v<<ones != 0 {
		return 0, fmt.Errorf("máscara %q no contigua", m)
	}
	return ones, nil
}

var ifaceRangeRe = regexp.MustCompile(`^(.+/)(\d+)-(\d+)$`)

const maxIfaceList = 48

// ParseInterfaceList lee el valor de un campo `interfaces`: nombres separados por comas o espacios, con rangos del último número
// (Gi1/0/1-4). Solo puertos físicos, sin repetidos (normIfaces) y hasta 48.
func ParseInterfaceList(s string) ([]string, error) {
	var names []string
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		m := ifaceRangeRe.FindStringSubmatch(tok)
		if m == nil {
			names = append(names, tok)
			continue
		}
		lo, _ := strconv.Atoi(m[2])
		hi, _ := strconv.Atoi(m[3])
		if lo > hi || hi-lo >= maxIfaceList {
			return nil, fmt.Errorf("rango %q inválido (de menor a mayor y hasta %d puertos)", tok, maxIfaceList)
		}
		for n := lo; n <= hi; n++ {
			names = append(names, m[1]+ntoa(n))
		}
	}
	out, err := normIfaces(names)
	if err == nil && len(out) > maxIfaceList {
		return nil, fmt.Errorf("más de %d puertos en un solo plan", maxIfaceList)
	}
	return out, err
}

// Templates devuelve el catálogo en orden: por tecnología (TechOrder) y, dentro de cada una, el orden en que se declaran.
func Templates() []Template {
	all := slices.Concat(baseTemplates(), l2PortTemplates(), l3MgmtTemplates())
	slices.SortStableFunc(all, func(a, b Template) int { return slices.Index(TechOrder, a.Tech) - slices.Index(TechOrder, b.Tech) })
	return all
}

// TemplateByID busca una plantilla del catálogo.
func TemplateByID(id string) (Template, bool) {
	for _, t := range Templates() {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// DescribeValues resume los valores no secretos de un formulario para la auditoría, en el orden de los campos.
func DescribeValues(t Template, v Values) string {
	var parts []string
	for _, f := range t.Fields {
		if f.Type != TypeSecret && v.Has(f.Name) {
			parts = append(parts, f.Name+"="+v.Str(f.Name))
		}
	}
	return "plantilla=" + t.ID + " " + strings.Join(parts, " ")
}

var bothPlatforms = []string{"ios", "ios-xe"}

// baseTemplates son los snippets que ya existían (VLAN, trunk, SVI) y la descripción de puertos, como adaptadores: su lógica no cambia.
func baseTemplates() []Template {
	vlanChange := func(v Values) VlanChange {
		return VlanChange{ID: v.Int("id"), Name: v.Str("name"), AcceptVTP: v.Bool("accept_vtp"), Remove: v.Bool("remove"), AcceptTrunk: v.Bool("accept_trunk")}
	}
	trunkChange := func(v Values) TrunkChange {
		return TrunkChange{Interface: v.Str("interface"), Op: v.Str("op"), Vlan: v.Int("vlan")}
	}
	sviChange := func(v Values) SVIChange {
		c := SVIChange{VlanID: v.Int("vlan"), Address: v.Str("address"), Mask: v.Str("mask")}
		if v.Has("description") {
			d := v.Str("description")
			c.Description = &d
		}
		return c
	}
	descChange := func(v Values) (PortChange, error) {
		switch {
		case v.Has("description") && v.Bool("remove"):
			return PortChange{}, errors.New("indica la descripción o marca quitarla, no las dos")
		case v.Bool("remove"):
			return PortChange{Description: strPtr("")}, nil
		case v.Has("description"):
			return PortChange{Description: strPtr(v.Str("description"))}, nil
		}
		return PortChange{}, errors.New("indica la descripción o marca quitarla")
	}
	return []Template{
		{ID: "vlan", Tech: "l2", Name: "Crear, nombrar o borrar una VLAN", Platforms: bothPlatforms, Fn: SnippetVlan,
			Fields: []Field{
				{Name: "id", Label: "VLAN", Type: TypeVlanID, Required: true, Min: 2, Max: 4094, Help: "2-4094; las reservadas 1002-1005 no se tocan."},
				{Name: "name", Label: "Nombre", Type: TypeText, Pattern: `^[A-Za-z0-9_.-]+$`, Max: 32, Help: "Letras, números, _ . -; sin espacios. Vacío crea la VLAN con su nombre por omisión."},
				{Name: "remove", Label: "Borrar la VLAN", Type: TypeBool, Default: "false", Help: "Solo una VLAN activa, sin puertos, SVI ni trunk nativo; no lleva nombre."},
				{Name: "accept_vtp", Label: "Aceptar que se propague por VTP", Type: TypeBool, Default: "false"},
				{Name: "accept_trunk", Label: "Aceptar borrar una VLAN que viaja por trunks", Type: TypeBool, Default: "false"},
			},
			Pre: func(v Values) ([]string, error) { return VlanPre(vlanChange(v)) },
			Plan: func(d string, v Values, o map[string]string) (DevicePlan, error) {
				return VlanPlan(d, vlanChange(v), o)
			}},
		{ID: "trunk", Tech: "l2", Name: "Agregar o quitar una VLAN de un trunk", Platforms: bothPlatforms, Fn: SnippetTrunk,
			Fields: []Field{
				{Name: "interface", Label: "Trunk", Type: TypeInterface, Required: true, Help: "Puerto físico o Port-channel que ya sea trunk."},
				{Name: "op", Label: "Operación", Type: TypeChoice, Required: true, Choices: []string{"add", "remove"}, Default: "add", Help: "Nunca reemplaza la lista permitida."},
				{Name: "vlan", Label: "VLAN", Type: TypeVlanID, Required: true, Min: 1, Max: 4094},
			},
			Pre: func(v Values) ([]string, error) { return TrunkPre(trunkChange(v)) },
			Plan: func(d string, v Values, o map[string]string) (DevicePlan, error) {
				return TrunkPlan(d, trunkChange(v), o)
			}},
		{ID: "descripcion", Tech: "l2", Name: "Descripción de puertos", Platforms: bothPlatforms, Fn: Ports,
			Fields: []Field{
				{Name: "interfaces", Label: "Puertos", Type: TypeInterfaces, Required: true, Help: "Lista separada por comas o rangos como Gi1/0/1-4; solo puertos físicos de acceso."},
				{Name: "description", Label: "Descripción", Type: TypeText, Max: 200},
				{Name: "remove", Label: "Quitar la descripción", Type: TypeBool, Default: "false"},
			},
			Pre: func(v Values) ([]string, error) {
				ifs, err := ParseInterfaceList(v.Str("interfaces"))
				if err != nil {
					return nil, err
				}
				return PortsPre(ifs, PortChange{})
			},
			Plan: func(d string, v Values, o map[string]string) (DevicePlan, error) {
				ifs, err := ParseInterfaceList(v.Str("interfaces"))
				if err != nil {
					return DevicePlan{}, err
				}
				ch, err := descChange(v)
				if err != nil {
					return DevicePlan{}, err
				}
				return PortsPlan(d, ifs, ch, o)
			}},
		{ID: "svi", Tech: "l3", Name: "Interfaz VLAN (SVI) con dirección IP", Platforms: bothPlatforms, Fn: SnippetSVI,
			Fields: []Field{
				{Name: "vlan", Label: "VLAN", Type: TypeVlanID, Required: true, Min: 1, Max: 4094},
				{Name: "description", Label: "Descripción", Type: TypeText, Max: 200},
				{Name: "address", Label: "Dirección IP", Type: TypeIPv4, Required: true},
				{Name: "mask", Label: "Máscara", Type: TypeIPv4Mask, Required: true, Default: "255.255.255.0", Help: "Contigua, de /8 a /30."},
			},
			Pre:  func(v Values) ([]string, error) { return SVIPre(sviChange(v)) },
			Plan: func(d string, v Values, o map[string]string) (DevicePlan, error) { return SVIPlan(d, sviChange(v), o) }},
	}
}

func strPtr(s string) *string { return &s }
