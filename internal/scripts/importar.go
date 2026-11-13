package scripts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Estados de un script del archivo frente a los guardados.
const (
	Nuevo           = "nuevo"
	Igual           = "igual"
	ConflictoID     = "conflicto_id"
	ConflictoNombre = "conflicto_nombre"
)

// Decisiones para un conflicto (omitir también vale para un nuevo).
const (
	Renombrar  = "renombrar"
	Reemplazar = "reemplazar"
	Omitir     = "omitir"
)

// Item es un script del archivo con su estado; Con es el ID guardado con el que choca o coincide.
type Item struct {
	Script Script
	Estado string
	Con    string
}

// Plan compara los scripts del archivo con los guardados del usuario y con la biblioteca local. La biblioteca
// no se edita, pero sus nombres cuentan: un «lib-*» igual al local es «igual»; uno distinto, o un script con el
// nombre de uno de la biblioteca, es un conflicto de nombre contra ella. Un «lib-*» de otra instalación que no
// coincide con nada se importa como script del usuario con un ID nuevo.
func Plan(entrante, guardados, biblioteca []Script) []Item {
	porID, porNombre, libID, libNombre := map[string]Script{}, map[string]Script{}, map[string]Script{}, map[string]Script{}
	for _, g := range guardados {
		porID[g.ID], porNombre[NameKey(g.Name)] = g, g
	}
	for _, l := range biblioteca {
		libID[l.ID], libNombre[NameKey(l.Name)] = l, l
	}
	out := make([]Item, len(entrante))
	for i, s := range entrante {
		it := Item{Script: s, Estado: Nuevo}
		if l, ok := libID[s.ID]; ok && IsLib(s.ID) && Same(s, l) {
			it.Con, it.Estado = l.ID, Igual
		} else if g, ok := porID[s.ID]; ok && !IsLib(s.ID) {
			it.Con, it.Estado = g.ID, ConflictoID
			if Same(s, g) {
				it.Estado = Igual
			}
		} else if l, ok := libNombre[NameKey(s.Name)]; ok {
			it.Con, it.Estado = l.ID, ConflictoNombre
		} else if g, ok := porNombre[NameKey(s.Name)]; ok {
			it.Con, it.Estado = g.ID, ConflictoNombre
			if IsLib(s.ID) && Same(s, g) {
				it.Estado = Igual
			}
		}
		out[i] = it
	}
	return out
}

// Resultado de aplicar: los scripts a escribir (insertar o reemplazar por ID) y los conteos.
// IDs dice en qué ID guardado quedó cada script del archivo (por su ID en el archivo); los omitidos no aparecen.
type Resultado struct {
	Writes                              []Script
	IDs                                 map[string]string
	Created, Replaced, Renamed, Skipped int
}

// NombreLibre da «<base> (<sufijo>)», o «… (<sufijo> 2)», 3… hasta que usado deje de decir que existe;
// recorta la base para no pasar de MaxName.
func NombreLibre(base, sufijo string, usado func(string) bool) string {
	for n := 1; ; n++ {
		suf := " (" + sufijo + ")"
		if n > 1 {
			suf = fmt.Sprintf(" (%s %d)", sufijo, n)
		}
		if r := []rune(base); len(r)+len([]rune(suf)) > MaxName {
			base = strings.TrimSpace(string(r[:MaxName-len([]rune(suf))]))
		}
		if c := base + suf; !usado(c) {
			return c
		}
	}
}

// Apply convierte el plan y las decisiones (por ID del archivo) en escrituras. Falla sin escribir nada si falta
// la decisión de un conflicto, si una decisión no cabe en el estado del script, o si el resultado repetiría un nombre.
// Todo lo que escribe queda con origen usuario y, si venía de la biblioteca, con un ID nuevo.
func Apply(items []Item, dec map[string]string, guardados, biblioteca []Script, ahora time.Time) (Resultado, error) {
	r := Resultado{IDs: map[string]string{}}
	enArchivo := map[string]Item{}
	for _, it := range items {
		enArchivo[it.Script.ID] = it
	}
	var sobran []string
	for id := range dec {
		if _, ok := enArchivo[id]; !ok {
			sobran = append(sobran, id)
		}
	}
	if len(sobran) > 0 {
		sort.Strings(sobran)
		return r, i18n.New("scripts.imp.dec_ids", i18n.A("ids", strings.Join(sobran, ", ")))
	}
	porID, nombres := map[string]Script{}, map[string]string{} // clave de nombre -> ID
	for _, g := range guardados {
		porID[g.ID], nombres[NameKey(g.Name)] = g, g.ID
	}
	for _, l := range biblioteca { // sus nombres están ocupados y no se pueden reemplazar
		nombres[NameKey(l.Name)] = l.ID
	}
	delArchivo := map[string]bool{} // nombres de todo el archivo: un renombrado no puede tomar el de otro script del archivo
	for _, it := range items {
		delArchivo[NameKey(it.Script.Name)] = true
	}
	reemplazados := map[string]bool{}
	var faltan []string
	for _, it := range items {
		d, hay := dec[it.Script.ID]
		if hay && d != Renombrar && d != Reemplazar && d != Omitir {
			return r, i18n.New("scripts.imp.dec_unknown", i18n.A("dec", d, "id", it.Script.ID))
		}
		conflicto := it.Estado == ConflictoID || it.Estado == ConflictoNombre
		if !hay && conflicto {
			faltan = append(faltan, it.Script.ID)
		}
		if hay && !conflicto && d != Omitir {
			return r, i18n.New("scripts.imp.only_skip", i18n.A("id", it.Script.ID, "state", it.Estado))
		}
	}
	if len(faltan) > 0 {
		return r, i18n.New("scripts.imp.missing", i18n.A("n", len(faltan), "ids", strings.Join(faltan, ", ")))
	}
	for _, it := range items {
		s := it.Script
		s.Origin, s.CreatedAt, s.UpdatedAt = OrigenUsuario, ahora, ahora
		archivoID := s.ID
		d := dec[s.ID]
		switch {
		case it.Estado == Igual || d == Omitir:
			r.Skipped++
			if it.Estado == Igual { // ya está guardado (o en la biblioteca): las referencias apuntan ahí
				r.IDs[archivoID] = it.Con
			}
			continue
		case d == Reemplazar:
			old, ok := porID[it.Con]
			if !ok {
				return r, i18n.New("scripts.imp.lib_clash", i18n.A("name", s.Name))
			}
			if reemplazados[old.ID] {
				return r, i18n.New("scripts.imp.dup_replace", i18n.A("id", old.ID))
			}
			reemplazados[old.ID] = true
			if id, ok := nombres[NameKey(s.Name)]; ok && id != old.ID {
				return r, i18n.New("scripts.imp.replace_dup_name", i18n.A("id", old.ID, "name", s.Name))
			}
			delete(nombres, NameKey(old.Name))
			s.ID, s.CreatedAt = old.ID, old.CreatedAt
			r.Replaced++
		case d == Renombrar:
			s.ID = NewID()
			s.Name = NombreLibre(s.Name, "importado", func(n string) bool { _, ok := nombres[NameKey(n)]; return ok || delArchivo[NameKey(n)] })
			r.Renamed++
		default: // nuevo
			if IsLib(s.ID) {
				s.ID = NewID()
			}
			if _, ok := nombres[NameKey(s.Name)]; ok {
				return r, i18n.New("scripts.imp.name_exists", i18n.A("name", s.Name))
			}
			r.Created++
		}
		if err := s.Validate(); err != nil {
			return r, i18n.Wrap("scripts.imp.item", err, i18n.A("name", s.Name))
		}
		nombres[NameKey(s.Name)] = s.ID
		r.IDs[archivoID] = s.ID
		r.Writes = append(r.Writes, s)
	}
	return r, nil
}
