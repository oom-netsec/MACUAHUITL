package scripts

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Colecciones (fase 29c): listas ordenadas de IDs de script, de un solo nivel. Guardan referencias, nunca copias,
// y un script puede estar en varias. «favoritos» es la colección por defecto.

const (
	FavoritosID     = "favoritos"
	FavoritosNombre = "Favoritos"

	MaxColecciones      = 100
	MaxScriptsColeccion = MaxImportScripts
	MaxFijados          = 5

	FormatoColecciones = "macuahuitl-colecciones"

	// Estados propios de una colección del archivo (además de Igual, ConflictoID y ConflictoNombre).
	ColNueva    = "nueva"
	ColFusionar = "fusionar" // solo favoritos: se le agregan los scripts que le faltan
)

// Coleccion agrupa scripts por ID. El JSON es también el formato del archivo de export.
type Coleccion struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Order       int       `json:"order"`
	ScriptIDs   []string  `json:"script_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ValidName aplica la regla de nombres de scripts y colecciones.
func ValidName(n string) error {
	if c := utf8.RuneCountInString(n); c < 1 || c > MaxName || n != strings.TrimSpace(n) || hasControl(n, false) {
		return errName
	}
	return nil
}

// Validate aplica las reglas de la fase: nombre, descripción, IDs de script válidos y sin repetir, y el tope.
// «favoritos» conserva su nombre.
func (c Coleccion) Validate() error {
	if c.ID != FavoritosID && !userID.MatchString(c.ID) {
		return i18n.New("scripts.col.id", i18n.A("id", c.ID))
	}
	if err := ValidName(c.Name); err != nil {
		return err
	}
	if c.ID == FavoritosID && c.Name != FavoritosNombre {
		return i18n.New("scripts.col.no_rename", i18n.A("id", FavoritosID))
	}
	if utf8.RuneCountInString(c.Description) > MaxDescription || hasControl(c.Description, true) {
		return i18n.New("scripts.err.description", i18n.A("max", MaxDescription))
	}
	if len(c.ScriptIDs) > MaxScriptsColeccion {
		return i18n.New("scripts.col.scripts_max", i18n.A("max", MaxScriptsColeccion))
	}
	seen := map[string]bool{}
	for _, id := range c.ScriptIDs {
		if !userID.MatchString(id) && !libID.MatchString(id) {
			return i18n.New("scripts.col.script_id", i18n.A("id", id))
		}
		if seen[id] {
			return i18n.New("scripts.col.script_dup", i18n.A("id", id))
		}
		seen[id] = true
	}
	return nil
}

func sameCol(a, b Coleccion) bool {
	return a.Name == b.Name && a.Description == b.Description && strings.Join(a.ScriptIDs, ",") == strings.Join(b.ScriptIDs, ",")
}

// ItemCol es una colección del archivo con su estado; Con es el ID local con el que choca o coincide.
type ItemCol struct {
	Col    Coleccion
	Estado string
	Con    string
}

// PlanColecciones compara las colecciones del archivo con las locales. «favoritos» nunca choca: es «igual» si no
// tiene nada que agregar y «fusionar» si sí. Para las demás, el ID manda sobre el nombre.
func PlanColecciones(entrante, locales []Coleccion) []ItemCol {
	porID, porNombre := map[string]Coleccion{}, map[string]Coleccion{}
	for _, l := range locales {
		porID[l.ID], porNombre[NameKey(l.Name)] = l, l
	}
	out := make([]ItemCol, len(entrante))
	for i, e := range entrante {
		it := ItemCol{Col: e, Estado: ColNueva}
		if l, ok := porID[e.ID]; e.ID == FavoritosID && ok {
			it.Con, it.Estado = l.ID, Igual
			have := map[string]bool{}
			for _, id := range l.ScriptIDs {
				have[id] = true
			}
			for _, id := range e.ScriptIDs {
				if !have[id] {
					it.Estado = ColFusionar
				}
			}
		} else if ok {
			it.Con, it.Estado = l.ID, ConflictoID
			if sameCol(e, l) {
				it.Estado = Igual
			}
		} else if l, ok := porNombre[NameKey(e.Name)]; ok {
			it.Con, it.Estado = l.ID, ConflictoNombre
		}
		out[i] = it
	}
	return out
}

// ResultadoCol son las colecciones a escribir (insertar o reemplazar por ID), los conteos y los avisos.
type ResultadoCol struct {
	Writes                                      []Coleccion
	Created, Replaced, Renamed, Merged, Skipped int
	Warnings                                    []string
}

// ApplyColecciones convierte el plan y las decisiones (por ID del archivo) en escrituras. mapa lleva el ID de cada
// script del archivo al ID en que quedó guardado (Resultado.IDs de Apply); lib son los IDs de la biblioteca local.
// Un script omitido o un «lib-*» que no existe aquí se quita de la colección con un aviso. Mismas reglas que Apply:
// falla sin escribir si falta la decisión de un conflicto, si una no cabe en el estado, o si el resultado repetiría
// un nombre o reemplazaría dos veces lo mismo. «favoritos» solo se fusiona u omite, y siempre con los IDs ya traducidos.
func ApplyColecciones(items []ItemCol, dec map[string]string, locales []Coleccion, mapa map[string]string, lib map[string]bool, ahora time.Time) (ResultadoCol, error) {
	var r ResultadoCol
	enArchivo := map[string]ItemCol{}
	for _, it := range items {
		enArchivo[it.Col.ID] = it
	}
	var sobran []string
	for id := range dec {
		if _, ok := enArchivo[id]; !ok {
			sobran = append(sobran, id)
		}
	}
	if len(sobran) > 0 {
		sort.Strings(sobran)
		return r, fmt.Errorf("decisión para colecciones que no están en el archivo: %s", strings.Join(sobran, ", "))
	}
	var faltan []string
	for _, it := range items {
		d, hay := dec[it.Col.ID]
		if hay && d != Renombrar && d != Reemplazar && d != Omitir {
			return r, fmt.Errorf("decisión %q desconocida para %s", d, it.Col.ID)
		}
		conflicto := it.Estado == ConflictoID || it.Estado == ConflictoNombre
		if !hay && conflicto {
			faltan = append(faltan, it.Col.ID)
		}
		if hay && !conflicto && d != Omitir {
			return r, fmt.Errorf("%s es %q: solo se puede omitir", it.Col.ID, it.Estado)
		}
	}
	if len(faltan) > 0 {
		return r, fmt.Errorf("falta la decisión de %d conflicto(s) de colecciones: %s", len(faltan), strings.Join(faltan, ", "))
	}
	porID, nombres := map[string]Coleccion{}, map[string]string{} // clave de nombre -> ID
	for _, l := range locales {
		porID[l.ID], nombres[NameKey(l.Name)] = l, l.ID
	}
	delArchivo := map[string]bool{}
	for _, it := range items {
		delArchivo[NameKey(it.Col.Name)] = true
	}
	reemplazadas := map[string]bool{}
	// refs pasa los IDs del archivo a los guardados, sin repetir y en orden.
	refs := func(c Coleccion) []string {
		out, seen := []string{}, map[string]bool{}
		for _, id := range c.ScriptIDs {
			nuevo := id
			if IsLib(id) {
				if !lib[id] {
					r.Warnings = append(r.Warnings, fmt.Sprintf("colección %q: el script %s no está en la biblioteca local; se omitió", c.Name, id))
					continue
				}
			} else if m, ok := mapa[id]; ok {
				nuevo = m
			} else {
				r.Warnings = append(r.Warnings, fmt.Sprintf("colección %q: el script %s no se importó; se quitó de la colección", c.Name, id))
				continue
			}
			if !seen[nuevo] {
				seen[nuevo] = true
				out = append(out, nuevo)
			}
		}
		return out
	}
	for _, it := range items {
		c := it.Col
		c.CreatedAt, c.UpdatedAt = ahora, ahora
		d := dec[c.ID]
		switch {
		case d == Omitir || (it.Estado == Igual && c.ID != FavoritosID):
			r.Skipped++
			continue
		case c.ID == FavoritosID: // agrega los que faltan, nunca reemplaza; aunque el plan diga «igual» (IDs del archivo), un script que cambió de ID al importar entra
			base := porID[it.Con]
			have := map[string]bool{}
			for _, id := range base.ScriptIDs {
				have[id] = true
			}
			add := 0
			merged := append([]string{}, base.ScriptIDs...)
			for _, id := range refs(c) {
				if !have[id] {
					have[id] = true
					merged = append(merged, id)
					add++
				}
			}
			if add == 0 {
				r.Skipped++
				continue
			}
			base.ScriptIDs, base.UpdatedAt = merged, ahora
			c = base
			r.Merged++
		case d == Reemplazar:
			old, ok := porID[it.Con]
			if !ok || old.ID == FavoritosID {
				return r, fmt.Errorf("%s choca con %s, que no se reemplaza: renómbrala u omítela", c.Name, FavoritosID)
			}
			if reemplazadas[old.ID] {
				return r, fmt.Errorf("dos decisiones reemplazan la misma colección guardada (%s)", old.ID)
			}
			reemplazadas[old.ID] = true
			if id, ok := nombres[NameKey(c.Name)]; ok && id != old.ID {
				return r, fmt.Errorf("reemplazar %s dejaría dos colecciones con el nombre %q", old.ID, c.Name)
			}
			delete(nombres, NameKey(old.Name))
			c.ID, c.CreatedAt, c.Order = old.ID, old.CreatedAt, old.Order
			c.ScriptIDs = refs(c)
			r.Replaced++
		case d == Renombrar:
			c.ID = NewID()
			c.Name = NombreLibre(c.Name, "importado", func(n string) bool { _, ok := nombres[NameKey(n)]; return ok || delArchivo[NameKey(n)] })
			c.ScriptIDs = refs(c)
			r.Renamed++
		default: // nueva
			if _, ok := nombres[NameKey(c.Name)]; ok {
				return r, fmt.Errorf("el nombre %q ya existe", c.Name)
			}
			c.ScriptIDs = refs(c)
			r.Created++
		}
		if err := c.Validate(); err != nil {
			return r, fmt.Errorf("%s: %w", c.Name, err)
		}
		nombres[NameKey(c.Name)] = c.ID
		r.Writes = append(r.Writes, c)
	}
	return r, nil
}

// ---- archivo de export de colecciones ----

type archivoCol struct {
	Formato     string          `json:"formato"`
	Version     int             `json:"version"`
	Exportado   string          `json:"exportado"`
	Colecciones json.RawMessage `json:"colecciones"`
	Scripts     json.RawMessage `json:"scripts"`
	SHA256      string          `json:"sha256,omitempty"` // opcional al importar
}

func normalizaCol(in []Coleccion) []Coleccion {
	out := make([]Coleccion, len(in))
	for i, c := range in {
		c.ScriptIDs = nonNil(c.ScriptIDs)
		out[i] = c
	}
	return out
}

// sumaCol es la suma del JSON canónico de las dos listas juntas, para que no se pueda cambiar una sin la otra.
func sumaCol(colRaw, scrRaw []byte) string {
	return sha([]byte(`{"colecciones":` + string(colRaw) + `,"scripts":` + string(scrRaw) + `}`))
}

func canonCol(cols []Coleccion, scripts []Script) (colRaw, scrRaw []byte, sum string, err error) {
	if colRaw, err = json.Marshal(normalizaCol(cols)); err != nil {
		return
	}
	if scrRaw, err = json.Marshal(normaliza(scripts)); err != nil {
		return
	}
	return colRaw, scrRaw, sumaCol(colRaw, scrRaw), nil
}

// MarshalColecciones arma el archivo de export: las colecciones y solo los scripts de usuario que referencian
// (los de la biblioteca viajan por ID).
func MarshalColecciones(cols []Coleccion, scripts []Script, now time.Time) ([]byte, error) {
	colRaw, scrRaw, sum, err := canonCol(cols, scripts)
	if err != nil {
		return nil, err
	}
	return json.Marshal(archivoCol{Formato: FormatoColecciones, Version: Version, Exportado: now.UTC().Format(time.RFC3339),
		Colecciones: colRaw, Scripts: scrRaw, SHA256: sum})
}

// ParseColecciones lee y valida un archivo de colecciones con las mismas reglas que Parse y, además: cada colección
// es válida y sin ID ni nombre repetidos, los scripts son todos de usuario y cada ID de usuario que una colección
// referencia viaja en el archivo. No toca el store.
func ParseColecciones(b []byte) ([]Coleccion, []Script, error) {
	c, s, _, err := ParseColeccionesAvisos(b)
	return c, s, err
}

// ParseColeccionesAvisos es ParseColecciones más los avisos (la suma es opcional, como en Parse).
func ParseColeccionesAvisos(b []byte) ([]Coleccion, []Script, []string, error) {
	if err := leerCabecera(b, FormatoColecciones, "colecciones"); err != nil {
		return nil, nil, nil, err
	}
	var a archivoCol
	if err := decodifica(b, &a, "colecciones"); err != nil {
		return nil, nil, nil, err
	}
	cols, err := decodificaLista[Coleccion](a.Colecciones, "colecciones")
	if err != nil {
		return nil, nil, nil, err
	}
	scripts, err := decodificaLista[Script](a.Scripts, "scripts")
	if err != nil {
		return nil, nil, nil, err
	}
	if len(cols) > MaxColecciones {
		return nil, nil, nil, fmt.Errorf("el archivo trae %d colecciones; el tope es %d", len(cols), MaxColecciones)
	}
	if len(scripts) > MaxImportScripts {
		return nil, nil, nil, fmt.Errorf("el archivo trae %d scripts; el tope es %d", len(scripts), MaxImportScripts)
	}
	avisos, err := verificaSuma(a.SHA256, func() (string, error) { _, _, sum, err := canonCol(cols, scripts); return sum, err })
	if err != nil {
		return nil, nil, nil, err
	}
	if err := validaScripts(scripts); err != nil {
		return nil, nil, nil, err
	}
	enArchivo := map[string]bool{}
	for _, s := range scripts {
		if s.Origin != OrigenUsuario {
			return nil, nil, nil, fmt.Errorf("script %q: los de la biblioteca viajan solo por ID", s.Name)
		}
		enArchivo[s.ID] = true
	}
	ids, nombres := map[string]bool{}, map[string]bool{}
	for i, c := range normalizaCol(cols) {
		cols[i] = c
		if err := c.Validate(); err != nil {
			return nil, nil, nil, i18n.Wrap("scripts.imp.col", i18n.A("n", i+1, "name", c.Name), err)
		}
		k := NameKey(c.Name)
		if ids[c.ID] || nombres[k] {
			return nil, nil, nil, i18n.New("scripts.imp.col_dup", i18n.A("n", i+1, "name", c.Name))
		}
		ids[c.ID], nombres[k] = true, true
		for _, id := range c.ScriptIDs {
			if !IsLib(id) && !enArchivo[id] {
				return nil, nil, nil, errors.New("la colección " + c.Name + " referencia al script " + id + ", que no viaja en el archivo")
			}
		}
	}
	return cols, scripts, avisos, nil
}
