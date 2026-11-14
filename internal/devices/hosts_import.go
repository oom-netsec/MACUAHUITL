package devices

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

// Estados de un host del archivo frente a los guardados.
const (
	Nuevo     = "nuevo"
	Igual     = "igual"
	Conflicto = "conflicto"

	MotivoDireccion = "direccion" // misma dirección y puerto con otros datos: solo reemplazar u omitir
	MotivoNombre    = "nombre"    // mismo nombre en otra dirección
)

// Decisiones para un conflicto (omitir también vale para un nuevo).
const (
	Renombrar  = "renombrar"
	Reemplazar = "reemplazar"
	Omitir     = "omitir"
)

// Item es un host del archivo con su estado; Con es el ID del guardado con el que choca o coincide.
type Item struct {
	Host   Host // CredentialID ya resuelto por etiqueta (vacío si no se halló)
	Estado string
	Motivo string
	Con    string
}

// Same dice si dos hosts tienen el mismo contenido (ignora ID y fechas).
func Same(a, b Host) bool {
	return a.Name == b.Name && Key(a) == Key(b) && a.Platform == b.Platform && a.Folder == b.Folder &&
		strings.Join(a.Tags, ",") == strings.Join(b.Tags, ",") && a.CredentialID == b.CredentialID && a.Notes == b.Notes
}

// Plan compara los hosts del archivo con los guardados. La dirección y el puerto mandan: si chocan es «igual» o
// conflicto de dirección aunque el nombre también choque con otro host.
func Plan(entrante, guardados []Host) []Item {
	porClave, porNombre := map[string]Host{}, map[string]Host{}
	for _, g := range guardados {
		porClave[Key(g)], porNombre[NameKey(g.Name)] = g, g
	}
	out := make([]Item, len(entrante))
	for i, h := range entrante {
		it := Item{Host: h, Estado: Nuevo}
		if g, ok := porClave[Key(h)]; ok {
			it.Con, it.Estado, it.Motivo = g.ID, Conflicto, MotivoDireccion
			if Same(h, g) {
				it.Estado, it.Motivo = Igual, ""
			}
		} else if g, ok := porNombre[NameKey(h.Name)]; ok {
			it.Con, it.Estado, it.Motivo = g.ID, Conflicto, MotivoNombre
		}
		out[i] = it
	}
	return out
}

// Resultado de aplicar: los hosts a escribir (insertar o reemplazar por ID, en este orden) y los conteos.
type Resultado struct {
	Writes                              []Host
	Created, Replaced, Renamed, Skipped int
}

// NombreLibre da «<base> (<sufijo>)», o «… (<sufijo> 2)», 3… hasta que usado deje de decir que existe;
// recorta la base para no pasar de MaxHostName.
func NombreLibre(base, sufijo string, usado func(string) bool) string {
	for n := 1; ; n++ {
		suf := " (" + sufijo + ")"
		if n > 1 {
			suf = fmt.Sprintf(" (%s %d)", sufijo, n)
		}
		if r := []rune(base); len(r)+len([]rune(suf)) > MaxHostName {
			base = strings.TrimSpace(string(r[:MaxHostName-len([]rune(suf))]))
		}
		if c := base + suf; !usado(c) {
			return c
		}
	}
}

// Apply convierte el plan y las decisiones (por Key del host: dirección:puerto) en escrituras, en el mismo orden
// en que se validan, así la base nunca ve un choque pasajero. Falla sin escribir nada si falta la decisión de un
// conflicto, si una decisión no cabe en el estado del host, o si el resultado repetiría un nombre o un destino.
func Apply(items []Item, dec map[string]string, guardados []Host, ahora time.Time) (Resultado, error) {
	var r Resultado
	enArchivo := map[string]bool{}
	delArchivo := map[string]bool{} // nombres de todo el archivo: un renombrado no puede tomar el de otro host del archivo
	for _, it := range items {
		enArchivo[Key(it.Host)], delArchivo[NameKey(it.Host.Name)] = true, true
	}
	var sobran []string
	for k := range dec {
		if !enArchivo[k] {
			sobran = append(sobran, k)
		}
	}
	if len(sobran) > 0 {
		sort.Strings(sobran)
		return r, i18n.New("hostimport.extra_keys", i18n.A("keys", strings.Join(sobran, ", ")))
	}
	porID, nombres, claves := map[string]Host{}, map[string]string{}, map[string]string{} // clave -> ID
	for _, g := range guardados {
		porID[g.ID], nombres[NameKey(g.Name)], claves[Key(g)] = g, g.ID, g.ID
	}
	var faltan []string
	for _, it := range items {
		k := Key(it.Host)
		d, hay := dec[k]
		if hay && d != Renombrar && d != Reemplazar && d != Omitir {
			return r, i18n.New("hostimport.unknown", i18n.A("action", d, "key", k))
		}
		if !hay && it.Estado == Conflicto {
			faltan = append(faltan, k)
		}
		if hay && it.Estado != Conflicto && d != Omitir {
			return r, i18n.New("hostimport.only_skip", i18n.A("key", k, "state", it.Estado))
		}
		if hay && d == Renombrar && it.Motivo == MotivoDireccion {
			return r, i18n.New("hostimport.no_rename", i18n.A("key", k))
		}
	}
	if len(faltan) > 0 {
		return r, i18n.New("hostimport.missing", i18n.A("n", len(faltan), "keys", strings.Join(faltan, ", ")))
	}
	reemplazados := map[string]bool{}
	for _, it := range items {
		x := it.Host
		x.CreatedAt, x.UpdatedAt = ahora, ahora
		d := dec[Key(x)]
		switch {
		case it.Estado == Igual || d == Omitir:
			r.Skipped++
			continue
		case d == Reemplazar:
			old := porID[it.Con]
			if reemplazados[old.ID] {
				return r, i18n.New("hostimport.twice", i18n.A("name", old.Name))
			}
			reemplazados[old.ID] = true
			if id, ok := nombres[NameKey(x.Name)]; ok && id != old.ID {
				return r, i18n.New("hostimport.dup_name", i18n.A("old", old.Name, "name", x.Name))
			}
			if id, ok := claves[Key(x)]; ok && id != old.ID {
				return r, i18n.New("hostimport.dup_target", i18n.A("old", old.Name, "key", Key(x)))
			}
			delete(nombres, NameKey(old.Name))
			delete(claves, Key(old))
			x.ID, x.CreatedAt = old.ID, old.CreatedAt
			r.Replaced++
		case d == Renombrar:
			x.ID = NewID()
			x.Name = NombreLibre(x.Name, "importado", func(n string) bool { _, ok := nombres[NameKey(n)]; return ok || delArchivo[NameKey(n)] })
			r.Renamed++
		default: // nuevo
			x.ID = NewID()
			if _, ok := nombres[NameKey(x.Name)]; ok {
				return r, i18n.New("hostimport.name_exists", i18n.A("name", x.Name))
			}
			r.Created++
		}
		if _, ok := claves[Key(x)]; ok && d != Reemplazar {
			return r, i18n.New("hostimport.key_exists", i18n.A("key", Key(x)))
		}
		if len(porID)+r.Created+r.Renamed > MaxHosts {
			return r, i18n.New("hostimport.over_max", i18n.A("max", MaxHosts))
		}
		nombres[NameKey(x.Name)], claves[Key(x)] = x.ID, x.ID
		r.Writes = append(r.Writes, x)
	}
	return r, nil
}
