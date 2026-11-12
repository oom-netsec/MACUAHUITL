package devices

import (
	"net/netip"
	"slices"
	"strings"
)

// Entry es un equipo del inventario: lo descubierto, el host de la libreta o los dos fusionados.
type Entry struct {
	Device
	Host *Host // nil si no hay host manual
}

// addrKey pone una dirección descubierta en la misma forma canónica que Clean deja la de un host.
func addrKey(a string) string {
	if ip, err := netip.ParseAddr(a); err == nil && ip.Zone() == "" {
		return ip.Unmap().String()
	}
	return strings.ToLower(a)
}

// Merge suma los hosts de la libreta a los equipos descubiertos. Un host con la dirección de un descubierto
// se fusiona en su fila (el nombre y la plataforma del host mandan; la evidencia y sus fuentes se conservan,
// más «manual»). Si varios hosts comparten dirección (puertos distintos), solo el primero por nombre se
// fusiona; los demás son filas aparte. El orden es el de siempre.
func Merge(found []Device, hosts []Host) []Entry {
	es := make([]Entry, len(found), len(found)+len(hosts))
	byAddr := map[string]int{}
	for i, d := range found {
		es[i] = Entry{Device: d}
		if d.Address != "" {
			byAddr[addrKey(d.Address)] = i
		}
	}
	sorted := slices.Clone(hosts)
	slices.SortFunc(sorted, func(a, b Host) int { return strings.Compare(NameKey(a.Name)+"\x00"+a.ID, NameKey(b.Name)+"\x00"+b.ID) })
	for _, h := range sorted {
		h := h
		if i, ok := byAddr[h.Address]; ok && es[i].Host == nil {
			e := &es[i]
			e.Host, e.Hostname = &h, h.Name
			if h.Platform != "" {
				e.Platform = h.Platform
			}
			e.Sources = append(slices.Clone(e.Sources), SrcManual)
			continue
		}
		es = append(es, Entry{Device: Device{Address: h.Address, Hostname: h.Name, Platform: h.Platform, Sources: []string{SrcManual}}, Host: &h})
	}
	slices.SortStableFunc(es, func(a, b Entry) int { return compare(a.Device, b.Device) })
	return es
}

// FilterEntries deja los equipos cuyo texto (dirección, nombre, plataforma, carpeta y etiquetas) contiene q,
// sin importar mayúsculas; folder (igual, sin importar mayúsculas) y tag (exacta) solo los cumplen los hosts de
// la libreta. Vacío = sin filtro.
func FilterEntries(es []Entry, q, folder, tag string) []Entry {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []Entry
	for _, e := range es {
		text := e.Address + "\x00" + e.Hostname + "\x00" + e.Platform
		if e.Host != nil {
			text += "\x00" + e.Host.Folder + "\x00" + strings.Join(e.Host.Tags, "\x00")
		}
		switch {
		case !strings.Contains(strings.ToLower(text), q):
		case folder != "" && (e.Host == nil || NameKey(e.Host.Folder) != NameKey(folder)):
		case tag != "" && (e.Host == nil || !slices.Contains(e.Host.Tags, tag)):
		default:
			out = append(out, e)
		}
	}
	return out
}
