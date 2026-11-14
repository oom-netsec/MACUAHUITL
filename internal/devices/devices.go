// Package devices junta los equipos que la app ya conoce, para los selectores y la lista de IP
// permitidas: los objetivos de los trabajos de Patrol (manifest.json), la evidencia de la flota
// (carpetas <equipo>_<IP> y zips de outputs/) y los respaldos (outputs/respaldos/<equipo>/).
// Sin duplicados: por dirección; un respaldo, que no trae dirección, se une por nombre.
//
// No hace: hablar con los equipos ni validar que sigan en línea; "última vez visto" es la hora
// de la evidencia más reciente, no un ping.
package devices

import (
	"archive/zip"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/oom-netsec/MACUAHUITL/internal/patrol"
)

// Orígenes de un equipo.
const (
	SrcPatrol    = "patrol"    // objetivo de un trabajo (manifest.json), también si falló
	SrcFlota     = "flota"     // tiene evidencia en outputs/ (carpeta o zip de un trabajo)
	SrcRespaldos = "respaldos" // tiene respaldos de configuración
)

// Topes de lectura contra una carpeta hostil o enorme.
var MaxDevices = 5000

const (
	maxJobDirs    = 2000
	maxZips       = 500
	maxZipEntries = 20000
	maxManifest   = 8 << 20
)

type Device struct {
	Address  string // vacío si solo se conoce por respaldos sin IP en la carpeta (nombre solo, IPv6 o DNS)
	Hostname string
	Platform string
	LastSeen time.Time // cero si nunca se alcanzó
	Sources  []string
}

type Result struct {
	Devices  []Device
	Warnings []string
}

var (
	hostDirRe = regexp.MustCompile(`^.+_\d{1,3}(?:\.\d{1,3}){3}$`)
	backupRe  = regexp.MustCompile(`^(\d{8}T\d{6}Z)-(?:running|startup)\.cfg$`)
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
)

// clean deja un nombre del disco listo para mostrar: control, formato invisible y UTF-8 inválido pasan a «?».
func clean(s string) string {
	s = strings.ToValidUTF8(s, "?")
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, strings.TrimSpace(s))
}

type obs struct {
	addr, host, platform, src string
	at                        time.Time
}

type acc struct {
	Device
	hostAt, platAt time.Time
	srcs           map[string]bool
}

type collector struct {
	obs   []obs
	warns []string
}

func (c *collector) warn(f string, a ...any) { c.warns = append(c.warns, fmt.Sprintf(f, a...)) }

// Collect lee la carpeta de salidas (outputs/) y las carpetas extra (los output_dir de los trabajos,
// que pueden estar fuera de outputs/) y arma la lista de equipos conocidos. Solo falla si outputs/
// no existe y ninguna extra se pudo leer; una extra ilegible es un aviso.
func Collect(outputs string, extra ...string) (Result, error) {
	c := &collector{}
	jobs := 0
	var first error
	read := 0
	for i, root := range append([]string{outputs}, extra...) {
		ents, err := os.ReadDir(root)
		if err != nil {
			if i == 0 {
				first = fmt.Errorf("devices: %w", err)
			} else if !errors.Is(err, fs.ErrNotExist) { // la carpeta de un trabajo viejo ya borrada no es noticia
				c.warn("%s: %v", root, err)
			}
			continue
		}
		read++
		for _, e := range ents {
			if !e.IsDir() { // DirEntry no sigue enlaces: un symlink no es carpeta
				continue
			}
			if e.Name() == "respaldos" {
				c.backups(filepath.Join(root, e.Name()))
				continue
			}
			if jobs++; jobs > maxJobDirs {
				c.warn("más de %d carpetas en outputs/: el resto no se leyó", maxJobDirs)
				return c.merge(), nil
			}
			c.job(filepath.Join(root, e.Name()), e.Name())
		}
	}
	if read == 0 {
		return Result{}, first
	}
	return c.merge(), nil
}

func (c *collector) add(o obs) {
	if o.addr == "" && o.host == "" {
		return
	}
	c.obs = append(c.obs, o)
}

type manifestFile struct {
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Devices   []struct {
		Target             patrol.Target
		Hostname, Platform string
		State              string
	} `json:"devices"`
}

func readSmall(p string, max int64) ([]byte, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, fmt.Errorf("no es un archivo regular o pasa de %d MiB", max>>20)
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

func (c *collector) job(dir, name string) {
	// carpeta de Patrol → equipo del manifest: la carpeta cambia los «:» de una IPv6 por «_» y no se puede deshacer
	known := map[string][2]string{}
	if b, err := readSmall(filepath.Join(dir, "manifest.json"), maxManifest); err == nil {
		var m manifestFile
		if err := json.Unmarshal(b, &m); err != nil {
			c.warn("%s/manifest.json ilegible: %v", name, err)
		} else {
			at := m.EndedAt
			if at.IsZero() {
				at = m.StartedAt
			}
			for _, d := range m.Devices {
				seen := time.Time{}
				if d.State == "completed" {
					seen = at
				}
				c.add(obs{addr: clean(d.Target.Address), host: clean(d.Hostname), platform: clean(d.Platform), src: SrcPatrol, at: seen})
				known[patrol.DeviceDirOf(d.Hostname, d.Target)] = [2]string{clean(d.Hostname), clean(d.Target.Address)}
			}
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		c.warn("%s: %v", name, err)
		return
	}
	zips := 0
	for _, e := range ents {
		switch {
		case e.IsDir() && (known[e.Name()] != [2]string{} || hostDirRe.MatchString(e.Name())):
			host, ip := c.hostIP(e.Name(), known)
			c.add(obs{addr: ip, host: host, src: SrcFlota, at: newestFile(filepath.Join(dir, e.Name()))})
		case e.Type().IsRegular() && strings.HasSuffix(strings.ToLower(e.Name()), ".zip"):
			if zips++; zips > maxZips {
				c.warn("%s: más de %d zips, el resto no se leyó", name, maxZips)
				continue
			}
			c.zipDevices(filepath.Join(dir, e.Name()), name, known)
		}
	}
}

// hostIP saca equipo y dirección de la carpeta de un equipo: del manifest si ahí está, y si no cortando en el último «_».
func (c *collector) hostIP(n string, known map[string][2]string) (host, ip string) {
	if k, ok := known[n]; ok {
		return k[0], k[1]
	}
	i := strings.LastIndexByte(n, '_')
	return clean(n[:i]), n[i+1:]
}

// newestFile es la hora de la evidencia más reciente de la carpeta de un equipo.
func newestFile(dir string) time.Time {
	var best time.Time
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.ModTime().After(best) {
			best = fi.ModTime()
		}
	}
	if best.IsZero() {
		if fi, err := os.Stat(dir); err == nil {
			best = fi.ModTime()
		}
	}
	return best.UTC()
}

func (c *collector) zipDevices(p, job string, known map[string][2]string) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		c.warn("%s/%s: %v", job, filepath.Base(p), err)
		return
	}
	defer zr.Close()
	var at time.Time
	if fi, err := os.Stat(p); err == nil {
		at = fi.ModTime().UTC()
	}
	seen := map[string]bool{}
	for i, zf := range zr.File {
		if i >= maxZipEntries {
			c.warn("%s/%s: más de %d entradas, el resto no se leyó", job, filepath.Base(p), maxZipEntries)
			return
		}
		n := path.Clean(zf.Name)
		dir := path.Dir(n)
		if strings.Count(n, "/") != 1 || strings.HasPrefix(n, "..") || (known[dir] == [2]string{} && !hostDirRe.MatchString(dir)) || seen[dir] {
			continue
		}
		seen[dir] = true
		host, ip := c.hostIP(dir, known)
		c.add(obs{addr: ip, host: host, src: SrcFlota, at: at})
	}
}

func (c *collector) backups(root string) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() || !nameRe.MatchString(e.Name()) {
			continue
		}
		files, _ := os.ReadDir(filepath.Join(root, e.Name()))
		var best time.Time
		for _, f := range files {
			m := backupRe.FindStringSubmatch(f.Name())
			if m == nil || !f.Type().IsRegular() {
				continue
			}
			if at, err := time.Parse("20060102T150405Z", m[1]); err == nil && at.After(best) {
				best = at
			}
		}
		if best.IsZero() {
			continue
		}
		if hostDirRe.MatchString(e.Name()) { // respaldos/<equipo>_<IP>: se junta por dirección
			host, ip := c.hostIP(e.Name(), nil)
			c.add(obs{addr: ip, host: host, src: SrcRespaldos, at: best})
		} else {
			c.add(obs{host: clean(e.Name()), src: SrcRespaldos, at: best})
		}
	}
}

// merge junta las observaciones: por dirección, y las que no la tienen (respaldos) por nombre.
func (c *collector) merge() Result {
	res := Result{Warnings: c.warns}
	byAddr := map[string]*acc{}
	var order []*acc
	capped := false
	get := func(addr string) *acc {
		if a := byAddr[addr]; a != nil {
			return a
		}
		if len(order) >= MaxDevices {
			capped = true
			return nil
		}
		a := &acc{Device: Device{Address: addr}, srcs: map[string]bool{}}
		byAddr[addr] = a
		order = append(order, a)
		return a
	}
	apply := func(a *acc, o obs) {
		a.srcs[o.src] = true
		if o.at.After(a.LastSeen) {
			a.LastSeen = o.at
		}
		if o.host != "" && o.host != a.Address && (a.Hostname == "" || o.at.After(a.hostAt)) {
			a.Hostname, a.hostAt = o.host, o.at
		}
		if o.platform != "" && (a.Platform == "" || o.at.After(a.platAt)) {
			a.Platform, a.platAt = o.platform, o.at
		}
	}
	for _, o := range c.obs {
		if o.addr != "" {
			if a := get(o.addr); a != nil {
				apply(a, o)
			}
		}
	}
	for _, o := range c.obs {
		if o.addr != "" {
			continue
		}
		var a *acc
		for _, x := range order {
			if x.Address != "" && strings.EqualFold(x.Hostname, o.host) {
				a = x
				break
			}
		}
		if a == nil {
			a = get("host:" + strings.ToLower(o.host)) // sin dirección: se identifica por su nombre
			if a != nil {
				a.Address = ""
			}
		}
		if a != nil {
			apply(a, o)
		}
	}
	if capped {
		res.Warnings = append(res.Warnings, fmt.Sprintf("más de %d equipos: la lista está incompleta", MaxDevices))
	}
	for _, a := range order {
		for _, s := range []string{SrcPatrol, SrcFlota, SrcRespaldos} {
			if a.srcs[s] {
				a.Sources = append(a.Sources, s)
			}
		}
		res.Devices = append(res.Devices, a.Device)
	}
	slices.SortStableFunc(res.Devices, compare)
	return res
}

// compare ordena IPv4 por valor, luego IPv6, luego otros nombres de destino, y al final los que no tienen dirección.
func compare(a, b Device) int {
	rank := func(d Device) (int, netip.Addr) {
		if d.Address == "" {
			return 3, netip.Addr{}
		}
		if ip, err := netip.ParseAddr(d.Address); err == nil {
			return 0, ip
		}
		return 2, netip.Addr{}
	}
	ra, ia := rank(a)
	rb, ib := rank(b)
	if ra != rb {
		return cmp.Compare(ra, rb)
	}
	if ra == 0 {
		if c := ia.Compare(ib); c != 0 {
			return c
		}
	} else if c := strings.Compare(a.Address, b.Address); c != 0 {
		return c
	}
	return strings.Compare(strings.ToLower(a.Hostname), strings.ToLower(b.Hostname))
}

// Filter deja los equipos cuyo nombre, dirección o plataforma contiene q (sin importar mayúsculas).
func Filter(ds []Device, q string) []Device {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return ds
	}
	var out []Device
	for _, d := range ds {
		if strings.Contains(strings.ToLower(d.Address+"\x00"+d.Hostname+"\x00"+d.Platform), q) {
			out = append(out, d)
		}
	}
	return out
}
