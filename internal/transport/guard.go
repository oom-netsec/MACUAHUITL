// Package transport concentra toda la red saliente: SSH, HTTPS hacia APIs,
// EgressGuard y known_hosts (spec §6.1, §7).
//
// No hace: decidir destinos; solo obedece a EgressGuard.
package transport

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/oom-netsec/MACUAHUITL/internal/audit"
	"github.com/oom-netsec/MACUAHUITL/internal/i18n"
)

var ErrEgressDenied error = i18n.New("transport.err.not_authorized", nil)

// Guard es la única puerta de salida a la red: cada trabajo solo alcanza
// las IPs, rangos y nombres que el ingeniero escribió para él.
type Guard struct {
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	onDeny  func(audit.Entry)
	mu      sync.RWMutex
	allowed map[string][]netip.Prefix
	ports   map[string]map[uint16]bool // ejecuciones que pueden ir a cualquier IP, solo en estos puertos
}

// NewGuard crea un Guard. resolve nil usa el resolvedor del sistema; onDeny puede ser nil.
func NewGuard(resolve func(ctx context.Context, host string) ([]netip.Addr, error), onDeny func(audit.Entry)) *Guard {
	if resolve == nil {
		resolve = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	if onDeny == nil {
		onDeny = func(audit.Entry) {}
	}
	return &Guard{resolve: resolve, onDeny: onDeny, allowed: map[string][]netip.Prefix{}, ports: map[string]map[uint16]bool{}}
}

func (g *Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap()}, nil
	}
	if host == "" {
		return nil, i18n.New("transport.err.empty_addr", nil)
	}
	addrs, err := g.resolve(ctx, host)
	if err != nil {
		return nil, i18n.Wrap("transport.err.resolve", err, i18n.A("host", host))
	}
	for i := range addrs {
		addrs[i] = addrs[i].Unmap()
	}
	return addrs, nil
}

// Allow autoriza para jobID cada dirección: IP, nombre DNS (se resuelve ahora) o CIDR.
func (g *Guard) Allow(ctx context.Context, jobID string, addresses []string) error {
	var add []netip.Prefix
	for _, a := range addresses {
		if p, err := netip.ParsePrefix(a); err == nil {
			if p.Masked() != p {
				return i18n.New("transport.err.host_bits", i18n.A("addr", a, "masked", p.Masked()))
			}
			add = append(add, p)
			continue
		}
		addrs, err := g.lookup(ctx, a)
		if err != nil {
			return err
		}
		for _, ip := range addrs {
			add = append(add, netip.PrefixFrom(ip, ip.BitLen()))
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.allowed[jobID] = append(g.allowed[jobID], add...)
	return nil
}

// Revoke quita todas las autorizaciones de jobID.
func (g *Guard) Revoke(jobID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.allowed, jobID)
	delete(g.ports, jobID)
}

// AllowAnyOnPorts permite a runID cualquier IP pero solo en esos puertos. Es la
// política del DNS profundo: raíz, TLD y autoritativos que nadie escribió, pero
// solo DNS (spec §6.1, decisión del dueño 2026-11-04). Cada conexión se audita aparte.
func (g *Guard) AllowAnyOnPorts(runID string, ports []uint16) {
	g.mu.Lock()
	defer g.mu.Unlock()
	m := map[uint16]bool{}
	for _, p := range ports {
		m[p] = true
	}
	g.ports[runID] = m
}

func (g *Guard) permitted(jobID string, ip netip.Addr, port uint16) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.ports[jobID][port] {
		return true
	}
	for _, p := range g.allowed[jobID] {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Dial abre TCP hacia host:port solo si alguna IP de host está autorizada para jobID.
func (g *Guard) Dial(ctx context.Context, jobID string, host string, port uint16) (net.Conn, error) {
	return g.DialNetwork(ctx, jobID, "tcp", host, port)
}

// DialerFor fija jobID para las herramientas que reciben un dialer sin noción de trabajos.
func (g *Guard) DialerFor(jobID string) func(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
	return func(ctx context.Context, network, host string, port uint16) (net.Conn, error) {
		return g.DialNetwork(ctx, jobID, network, host, port)
	}
}

// DialNetwork es Dial para tcp o udp.
func (g *Guard) DialNetwork(ctx context.Context, jobID, network, host string, port uint16) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, i18n.New("transport.err.network", i18n.A("network", network))
	}
	addrs, err := g.lookup(ctx, host)
	if err == nil {
		for _, ip := range addrs {
			if g.permitted(jobID, ip, port) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, network, net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
			}
		}
	}
	g.onDeny(audit.Entry{Action: "egress.denied", Target: net.JoinHostPort(host, strconv.Itoa(int(port))), Detail: jobID + " " + network})
	return nil, ErrEgressDenied
}

// PacketTo abre un socket UDP sin conectar hacia host:port si jobID lo tiene autorizado. Es
// para protocolos como TFTP, cuyo servidor contesta desde otro puerto: un socket conectado
// descartaría la respuesta. Solo se puede enviar a la IP autorizada (cualquier puerto); toda
// otra dirección se rechaza y queda auditada. Devuelve también la dirección destino.
func (g *Guard) PacketTo(ctx context.Context, jobID, host string, port uint16) (net.PacketConn, *net.UDPAddr, error) {
	addrs, err := g.lookup(ctx, host)
	if err == nil {
		for _, ip := range addrs {
			if !g.permitted(jobID, ip, port) {
				continue
			}
			network, bind := "udp4", "0.0.0.0:0"
			if ip.Is6() {
				network, bind = "udp6", "[::]:0"
			}
			pc, err := net.ListenPacket(network, bind)
			if err != nil {
				return nil, nil, err
			}
			dst := &net.UDPAddr{IP: ip.AsSlice(), Port: int(port)}
			return &guardedPacket{PacketConn: pc, g: g, job: jobID, ip: ip}, dst, nil
		}
	}
	g.onDeny(audit.Entry{Action: "egress.denied", Target: net.JoinHostPort(host, strconv.Itoa(int(port))), Detail: jobID + " udp"})
	return nil, nil, ErrEgressDenied
}

type guardedPacket struct {
	net.PacketConn
	g   *Guard
	job string
	ip  netip.Addr
}

func (p *guardedPacket) WriteTo(b []byte, to net.Addr) (int, error) {
	if ua, ok := to.(*net.UDPAddr); ok {
		if a, ok := netip.AddrFromSlice(ua.IP); ok && a.Unmap() == p.ip.Unmap() {
			return p.PacketConn.WriteTo(b, to)
		}
	}
	p.g.onDeny(audit.Entry{Action: "egress.denied", Target: to.String(), Detail: p.job + " udp"})
	return 0, ErrEgressDenied
}
