package diag

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SystemDNSHosts lista los DNS de los adaptadores activos con GetAdaptersAddresses (sin SKIP_DNS_SERVER).
func SystemDNSHosts() []string { return ResolverHosts(realDNSAdapters()) }

func realDNSAdapters() []DNSAdapter {
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_UNICAST, 0, aa, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil
		}
		var out []DNSAdapter
		for ; aa != nil; aa = aa.Next {
			a := DNSAdapter{Up: aa.OperStatus == windows.IfOperStatusUp, Loopback: aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK}
			for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
				if ip, ok := netip.AddrFromSlice(d.Address.IP()); ok {
					a.DNS = append(a.DNS, ip)
				}
			}
			out = append(out, a)
		}
		return out
	}
	return nil
}
