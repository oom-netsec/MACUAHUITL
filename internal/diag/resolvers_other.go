//go:build !windows

package diag

// SystemDNSHosts: fuera de Windows los resolvers salen de resolv.conf (service/tools), no de los adaptadores.
func SystemDNSHosts() []string { return nil }
