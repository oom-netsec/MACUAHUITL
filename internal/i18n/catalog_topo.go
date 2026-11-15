package i18n

// Topología (mctl visibility topo): resumen legible y hallazgos de los enlaces.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"topo.text.header":   e("Topología: {nodes} equipos, {links} enlaces", "Topology: {nodes} {nodes|device|devices}, {links} {links|link|links}", "nodes", "links"),
		"topo.text.devices":  e("Equipos:", "Devices:"),
		"topo.text.links":    e("Enlaces:", "Links:"),
		"topo.text.findings": e("Hallazgos:", "Findings:"),
		"topo.text.stp_root": e("root STP en {vlans}", "STP root on {vlans}", "vlans"),

		"topo.finding.one_sided":    e("{where}: solo lo ve un lado; {other} no lo reporta (CDP/LLDP apagado en el puerto, enlace unidireccional o cableado distinto)", "{where}: only one side sees it; {other} does not report it (CDP/LLDP off on the port, unidirectional link or different cabling)", "where", "other"),
		"topo.finding.native_vlan":  e("{where}: VLAN nativa distinta ({a} vs {b})", "{where}: native VLAN mismatch ({a} vs {b})", "where", "a", "b"),
		"topo.finding.duplex":       e("{where}: duplex distinto ({a} vs {b})", "{where}: duplex mismatch ({a} vs {b})", "where", "a", "b"),
		"topo.finding.port_channel": e("{device} {po}: miembros hacia vecinos distintos ({peers}); correcto solo con vPC, StackWise Virtual o MLAG", "{device} {po}: members go to different neighbors ({peers}); correct only with vPC, StackWise Virtual or MLAG", "device", "po", "peers"),
		"topo.segment.name":         e("segmento compartido ({n} equipos)", "shared segment ({n} {n|device|devices})", "n"),
		"topo.text.members":         e("miembros: {list}", "members: {list}", "list"),
	})
}
