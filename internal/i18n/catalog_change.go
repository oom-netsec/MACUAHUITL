package i18n

// Cambios (comparación PRE/POST): hallazgos por faceta, nota fija y texto del informe. Los valores (equipos,
// interfaces, vecinos, estados de protocolos, versiones) viajan como argumentos y no se traducen; las líneas
// de configuración de la diferencia tampoco.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"change.note": e("Comparación de salidas show; interpretación según la documentación pública de Cisco IOS-XE, sin validar en laboratorio. La app no aplica configuración.",
			"Comparison of show outputs; interpretation based on public Cisco IOS-XE documentation, not validated in the lab. The app does not apply configuration."),

		"change.detail.no_post":      e("no está en la captura POST", "not in the POST capture"),
		"change.detail.post_failed":  e("la captura POST falló: {detail}", "the POST capture failed: {detail}", "detail"),
		"change.detail.pre_failed":   e("la captura PRE falló ({detail}): no hay línea base completa", "the PRE capture failed ({detail}): there is no complete baseline", "detail"),
		"change.detail.no_pre":       e("no está en la captura PRE: sin línea base", "not in the PRE capture: no baseline"),
		"change.detail.missing_post": e("sin salida de {cmd:q} en POST: no se puede comparar", "no output of {cmd:q} in POST: cannot compare", "cmd"),
		"change.detail.no_pre_data":  e("sin salidas reconocidas en PRE: no hay línea base", "no recognized outputs in PRE: no baseline"),
		"change.detail.no_post_data": e("sin salidas reconocidas en POST: no se puede comparar", "no recognized outputs in POST: cannot compare"),
		"change.detail.version":      e("{from} → {to}", "{from} → {to}", "from", "to"),
		"change.detail.reloaded":     e("el equipo se recargó entre PRE y POST (uptime {min} min)", "the device reloaded between PRE and POST (uptime {min} min)", "min"),
		"change.detail.iface_gone":   e("{name} estaba up/up y ya no aparece", "{name} was up/up and no longer appears", "name"),
		"change.detail.iface_down":   e("{name}: up/up → {to}", "{name}: up/up → {to}", "name", "to"),
		"change.detail.iface_up":     e("{name}: {from} → up/up", "{name}: {from} → up/up", "name", "from"),
		"change.detail.iface_new":    e("{name}: no existía → up/up", "{name}: did not exist → up/up", "name"),
		"change.detail.nbr_lost":     e("vecino perdido: {name} (puerto {port})", "neighbor lost: {name} (port {port})", "name", "port"),
		"change.detail.nbr_new":      e("vecino nuevo: {name} (puerto {port})", "new neighbor: {name} (port {port})", "name", "port"),
		"change.detail.nbr_port":     e("{name}: puerto remoto {from} → {to}", "{name}: remote port {from} → {to}", "name", "from", "to"),
		"change.detail.ospf_lost":    e("adyacencia perdida: {name} (estaba {state})", "adjacency lost: {name} (was {state})", "name", "state"),
		"change.detail.state":        e("{name}: {from} → {to}", "{name}: {from} → {to}", "name", "from", "to"),
		"change.detail.ospf_new":     e("adyacencia nueva: {name} ({state})", "new adjacency: {name} ({state})", "name", "state"),
		"change.detail.bgp_gone":     e("vecino {name}: Established → ya no aparece", "neighbor {name}: Established → no longer appears", "name"),
		"change.detail.bgp_down":     e("vecino {name}: Established → {state}", "neighbor {name}: Established → {state}", "name", "state"),
		"change.detail.bgp_new":      e("vecino nuevo {name} ({state})", "new neighbor {name} ({state})", "name", "state"),
		"change.detail.bgp_up":       e("vecino {name}: {state} → Established", "neighbor {name}: {state} → Established", "name", "state"),
		"change.detail.bgp_prefixes": e("vecino {name}: prefijos recibidos {from} → {to}", "neighbor {name}: received prefixes {from} → {to}", "name", "from", "to"),
		"change.detail.routes_zero":  e("{name}: {from} → 0 rutas", "{name}: {from} → 0 routes", "name", "from"),
		"change.detail.routes":       e("{name}: {from} → {to}", "{name}: {from} → {to}", "name", "from", "to"),
		"change.detail.mac_drop":     e("VLAN {name}: {from} → {to}", "VLAN {name}: {from} → {to}", "name", "from", "to"),
		"change.detail.arp_drop":     e("{name}: {from} → {to}", "{name}: {from} → {to}", "name", "from", "to"),
		"change.detail.hsrp_gone":    e("{name} ya no aparece (estaba {state})", "{name} no longer appears (was {state})", "name", "state"),
		"change.detail.hsrp_new":     e("{name}: no existía → {to}", "{name}: did not exist → {to}", "name", "to"),
		"change.detail.stp_gone":     e("{name} ya no aparece", "{name} no longer appears", "name"),
		"change.detail.stp_root":     e("{name}: raíz {from} → {to}", "{name}: root {from} → {to}", "name", "from", "to"),
		"change.detail.stp_new":      e("{name} nueva (raíz {root})", "{name} is new (root {root})", "name", "root"),
		"change.detail.stp_port":     e("{name}: puerto raíz {from} → {to}", "{name}: root port {from} → {to}", "name", "from", "to"),
		"change.word.none":           e("ninguno", "none"),
		"change.detail.config":       e("running-config: {added} agregadas, {removed} quitadas", "running-config: {added} added, {removed} removed", "added", "removed"),
		"change.diff.more":           e("… {n} líneas más", "… {n} more {n|line|lines}", "n"),

		"change.text.verdict.ok":         e("SIN CAMBIOS INESPERADOS", "NO UNEXPECTED CHANGES"),
		"change.text.verdict.review":     e("REVISAR", "REVIEW"),
		"change.text.verdict.regression": e("REGRESIÓN", "REGRESSION"),
		"change.text.level.info":         e("info", "info"),
		"change.text.level.review":       e("revisar", "review"),
		"change.text.level.regression":   e("REGRESIÓN", "REGRESSION"),
	})
}
