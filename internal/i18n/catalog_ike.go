package i18n

// Decodificador IKE/IPsec (internal/ikedec): título, explicación y acción de cada hallazgo (ike.finding.<código>.*),
// sus variantes dinámicas, el significado de los estados de SA, las etiquetas del informe de texto (ike.text.*) y los
// valores cerrados (ike.val.*). Los comandos de Cisco, los estados (MM_*, QM_IDLE), los nombres de equipo y la salida
// pegada que sirve de evidencia no se traducen. Las reglas siguen la documentación pública de Cisco, sin validar en laboratorio.
func init() {
	e := func(es, en string, args ...string) entry { return entry{Es: es, En: en, Args: args} }
	add(map[string]entry{
		"ike.finding.p1_propuesta.title":               e("Propuestas de fase 1 (IKE) no coinciden", "IKE phase 1 proposals do not match"),
		"ike.finding.p1_propuesta.explanation":         e("Ninguna propuesta IKE del par coincide con las políticas locales (cifrado, hash/integridad, PRF, grupo DH, método de autenticación o lifetime).", "None of the peer's IKE proposals matches the local policies (encryption, hash/integrity, PRF, DH group, authentication method or lifetime)."),
		"ike.finding.p1_propuesta.action":              e("Compara 'crypto isakmp policy' / 'crypto ikev2 proposal' (ASA: 'crypto ikev1|ikev2 policy') en ambos extremos y deja al menos una idéntica; evita DES/3DES/MD5/grupos 1, 2 y 5.", "Compare 'crypto isakmp policy' / 'crypto ikev2 proposal' (ASA: 'crypto ikev1|ikev2 policy') on both ends and leave at least one identical; avoid DES/3DES/MD5 and groups 1, 2 and 5."),
		"ike.finding.p1_propuesta.explanation_attrs":   e("Ninguna propuesta IKE del par coincide con las políticas locales (cifrado, hash/integridad, PRF, grupo DH, método de autenticación o lifetime). Atributos que no coinciden según el equipo: {attrs}.", "None of the peer's IKE proposals matches the local policies (encryption, hash/integrity, PRF, DH group, authentication method or lifetime). Attributes that do not match according to the device: {attrs}.", "attrs"),
		"ike.finding.p2_propuesta.title":               e("Propuestas de fase 2 (IPsec) no coinciden", "IPsec phase 2 proposals do not match"),
		"ike.finding.p2_propuesta.explanation":         e("El transform-set / IPsec proposal ofrecido no coincide con el local (ESP cifrado, integridad, modo túnel/transporte).", "The offered transform-set / IPsec proposal does not match the local one (ESP encryption, integrity, tunnel/transport mode)."),
		"ike.finding.p2_propuesta.action":              e("Iguala 'crypto ipsec transform-set' (IKEv2/ASA: 'crypto ipsec ikev2 ipsec-proposal') en ambos extremos, incluido el modo.", "Make 'crypto ipsec transform-set' (IKEv2/ASA: 'crypto ipsec ikev2 ipsec-proposal') identical on both ends, including the mode."),
		"ike.finding.pfs.title":                        e("PFS o grupo DH de fase 2 distinto", "Phase 2 PFS or DH group differs"),
		"ike.finding.pfs.explanation":                  e("Un extremo exige PFS (o un grupo DH distinto) para la fase 2 y el otro no; también falla el rekey de CREATE_CHILD_SA.", "One end requires PFS (or a different DH group) for phase 2 and the other does not; the CREATE_CHILD_SA rekey also fails."),
		"ike.finding.pfs.action":                       e("Configura 'set pfs groupN' igual en ambos crypto maps / perfiles IPsec, o quítalo de ambos.", "Configure 'set pfs groupN' the same on both crypto maps / IPsec profiles, or remove it from both."),
		"ike.finding.pfs.explanation_rejected":         e("El par propone PFS (atributo 'group is N') en fase 2 y la propuesta fue rechazada: si el transform-set coincide, la causa es el PFS. Un extremo exige PFS (o un grupo DH distinto) para la fase 2 y el otro no; también falla el rekey de CREATE_CHILD_SA.", "The peer proposes PFS ('group is N' attribute) in phase 2 and the proposal was rejected: if the transform-set matches, the cause is PFS. One end requires PFS (or a different DH group) for phase 2 and the other does not; the CREATE_CHILD_SA rekey also fails."),
		"ike.finding.psk.title":                        e("Clave precompartida (PSK) incorrecta o falla de autenticación", "Pre-shared key (PSK) is wrong or authentication fails"),
		"ike.finding.psk.explanation":                  e("Los mensajes 5/6 de Main Mode (o IKE_AUTH en IKEv2) no se descifran o el hash/AUTH no verifica: casi siempre la PSK difiere, o el par usa otro método (certificados).", "Main Mode messages 5/6 (or IKE_AUTH in IKEv2) cannot be decrypted or the hash/AUTH does not verify: almost always the PSK differs, or the peer uses another method (certificates)."),
		"ike.finding.psk.action":                       e("Vuelve a escribir la PSK en ambos extremos ('crypto isakmp key', keyring IKEv2 o tunnel-group ipsec-attributes) cuidando espacios finales y mayúsculas; verifica el método de autenticación.", "Re-enter the PSK on both ends ('crypto isakmp key', IKEv2 keyring or tunnel-group ipsec-attributes), watching for trailing spaces and case; verify the authentication method."),
		"ike.finding.psk_ausente.title":                e("No hay PSK configurada para el par", "No PSK is configured for the peer"),
		"ike.finding.psk_ausente.explanation":          e("El equipo no encuentra una clave para la dirección o identidad del par.", "The device cannot find a key for the peer's address or identity."),
		"ike.finding.psk_ausente.action":               e("Agrega la PSK para la IP real del par (ojo con NAT: la IP pública) en el keyring o 'crypto isakmp key'.", "Add the PSK for the peer's real IP (beware of NAT: the public IP) in the keyring or 'crypto isakmp key'."),
		"ike.finding.sin_respuesta.title":              e("El par no responde (retransmisiones)", "The peer does not respond (retransmissions)"),
		"ike.finding.sin_respuesta.explanation":        e("Se agotaron las retransmisiones sin respuesta: el par no recibe o no contesta IKE.", "Retransmissions were exhausted with no reply: the peer does not receive or does not answer IKE."),
		"ike.finding.sin_respuesta.action":             e("Comprueba alcance a la IP del par, que UDP 500 (y 4500 con NAT) no esté filtrado en el camino, que el par tenga crypto map/perfil en esa interfaz y la dirección de peer correcta.", "Check reachability to the peer IP, that UDP 500 (and 4500 with NAT) is not filtered along the path, that the peer has a crypto map/profile on that interface and the right peer address."),
		"ike.finding.retrans_key_exch.title":           e("Retransmisiones en MM_KEY_EXCH", "Retransmissions in MM_KEY_EXCH"),
		"ike.finding.retrans_key_exch.explanation":     e("La propuesta ya se aceptó y el DH terminó, pero los mensajes 5/6 no se completan: PSK distinta o, si hay NAT, UDP 4500 bloqueado.", "The proposal was already accepted and the DH exchange finished, but messages 5/6 do not complete: a different PSK or, with NAT, UDP 4500 blocked."),
		"ike.finding.retrans_key_exch.action":          e("Revisa la PSK y que UDP 4500 pase entre los pares.", "Check the PSK and that UDP 4500 passes between the peers."),
		"ike.finding.proxy_id.title":                   e("Proxy IDs / traffic selectors no coinciden", "Proxy IDs / traffic selectors do not match"),
		"ike.finding.proxy_id.explanation":             e("Las redes protegidas (ACL de cripto / traffic selectors) que propone el par no son el espejo exacto de las locales.", "The protected networks (crypto ACL / traffic selectors) that the peer proposes are not the exact mirror of the local ones."),
		"ike.finding.proxy_id.action":                  e("Haz la ACL de cripto de un lado espejo exacto de la del otro (mismas redes y máscaras, mismo protocolo/puerto); en VTI usa 'any any'.", "Make the crypto ACL on one side the exact mirror of the other (same networks and masks, same protocol/port); on a VTI use 'any any'."),
		"ike.finding.identidad.title":                  e("Identidad del par no coincide con ningún perfil", "Peer identity does not match any profile"),
		"ike.finding.identidad.explanation":            e("La identidad que envía el par (IP, FQDN, DN) no coincide con 'match identity remote' de ningún perfil, o no existe el tunnel-group.", "The identity the peer sends (IP, FQDN, DN) does not match 'match identity remote' of any profile, or the tunnel-group does not exist."),
		"ike.finding.identidad.action":                 e("Revisa 'match identity remote address|fqdn' del perfil IKEv2/ISAKMP (o el tunnel-group en ASA) y la 'identity local' del otro extremo.", "Check 'match identity remote address|fqdn' of the IKEv2/ISAKMP profile (or the tunnel-group on ASA) and the other end's 'identity local'."),
		"ike.finding.nat_t.title":                      e("NAT-T: hay NAT entre los pares", "NAT-T: there is NAT between the peers"),
		"ike.finding.nat_t.explanation":                e("Se detectó NAT en el camino: IKE y ESP viajan encapsulados en UDP 4500.", "NAT was detected on the path: IKE and ESP travel encapsulated in UDP 4500."),
		"ike.finding.nat_t.action":                     e("Permite UDP 500 y UDP 4500 entre los pares; con NAT no basta abrir ESP (IP 50). Usa la IP pública del par en PSK y peer.", "Allow UDP 500 and UDP 4500 between the peers; with NAT, opening ESP (IP 50) is not enough. Use the peer's public IP in the PSK and peer."),
		"ike.finding.lifetime.title":                   e("Lifetime distinto", "Different lifetime"),
		"ike.finding.lifetime.explanation":             e("Los lifetimes de fase 1 o 2 difieren; según la plataforma se toma el menor o se rechaza la propuesta.", "The phase 1 or 2 lifetimes differ; depending on the platform the lower one is used or the proposal is rejected."),
		"ike.finding.lifetime.action":                  e("Iguala 'lifetime' de la política IKE y 'set security-association lifetime' en ambos extremos.", "Make the IKE policy 'lifetime' and 'set security-association lifetime' equal on both ends."),
		"ike.finding.dpd.title":                        e("DPD: el par dejó de responder", "DPD: the peer stopped responding"),
		"ike.finding.dpd.explanation":                  e("Se enviaron consultas DPD (R_U_THERE / liveness) sin respuesta: el par se reinició, perdió la SA o el camino se cortó.", "DPD queries (R_U_THERE / liveness) were sent with no reply: the peer rebooted, lost the SA or the path was cut."),
		"ike.finding.dpd.action":                       e("Verifica alcance UDP 500/4500 y el estado de la SA en el par; con 'crypto isakmp keepalive' / 'dpd' en ambos lados la SA huérfana se limpia sola.", "Verify UDP 500/4500 reachability and the SA state on the peer; with 'crypto isakmp keepalive' / 'dpd' on both sides the orphaned SA is cleaned up on its own."),
		"ike.finding.sa_estado.title":                  e("SA atascadas en negociación", "SAs stuck in negotiation"),
		"ike.finding.sa_estado.explanation":            e("Estados que no son QM_IDLE/MM_ACTIVE/READY indican en qué paso se detuvo la negociación.", "States other than QM_IDLE/MM_ACTIVE/READY show the step where the negotiation stopped."),
		"ike.finding.sa_estado.action":                 e("Corre el debug de la fase indicada en ambos extremos mientras generas tráfico, y pégalo aquí.", "Run the debug of the indicated phase on both ends while you generate traffic, and paste it here."),
		"ike.finding.ipsec_sin_sa.title":               e("Sin SA de IPsec para estas redes", "No IPsec SA for these networks"),
		"ike.finding.ipsec_sin_sa.explanation":         e("La entrada existe en el crypto map pero no hay SPI de entrada ni salida: la fase 2 no se ha negociado para este par de redes.", "The entry exists in the crypto map but there is no inbound or outbound SPI: phase 2 has not been negotiated for this pair of networks."),
		"ike.finding.ipsec_sin_sa.action":              e("Genera tráfico interesante desde la LAN (ping con origen en la red protegida) y revisa el debug de fase 2 (proxy IDs, transform-set, PFS).", "Generate interesting traffic from the LAN (ping sourced from the protected network) and check the phase 2 debug (proxy IDs, transform-set, PFS)."),
		"ike.finding.ipsec_unidireccional.title":       e("Tráfico cifrado sale pero no regresa", "Encrypted traffic leaves but does not come back"),
		"ike.finding.ipsec_unidireccional.explanation": e("Se encapsula hacia el par pero no llega nada de vuelta: el otro extremo no responde por el túnel o el ESP de regreso se pierde.", "Traffic is encapsulated toward the peer but nothing comes back: the other end does not answer through the tunnel or the return ESP is lost."),
		"ike.finding.ipsec_unidireccional.action":      e("En el par: ruta de regreso hacia esta LAN, NAT exemption (no NATear el tráfico del túnel), ACL de cripto espejo y sus contadores; en el camino: ESP (IP 50) o UDP 4500 filtrados.", "On the peer: return route to this LAN, NAT exemption (do not NAT tunnel traffic), mirrored crypto ACL and its counters; on the path: ESP (IP 50) or UDP 4500 filtered."),
		"ike.finding.ipsec_solo_entrada.title":         e("Llega tráfico del túnel pero no sale nada", "Tunnel traffic arrives but nothing goes out"),
		"ike.finding.ipsec_solo_entrada.explanation":   e("Se desencapsula lo que manda el par pero las respuestas locales no entran al túnel.", "What the peer sends is decapsulated but local replies do not enter the tunnel."),
		"ike.finding.ipsec_solo_entrada.action":        e("Revisa que la ruta hacia la red remota salga por la interfaz con el crypto map / túnel, la NAT exemption local y la ACL de cripto.", "Check that the route to the remote network goes out the interface with the crypto map / tunnel, the local NAT exemption and the crypto ACL."),
		"ike.finding.ipsec_sin_trafico.title":          e("SA arriba sin tráfico", "SA up with no traffic"),
		"ike.finding.ipsec_sin_trafico.explanation":    e("La fase 2 está negociada pero no pasa tráfico en ningún sentido.", "Phase 2 is negotiated but no traffic flows in either direction."),
		"ike.finding.ipsec_sin_trafico.action":         e("Confirma que el tráfico de prueba coincide con la ACL de cripto y que se enruta hacia la interfaz del túnel.", "Confirm that the test traffic matches the crypto ACL and is routed toward the tunnel interface."),
		"ike.finding.ipsec_errores.title":              e("Contadores de error de IPsec", "IPsec error counters"),
		"ike.finding.ipsec_errores.explanation":        e("Hay errores de envío/recepción, de integridad o de anti-replay en la SA.", "There are send/receive, integrity or anti-replay errors on the SA."),
		"ike.finding.ipsec_errores.action":             e("send errors suele ser falta de SA o de ruta; recv/verify/replay failed apuntan a pérdidas, reordenamiento (QoS) o llaves desincronizadas: limpia la SA y observa si vuelven a subir.", "send errors usually mean a missing SA or route; recv/verify/replay failed point to loss, reordering (QoS) or out-of-sync keys: clear the SA and see whether they come back."),
		"ike.finding.limite_sas.title":                 e("Se omitieron SAs por exceder el tope", "SAs were omitted for exceeding the limit"),
		"ike.finding.limite_sas.explanation":           e("El resultado lista como máximo {max} SAs IKE y {max} SAs IPsec; se omitieron {sa} SAs IKE y {ipsec} SAs IPsec.", "The result lists at most {max} IKE SAs and {max} IPsec SAs; {sa} IKE SAs and {ipsec} IPsec SAs were omitted.", "max", "sa", "ipsec"),
		"ike.finding.limite_sas.action":                e("Pega solo la salida del par o túnel que investigas.", "Paste only the output of the peer or tunnel you are investigating."),

		// atributos de fase 1 que no coinciden
		"ike.val.attr.encryption":  e("cifrado", "encryption"),
		"ike.val.attr.hash":        e("hash", "hash"),
		"ike.val.attr.dh_group":    e("grupo DH", "DH group"),
		"ike.val.attr.auth_method": e("método de autenticación", "authentication method"),
		"ike.val.attr.lifetime":    e("lifetime", "lifetime"),

		// qué dice cada estado de SA que no es estable (evidencia de sa-estado)
		"ike.state.phase1_stalled": e("fase 1 detenida en el primer intercambio: el par no responde o rechaza la propuesta", "phase 1 stalled in the first exchange: the peer does not respond or rejects the proposal"),
		"ike.state.aggressive":     e("Aggressive Mode sin respuesta: el par no contesta o rechaza la propuesta/identidad", "Aggressive Mode with no reply: the peer does not answer or rejects the proposal/identity"),
		"ike.state.ikev2_neg":      e("IKEv2 en negociación sin terminar: sin respuesta, propuestas o autenticación", "IKEv2 negotiation not finished: no reply, proposals or authentication"),
		"ike.state.dh_stalled":     e("propuesta aceptada pero el intercambio DH no avanza", "proposal accepted but the DH exchange does not progress"),
		"ike.state.auth_failed":    e("falla en la autenticación: PSK distinta o UDP 4500 bloqueado con NAT", "authentication failure: different PSK or UDP 4500 blocked with NAT"),
		"ike.state.deleting":       e("SA en borrado", "SA being deleted"),

		// propuestas
		"ike.proposal.source.v1_transform": e("transform {transform} del par vs política {policy}", "peer transform {transform} vs policy {policy}", "transform", "policy"),
		"ike.proposal.source.v1_proposal":  e("propuesta {n} del par", "peer proposal {n}", "n"),
		"ike.proposal.source.received":     e("recibida del par", "received from the peer"),
		"ike.proposal.source.expected":     e("esperada (local)", "expected (local)"),
		"ike.val.result.accepted":          e("aceptada", "accepted"),
		"ike.val.result.rejected":          e("rechazada", "rejected"),

		// estado de cada fase
		"ike.val.phase.established": e("establecida", "established"),
		"ike.val.phase.failed":      e("falló", "failed"),
		"ike.val.phase.mixed":       e("mixta", "mixed"),
		"ike.val.phase.incomplete":  e("incompleta", "incomplete"),
		"ike.val.phase.no_data":     e("sin datos", "no data"),

		// severidad en el texto del informe
		"ike.val.severity.aviso": e("aviso", "warning"),
		"ike.val.severity.error": e("error", "error"),
		"ike.val.severity.info":  e("info", "info"),

		"ike.note": e("Reglas basadas en la documentación pública de Cisco, sin validar en laboratorio: confirma cada causa contra la configuración de ambos extremos.", "Rules based on Cisco's public documentation, not validated in the lab: confirm each cause against the configuration of both ends."),

		// informe de texto
		"ike.text.unrecognized": e("No se reconoció salida de IKE/IPsec. Pega debug crypto isakmp/ikev2/ipsec o show crypto isakmp sa / ikev2 sa detail / ipsec sa.", "No IKE/IPsec output was recognized. Paste debug crypto isakmp/ikev2/ipsec or show crypto isakmp sa / ikev2 sa detail / ipsec sa."),
		"ike.text.detected":     e("Detectado: {sources}\nFase 1: {phase1}   Fase 2: {phase2}", "Detected: {sources}\nPhase 1: {phase1}   Phase 2: {phase2}", "sources", "phase1", "phase2"),
		"ike.text.proposals":    e("Propuestas:", "Proposals:"),
		"ike.text.proposal":     e("F{phase} {source}: {detail}", "P{phase} {source}: {detail}", "phase", "source", "detail"),
		"ike.text.result":       e("→ {result}", "→ {result}", "result"),
		"ike.text.sas":          e("SA:", "SA:"),
		"ike.text.findings":     e("Hallazgos:", "Findings:"),
		"ike.text.action":       e("Acción: {action}", "Action: {action}", "action"),
		"ike.text.note":         e("Nota: {note}", "Note: {note}", "note"),
	})
}
