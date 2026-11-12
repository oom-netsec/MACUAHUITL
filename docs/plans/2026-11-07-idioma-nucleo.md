# Idioma del núcleo: texto en español que la interfaz no puede traducir

La interfaz ya traduce todo lo que vive en el front (`t()`), los vocabularios cerrados del núcleo (`lib/vocab.ts`, con prueba) y las plantillas de snippets (nombre, campos y ayudas, con prueba contra `internal/assist/*.go`). Lo que sigue lo produce el núcleo como texto libre en español y viaja tal cual a la pantalla: en inglés se ve en español. No se traduce en el front (frágil y sin contexto). Propuesta para el núcleo: cada mensaje lleva un código estable (`code`) y sus parámetros (`args`) además del texto; el front busca `core.<code>` en es/en y usa el texto del núcleo solo como respaldo. Alternativa mínima: el cliente manda `Accept-Language` (metadato gRPC `locale`) y el núcleo elige el catálogo.

## Acoplamientos que hay que romper primero

El front lee texto en español del núcleo para dibujar tarjetas; al agregar idiomas hay que entregar estos datos estructurados:

| Front | Qué lee | Origen |
|---|---|---|
| `modules/security/parse.ts` | «Servidor RADIUS», «Servidor TACACS+», «Hallazgos:», «Emisor», «Serie», «Validez … (N días)», «Llave», «Firma», «servidor pidió:», «mensaje:», «datos:», «enviado», «recibido» | `radiustest.Text`, `tacacstest.Text`, `pki.Text` |
| `modules/calc/bars.ts` | Títulos «Subred …», «VLSM sobre …», filas «Red», «Primera usable», «Última usable», «Hosts usables», columnas «Prefijo», «Nombre», nota «Espacio libre: » | `internal/calc/*.go` |
| `modules/tools/pcapParse.ts` | Encabezados «== Conversaciones», «== Equipos con más tráfico» | `internal/pcapan/text.go` |
| `modules/tools/syslogOpts.ts` | Expresiones sobre los errores de validación («tasa por origen», «ráfaga global», «la cola», «plantilla», «dirección inválida»…) para asignarlos a su campo | `internal/diag/syslogd/{limits,rotate}.go` |
| `lib/core.ts` | `/ya existe/` en el error de guardar para pedir confirmación de reemplazo | `ui/bridge` (`WriteFile`) |
| `modules/snippets/form.ts` | Prefijo `assist: <id>: ` en el error de validación | `internal/assist/snippets.go` |

## Inventario por área

Formato: archivo del núcleo → RPC o campo por donde viaja → ejemplos.

### Seguridad (RADIUS, TACACS+, PKI, IKE)
- `internal/diag/radiustest/radiustest.go` → `SecRadius` (string): causas de «sin respuesta», «respuesta inválida», «Blast-RADIUS», «rechazó la autenticación»; valores `Message-Authenticator` «ausente/válido/inválido» (ya mapeados) y «código N».
- `internal/diag/tacacstest/tacacstest.go` → `SecTacacs`: «la respuesta no se descifra…», «Autenticación rechazada…», «El comando no está autorizado…», «estado …».
- `internal/pki/pki.go` → `SecPki*`: advertencias («llave RSA de menos de 2048 bits…», «vencido», «autofirmado», «vence en N días», «sin SAN…»), etiquetas de `Text` («Uso de llave», «Firma válida», «sí/no»).
- `internal/ikedec/ikedec.go` → `SecIkeDecode`: ~75 mensajes de hallazgo (títulos, detalles, causas) con `Severity` «aviso/error/info» (ya mapeada).

### DNS, TLS, syslog, captura
- `internal/diag/dnsq/{checks,trace,dnssec,query}.go` → `ToolsDns` (string): `Finding{Severity, Code, Detail}` con `Code` estable («sin-edns», «ttl-bajo», «ns-lame»…) y `Detail` en español («TCP/53 no responde: …», «hay varios SPF…»).
- `internal/diag/tlsinspect/tlsinspect.go` → `ToolsTls` (JSON): `Findings[].Detail` («<versión> sigue habilitado; deshabilítalo», «el certificado vence en N días»), `VerifyError`.
- `internal/diag/syslogd/{limits,rotate}.go` → evento `SyslogEvent.error` y errores de `SyslogStart`: validación de límites y plantilla («la plantilla debe llevar {fecha} o {hora}»). Nota: la plantilla usa los tokens `{fecha}`, `{hora}`, `{origen}` en español, que además son sintaxis del usuario.
- `internal/pcapan/text.go` → `ToolsPcap` (string): todo el informe («Paquetes: … · Bytes: …», «== Vecinos (¿a dónde estoy conectado?)»).
- `internal/capture/capture.go`, `internal/diag/args.go` → `DiagEvent.error`: errores de argumentos y de herramientas.

### Transferencias y servidor de archivos
- `internal/diag/fileserve/{tftp,ftp,sshsrv,recv,fileserve}.go` → `TransferLine.Error`, `ServeEvent.transfer` (JSON): motivos de rechazo («origen no permitido», «archivo no publicado», «línea demasiado larga», «orden inválida»). `Dir` «lectura/escritura» y `Result` «ok/error» ya se traducen en el front.
- `internal/diag/transfer/transfer.go`, `internal/service/transfer/{client,transfer}.go` → `TransferResult.report` y errores de validación («URL inválida …», «no pongas la contraseña en la URL…»); `TransferListing.reason` («este servidor no permite listar: …»).

### Asistente de cambios y snippets
- `internal/assist/plan.go`, `l2port.go`, `l3mgmt.go`, `snippets.go`, `templates.go`, `ports.go`, `credrotate.go`, `restore*.go` → `AssistPlan.devices[].notes`, `pre/post` (descripciones de verificación), errores de validación de campos (`Field.Help` ya está traducido; los errores por valor no).
- `internal/assist/run.go`, `internal/service/assist/assist.go` → `AssistEvent.failReason`, `AssistDone` y errores gRPC («el modo asistido no está habilitado…», «la ejecución no está en un estado que admita eso»).
- Los textos de catálogo (`Name`, `Label`, `Help`) siguen llegando en español; el front los reemplaza por clave `snippet.<id>.…`. Una plantilla o campo nuevo sin traducir hace fallar `lib/vocab.test.ts`.

### Flota y análisis
- `internal/fleet/{report,path,l2,fleet,text}.go` → `FleetSummary.rows[].value/detail` («no sincronizado», «NN % usada», «libre X de Y», «reinicio en las 24 h previas a la evidencia»), `PathHop.reason` («el destino es una interfaz de este equipo», «ningún equipo de la flota tiene una ruta conectada…»), `warnings`, `Problem.evidence`, `source` («carpeta de Patrol», ya mapeado).
- `internal/analyze/{rules,timeline,diff}.go` → `Finding.title/explanation/action/detail`, `TimelineEvent.text/note` («ronda N: M comando(s)», «por <usuario>»); `source` «hallazgo/log-equipo/auditoria» ya mapeado.
- `internal/acl/{parse,model}.go` → `Finding.detail` («la regla 1 ya cubre este tráfico») y `LineError` («línea N: …»).
- `internal/change/change.go`, `internal/upgrade/upgrade.go`, `internal/compliance/hardening.go` → `DeviceReport.findings[].detail`, `config_diff` (prefijos «+ sección > línea»), nota fija («Comparación de salidas show; …»), reglas de endurecimiento («sin aaa new-model: …»).
- `internal/drift`, `internal/cleaner` (`cleaner/*.go`, `drift/*.go`) → texto de informe y motivos (`why`) por línea.

### Forense, métricas, Patrol
- `internal/crashinfo/crashinfo.go`, `internal/logintel/debugs.go`, `internal/msgkb/msgkb.go`, `internal/metrics/{ports,series}.go` → `meaning/cause/action/verify` de la base de mensajes, `hint` del crashinfo, anomalías («rara dentro de una familia frecuente…»), advertencias («falta el comando X: …»). La fuente fija «documentación pública de Cisco (sin validar en laboratorio)» también va en español.
- `internal/patrol/job.go`, `internal/core/services.go`, `internal/service/{backup,terminal,visibility,forensic}/*.go` → `DeviceStateChanged.detail`, `JobPhase.detail`, `LoginTest` pasos, errores gRPC («sin equipos», «sin credencial por defecto», «no hay un script %q», «archivo de grabación: …»).
- `internal/scripts/script.go`, `internal/service/scripts/scripts.go` → errores de validación y nombres/descripciones de la biblioteca (datos: «Config · VLAN y puerto de acceso», «Puertos sin uso»).
- Auditoría: `internal/audit` y `d.Audit(...)` en servicios → `AuditRecord.detail` (texto libre con `razon=`, `guard=`).

### Calculadora
- `internal/calc/{addr,misc,bgp,mtu,…}.go` → `CalcResult{title, head, rows, notes}`: toda la salida (títulos, etiquetas de fila, notas) y los errores de entrada («indica el prefijo (10.0.0.0/24 o 10.0.0.0 255.255.255.0)»). Es el módulo con más texto fijo; conviene devolver etiquetas por clave.

### Nombres de carpetas y archivos en disco
Las rutas predeterminadas («outputs/recibidos/», «outputs/terminal/») y los nombres de archivo que propone el núcleo están en español y la interfaz las cita en sus ayudas; cambiarlas rompería datos existentes, así que solo se anotan.

## Fuera de alcance
La CLI `mctl` imprime en español y no usa la interfaz. Los nombres de comandos `show`, protocolos y palabras clave de Cisco no se traducen.
