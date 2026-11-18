# 43e: pulido de Windows e idioma (plan)

Origen: QA funcional en Windows 11 real (v1.2.0 y main ea30c255) que mandó Release. Sin pérdida de datos ni fallos de seguridad; sí
resolvers que no existen en Windows, errores crudos, horas sin zona y español filtrado con la app en inglés. Nueve PRs chicos, cada uno con
su prueba escrita PRIMERO (roja). Este documento es solo el plan: todo lo que dice «por confirmar» se confirma al escribir la prueba roja,
no suponiendo. Líneas citadas leídas en origin/main b5437418.

## Decisiones ya tomadas (de Release)

- Las acciones de auditoría guardadas conservan su clave estable: la cadena de hashes no deja reescribirlas. Solo se traduce lo que se muestra.
- Lo que ya está en disco se lee viejo y se escribe nuevo, o se deja y queda escrito el motivo (sección «Lo que ya está en disco»).
- Los adhoc fallidos en `created` y las carpetas `lote-*` vacías son de la fase 46 (sección «Fase 46»).
- Idioma canónico inglés; el español se elige en Ajustes. Ningún cambio de 43e toca la cadena de auditoría ni borra evidencia.

## 43e-1 Resolvers de Windows (ALTO)

Hoy: `dns query|hygiene|transport` sin `-s` llama `dnsq.SystemResolvers(resolvConf)` (service/tools/tools.go:79-82), con `resolvConf =
"/etc/resolv.conf"` fijo (tools.go:29); `SystemResolvers` (dnsq/query.go:415-428) lee el archivo con `dns.ClientConfigFromFile`. En Windows falla
con «open /etc/resolv.conf». Ya existe GetAdaptersAddresses en el repo (diag/proc_windows.go:35-52) pero con `GAA_FLAG_SKIP_DNS_SERVER`.

Cambio mínimo: `var systemResolvers = func() ([]dnsq.Server, error)` en tools.go (seam para pruebas). Linux: lo de hoy. Windows
(`dnsq/resolvers_windows.go`): GetAdaptersAddresses sin SKIP_DNS_SERVER, adaptadores con `OperStatus == IfOperStatusUp` y no loopback, recorre
`FirstDnsServerAddress`, sin repetidos, descarta `fec0:0:0:ffff::1-3` (los DNS «fantasma» de Windows) y direcciones no específicas; puerto 53.
Sin ninguno: error claro nuevo `dns.err.no_resolvers` («no se encontró un resolver del sistema; pasa uno con -s IP»), también en Linux cuando
resolv.conf no existe (hoy «dnsq: open …»). La lista pasa por el mismo `Guard().Allow` (tools.go:91): sin atajos.

Prueba roja: `TestSystemResolversSinSFalla…` en tools_test.go: con el seam devolviendo `[]Server{{Host:"192.0.2.53"}}`, `dns query` sin `Servers`
consulta a ese host (hoy en Windows no hay seam); y `TestSinResolversPideS`: seam vacío da `dns.err.no_resolvers` (FailedPrecondition) en es y en. [W]
`resolvers_windows_test.go`: la función real no devuelve `fec0:0:0:ffff::` ni vacío con una NIC activa (se salta si no hay). Parseo de la lista de
adaptadores en una función pura probada en [T] con una tabla (arriba/abajo, repetidos, fantasma, IPv6).

Riesgos: DNS de una VPN o NIC virtual entran a la lista (es lo que usa el sistema); sin RFC aparte, `Allow` ya limita a lo permitido. Sin datos en disco.

## 43e-2 Errores legibles (MEDIO)

Hoy:
- Sin núcleo: `ipc.Dial` crea el cliente sin conectar (ipc.go:44-50; `grpc.NewClient`), el primer RPC falla con `Unavailable … cannot find the file`
  y `main.go:162` solo hace `LocalizeUsage(err)`. `ipc.ErrNotRunning` ya existe (ipc.go:24, «ipc: el núcleo no está corriendo») y `core stop` lo usa
  (core.go:52), pero ningún otro comando.
- Prefijo gRPC: no hay conversión en mctl; `printErr` (main.go:88) imprime `err.Error()`, que para un status es «rpc error: code = X desc = …».
- «vault: vault:»: 38 sitios hacen `fmt.Errorf("vault: %w", err)` (vault.go:136-756, backup.go:111-215, seal.go:42-71) y los centinelas del catálogo ya
  empiezan con «vault: » (catalog_vault.go:7-15). No se fijó de qué ruta sale el doble: se fija con la prueba roja (abrir respaldo inexistente,
  exportar a carpeta inexistente, `Open` de bóveda corrupta).
- Ruta relativa con «GetFileAttributesEx»: la cadena es de `os.Stat` en Windows; candidatos: outputs.go:97 y :94 (`prefs.outputs.ilegible` con
  `err` crudo) y cualquier `os.Stat` de mctl. El QA no dice qué comando fue (pregunta abajo).
- «0700» en Windows: catalog_outputs.go:15 (`no_existe`) y :23-24 (`permisos`), que en Windows nunca debería salir `permisos` (outputs.go:123) pero
  `no_existe` (outputs.go:80) sí.
- Barras mezcladas: `mctl.security.ca_written` pone `{dir}/` literal (catalog_mctl_a.go:123) y `pkiCaInit` imprime `dir` tal cual lo tecleó el usuario
  (security.go:329).

Cambio mínimo:
1. `cli.CoreError(err)` (cmd/mctl/cli) aplicado una vez en `run` (main.go:~162), junto a `LocalizeUsage`: si `status.Code == Unavailable` y el mensaje
   es de conexión (no de un servicio como «cerrándose»), devuelve `cli.Err("mctl.err.core_down")` = «el núcleo no está corriendo; arráncalo (app, o
   macuahuitld)»; para cualquier otro status devuelve `errors.New(status.Convert(err).Message())` (sin «rpc error: code =»). Conserva `ExitError`.
   Vale en Linux (socket inexistente) y Windows (pipe).
2. Un `wrapVault(err)` único que no antepone «vault: » si el texto ya lo trae; sustituye los 38 sitios (o solo los de rutas con prueba roja).
3. `outputsErr(…ilegible)`: el `err` pasa por `i18n`/`fs.PathError` → solo causa (`errors.Unwrap` de `*PathError`), sin `GetFileAttributesEx`.
4. Variantes sin «0700» cuando `OutputsGOOS == "windows"`: `no_existe_win` («créala; la app le pondrá permisos solo de tu usuario» si es lo que hace
   `MkdirPrivate`, si no solo «créala»); `permisos` ya no sale en Windows.
5. `ca_written` sin `/` final y `pkiCaInit` imprime `filepath.Clean(abs)`; revisar otros `{dir}/` en catálogos (grep `\}/` en catalog_*).

Pruebas rojas: `TestCoreCaidoMensajeLegible` (main_test: sin servidor, `mctl job list` imprime la frase y código 1, en es y en, sin «rpc error»,
«Unavailable», «pipe» ni «cannot find»); `TestStatusSinPrefijoRPC` (un status `NotFound/desc=x` sale «x»); `TestVaultSinTartamudeo` (tres rutas, sin
«vault: vault:»); `TestOutputsIlegibleSinApiCruda` y `TestOutputsWindowsSinCeroSieteCeroCero` (con `OutputsGOOS="windows"`, ningún mensaje contiene «0700»);
`TestCaWrittenUnaBarra` (Windows simulado: ninguna `/` junto a `\`).

Riesgos: la prueba `noegress` — `cli` ya importa `grpc/status`, no `net`. `Unavailable` también lo usan servicios (visibility.go:124, field.go:163):
se distingue por el motivo (`ErrorInfo.Reason`) o porque el error no trae `ErrorInfo`; un status con reason no se pisa. Los errores de usuario de otros
idiomas no cambian (el catálogo ya los localiza).

## 43e-3 Id del preview de `cred backup import` (MEDIO)

Hoy: `PreviewBackupImport` pone `Id: i.ID` (core/respaldo.go:~316), y `i.ID` es el id DENTRO del respaldo: `WriteBackup` hace `c.ID = ""` «el respaldo
asigna IDs propios» (vault/backup.go:132). `classify` (respaldo.go:257-279) compara por etiqueta y contenido y, si son iguales, el estado es `igual`
con `target` = id vivo, que no se muestra. Veredicto: NO es un bug de pérdida ni de mezcla; es el id del respaldo, pero la tabla (`ID ETIQUETA ESTADO`,
catalog_mctl_a.go:102) lo presenta como si fuera el de la bóveda. Además `--decision` acepta ese id (backup.go:141-145), así que el valor se queda.

Cambio mínimo: encabezado «BACKUP ID» (es: «ID EN EL RESPALDO») y, cuando el estado es `igual` o `conflicto`, columna «ID EN LA BÓVEDA» con `target`. Hace
falta un campo `target_id` en `VaultBackupItem` (proto, aditivo; campo nuevo no rompe clientes). Si se prefiere sin proto: solo el encabezado.
Prueba roja: `TestPreviewIgualMuestraIdVivo` (core): respaldo y bóveda con la misma credencial; el item `igual` trae `TargetId == id vivo != Id`.
Mctl: `TestImportPreviewEncabezados`. Riesgos: proto aditivo (regenerar y `buf breaking`); el front puede ignorar el campo. Sin datos en disco.

## 43e-4 nmap `-Pn` y aviso con 0 hosts up (MEDIO)

Hoy: `buildPlan` Nmap (diag/args.go:195-215) arma `-sT|-sS|-sU|-sn`, `-p`, `-T`, `-sV`, `-6`, `-n -oG - host`; sin opción para saltar el descubrimiento, así que
127.0.0.1 o una IP local dan «0 hosts up». Cualquier clave desconocida falla en `o.done()` (args.go:118-128). Nadie interpreta la salida: el núcleo la
reenvía línea a línea (service/diag/diag.go:112-114).

Cambio mínimo: `o.boolean("skip_discovery")` → `-Pn` (antes de `-n`); combinada con `scan=ping` (`-sn`) es error claro (`diag.err.skip_with_ping`).
Aviso: en el mismo `Run` de service/diag, la última línea `# Nmap done … (0 hosts up)` del `-oG` envía una `OutputLine` de aviso
(`diag.warn.zero_up`: «0 hosts respondieron; si el equipo está arriba, repite con -o skip_discovery=true (-Pn)»); sin campo proto nuevo, sirve a mctl y a la app.
Ayuda: mctl (diag.go:179-185) y help_en.txt listan `nmap -o: scan, ports, timing, service_detection, skip_discovery`.

Prueba roja: `TestNmapSkipDiscoveryArgv` (args_test: argv contiene `-Pn` antes de `-oG`; con `scan=ping` error; sin la opción, argv idéntico al de hoy);
`TestAvisoCeroHostsUp` (service/diag con salida simulada `(0 hosts up)` envía el aviso una vez; con `(1 host up)` no). Riesgos: `-Pn` contra una red /24 es lento
(todos «up»): se mantiene el límite actual de CIDR; el texto del aviso no sale en el archivo de salida (solo en el flujo).

## 43e-5 `pki ca init` (BAJO)

Hoy: `pkiCaInit` hace `os.Mkdir(dir, 0o700)` y `sys.MkdirPrivate` ANTES de pedir la contraseña y llamar al núcleo (security.go:301-308); si falla la
contraseña (`newPassword`, :46), el RPC (:314) o `writeNew` (:318-323) la carpeta queda vacía y el siguiente intento da «Cannot create a file when that
file already exists». El error de stdin es `ErrWrap("mctl.cli.stdin_expected", err, …)` (cli.go:118): «expected "Password to seal the key:" on stdin: EOF».

Cambio mínimo: crear la carpeta DESPUÉS de tener `pw` y la respuesta del núcleo; si `writeNew` falla a medias, quitar solo los dos archivos que este
comando creó y la carpeta si él la creó (`created bool`). Nunca borrar una carpeta preexistente. `stdin_expected`: sin la cola «EOF» cuando `err == io.EOF`:
«se necesita la contraseña por stdin («Contraseña para sellar la llave») y no llegó nada; usa una terminal o redirige un archivo» (clave `mctl.cli.stdin_eof`).

Prueba roja: `TestCaInitFallaNoDejaCarpeta` (mctl: stdin vacío → error, `dir` no existe; contraseñas distintas → ídem); `TestCaInitCarpetaPreexistenteIntacta`
(carpeta ya existente con un archivo propio: el error es el de siempre y nada se borra); `TestStdinEOFLegible`. Riesgos: el orden cambia (ya no se crea antes de preguntar):
el error «carpeta ya existe» ahora puede salir tras pedir la contraseña: se comprueba con `os.Stat` antes de preguntar, sin crear.

## 43e-6 `transfer serve|get|ls` (BAJO, los 7 puntos del QA)

1. Pie de TFTP «If you applied the redirect rule, remove it:» sin nada: `mctl.transfer.closed` (catalog_mctl_a.go:173) solo se imprime con `Cleanup != ""`
   (transfer.go:171). En Windows el comando es una regla de firewall, no una redirección. Por confirmar con la prueba qué `Cleanup` llega; el cambio: texto por
   sistema (`closed_win`: «Si abriste la regla de firewall, quítala») y nada si `Cleanup` está vacío o es solo espacios tras `cleanLines`.
2. Regla de firewall para 127.0.0.1: `firewallRule` ya la omite en loopback (firewall.go:~48 `ruleOK`) pero `ServerHintIn` imprime igual la prosa
   `win_std_port` (hints.go:78-83). Cambio: con IP loopback en Windows, ni prosa ni regla. Prueba `TestHintLoopbackWindowsSinRegla`.
3. Puerto 22 ocupado por el sshd de Windows: el bind falla con el texto crudo del sistema (`service.ErrFrom(…Unavailable)`, transfer.go:~202). Cambio: si el error
   es dirección en uso, el puerto es 22 y es Windows, anexar `transfer.err.sshd_windows` («el puerto 22 lo usa el servicio OpenSSH Server; páralo o usa otro puerto»).
4. Archivo con espacios: `HintIn` y `ServerHintIn` imprimen `copy tftp://h/mi archivo flash:` (hints.go:38,50,58,71; fileserve.go:237-241). Cambio: `url.PathEscape` del
   nombre en las URLs del hint (el cliente lo decodifica). Prueba `TestHintNombreConEspaciosEscapa` (tftp, ftp, scp, sftp, http).
5. `get ftp://…/b%20c.txt`: `url.Parse` decodifica a «b c» y `remotePath` (transfer.go:153-166) admite solo `[A-Za-z0-9._-/:@+,=~]`, de ahí «character ' ' is not
   allowed». Cambio: aceptar espacio SOLO para ftp y sftp/http; scp lo rechaza con mensaje propio (la ruta llega a un shell remoto; ver el comentario de la función).
   Prueba `TestRemotePathEspacio` por esquema.
6. `ls http://` contra nuestro servidor: el servidor publica sin índice a propósito (http.go:~84 «sin listado ni pistas»), `httpList` recibe 404 (browse.go:312-314) y
   devuelve «HTTP 404». Cambio: ese 404 → `xfer.err.no_index` («este servidor HTTP no publica un índice»); el servidor no cambia.
7. «fingerprint 1 (ed25519, RSA)»: hints.go:63-65 / catalog_hints.go:21 imprime el número y la lista fija. Cambio: la llave dice su tipo (`SHA256:… (ed25519)`), con el tipo
   que ya tiene `Ready.Fingerprints` (a confirmar el tipo de dato; si es solo string, se calcula con `ssh.ParsePublicKey`).

Riesgos: el escape de URL cambia lo copiable (el equipo IOS no decodifica `%20` en `copy tftp:`: por confirmar en el 3560CX; si no, avisar «renombra el archivo» y dejarlo sin escapar).

## 43e-7 Ayuda de `diag` (BAJO)

Hoy: la ayuda dice «interval (0.2-60, solo Linux)» pero `tos` también falla en Windows (args_ping.go:147-153 `winOnly("interval"|"tos"|"df")`; df es aceptado en
Windows? por confirmar en la prueba). Una clave desconocida da «opción X no existe para esta herramienta» (catalog_diagerr.go:15) sin listar las válidas.
Cambio mínimo: marcar `tos` y `interval` (y `source` si aplica) como solo Linux en cmd/mctl/diag/diag.go:179-185 y help_en.txt:24; `opts.done()` (args.go:118-128)
agrega las claves válidas de la herramienta (un `map[Tool][]string` junto a `buildPlan`, probado contra las claves que `buildPlan` realmente lee).
Prueba roja: `TestOpcionDesconocidaListaValidas` (cada herramienta; texto en es y en); `TestAyudaDiagMarcaOpcionesSoloLinux` (la ayuda y `winOnly` coinciden: la prueba extrae
las claves marcadas del código y las busca en la ayuda). Riesgos: si el mapa de claves válidas se desincroniza, la prueba que cruza `buildPlan` lo detecta.

## 43e-8 Horas (BAJO)

Hoy, mezcla: local sin zona (`job watch` patrol.go:212 `15:04:05`, visibility.go:193, assistrun.go:52, syslog en transfer/status.go:131); UTC sin decirlo (devices.go:46,
scripts.go:68, transfer.go:341 «2006-01-02 15:04», timeline analyze/timeline.go:426 sin zona, backup list service/backup/backup.go:525 con «Z» pegada); RFC 3339 en UTC
(metrics.go:70, fleet.go:527). `ports status` imprime `ts(r.AtMs)` (metrics.go:221) con `AtMs == 0` cuando se lee de una carpeta → «1970-01-01».

Cambio mínimo: un solo ayudante en cmd/mctl/cli (`cli.Time(ms)`/`cli.TimeOf(t)`): hora LOCAL con la zona, `2006-01-02 15:04 MST` (a segundos donde hoy hay segundos), y `-`
para cero; se usa en TODO lo que mctl muestra con fecha. En el núcleo, el mismo formato (`service.FmtLocal`) para los textos de informe (timeline, backup list, find). JSON:
siempre RFC 3339 con zona (`Z` u offset), nunca epoch crudo ni «15:04» (las claves JSON no cambian de nombre). `ports status`: `AtMs == 0` no imprime fecha.

Prueba roja: `TestHoraLocalConZona` (zona fija `America/Mexico_City` con `time.Local` inyectado: cada pantalla muestra «CST»/«CDT»), `TestJSONRFC3339ConZona` (todas las fechas
JSON de mctl parsean con `time.Parse(time.RFC3339, …)` y traen zona), `TestPortsStatusSinFechaCero`. Riesgos: scripts que parseaban el texto UTC sin zona (el JSON es el contrato, no el texto);
`devices`/`scripts` pasan de UTC a local: se anota en el CHANGELOG. La auditoría guarda UTC y no cambia.

## 43e-9 Español filtrado y muestra de hosts (BAJO)

Cambios de lo que se escribe nuevo (ver la siguiente sección para lo ya guardado):
- FTP «550 el archivo ya existe»: respuestas del servidor FTP son texto del protocolo (ftp.go:254-457, `s.reply(550, "…")` y `errExists.Error()`); pasan al catálogo con el idioma del
  núcleo (`fileserve.reason.*` ya existe para el motivo mostrado; falta la respuesta enviada al cliente). Cambio: en inglés siempre en el cable (los equipos no leen es) y la razón localizada
  solo en la UI.
- pki OU «Laboratorio - no confiable» (pki.go:157): va dentro del certificado emitido; los ya emitidos no cambian. Nuevo: «Lab - untrusted» (inglés canónico).
- prefs `--format` «(texto, crudo or jsonl)» (catalog_mctl_flags.go:158 y los comentarios de syslogd/flows): el valor `crudo|texto` es el del archivo de prefs; en inglés acepta `text|raw` (y
  `texto|crudo` como alias) y la ayuda dice la forma del idioma.
- códigos de prefs en el mensaje («prefs.outputs.no_existe: …», catalog_outputs.go:12-24): quitar el prefijo del texto; el motivo viaja en `ErrorInfo.Reason`. El front lee
  `reason` primero (lib/outputsError.ts:12) y solo cae al prefijo si no hay ErrorInfo; no hay cliente que lo necesite: se retira también la rama de respaldo en una limpieza posterior.
- hosts template: los ejemplos «Oficina» y «Piso 2» (devices/hosts_fields.go:71,89) a «Office» y «Floor 2» (los valores van a la plantilla que se importa; las descripciones ya se localizan, exchange.go:275-276).
- Prueba roja: `TestSinEspanolConLangEn` (tabla que corre cada mensaje de esta lista con `--lang en` y falla con una palabra del diccionario de español: «archivo», «ya existe», «crudo», «no confiable», «Oficina»).

### Lo que ya está en disco o en uso, caso por caso

| Caso | Dónde vive | Qué se hace | Por qué |
|---|---|---|---|
| tls `Severity` «aviso», `Code` «tls-antiguo» | JSON del informe (`tlsinspect.Finding`, tlsinspect.go:44-47; códigos en :192-241) y front (samples.ts:45, tlsCerts.test.ts:10) | `Severity`: el JSON del informe sale `warning` (hoy solo el gRPC, `SeverityCode`, tools.go:171); lee los dos. `Code`: se queda en español (slug estable) | Es identificador, como una clave de auditoría; la UI y el front lo usan; los textos ya salen localizados. El informe no se guarda en disco: no hay datos viejos que leer |
| fuente `auditoria` del timeline | `analyze/timeline.go:325` y `vocab.ts:13` (el front ya traduce con `vocab`) | El valor del JSON se queda; el texto de mctl (`TextIn`, timeline.go:426) la traduce («audit»). Se añade `audit` a vocab como alias | Es un enumerado; cambiarlo rompe quien filtra por él |
| acción `hosts.crear` (y `.editar`, `.borrar`, `.importar`, `.exportar`) | cadena de hashes (inventory/hosts.go:122,142,189) | Clave estable intacta. Solo se muestra traducida: mapa `audit.ActionLabel` (en: «host created») en `mctl audit` y en la UI. Las filas NUEVAS siguen escribiendo la clave de hoy | Una acción nueva en inglés convivirá con filas viejas en español y rompe cualquier filtro/exportación por acción; se decidió no reescribir. Un cambio de clave sería otra fase con lectura de ambas |
| `flujos_*.log` | `visibility.go:289` + `cmd/mctl/visibility.go:301` (plantilla `flujos_{fecha}_{hora}`) | Default nuevo `flows_{date}_{time}`; las plantillas guardadas en prefs se respetan tal cual (`canon`, rotate.go:41, ya admite los dos). Los `flujos_*.log` viejos no se tocan ni se borran | Aviso: la retención se arma con la plantilla actual, así que los viejos quedan fuera de la cuenta de `max_files`; se avisa en CHANGELOG y se borran a mano |
| `outputs\respaldos`, `.trabajos`, `lote-*` | backup.go:35,92,134,138; assist/restore.go:33; devices.go:35,120 | Se quedan. Solo cambia el texto que los nombra | Es evidencia del usuario: la fase 46 jura no tocarla. Renombrar exige que cada lector (backup, restore, devices, jobs) lea ambos nombres y rompe respaldos ya registrados con rutas absolutas |
| `adhoc\lote-N` | adhoc.go:48 | Se queda; las vacías: ver fase 46 | Idem |

## Fase 46 (adhoc fallidos en `created` y `lote-*` vacías)

Revisado: los PR #247, #249, #252, #254 y #255 siguen abiertos (ninguno en main). #252 trae `removeJobs` y `service.ArmedOnly` (un job `created` ya no cuenta como «en uso» y se puede quitar por id); no cambia el estado de un job cuyo `ArmJob` falló.
Lo que cubren (por su diff): historial «past», raíces de evidencia, quitar por id (`created` se puede quitar a mano) y `all_finished` que SALTA `created`.
Lo que NO cubren: `StartAdhoc` deja el trabajo en `created` cuando `ArmJob` falla (adhoc/adhoc.go:~75) y `StartBackup` hace lo mismo (backup.go:~148 en adelante),
con la carpeta `lote-*` vacía que `os.Remove(dir)` solo borra si falla `CreateJob` (adhoc.go:~58, backup.go:~143). Queda como pendiente aparte, «46c2» de la fase 46 (no entra en 43e; «46f» es la UI de Front):
si `ArmJob` falla en un lote adhoc o de backup → cancelar el trabajo (`cancelled`, con motivo) y quitar la carpeta SOLO si está vacía (`os.Remove`, nunca `RemoveAll`),
más barrido al arrancar de `lote-*` vacías sin job asociado. Queda pendiente la decisión de Release (preguntas).

## Orden y bloques

Cada uno un PR chico con `./dev.sh test` y el job windows verde; prueba roja primero.
1. 43e-1 resolvers (alto) → 2. 43e-2 errores → 3. 43e-3 id del preview → 4. 43e-4 nmap → 5. 43e-5 pki → 6. 43e-6 transfer → 7. 43e-7 ayuda de diag → 8. 43e-8 horas → 9. 43e-9 español.
43e-3 y 43e-8 tocan proto/catálogos: no mezclar con 43e-9 (muchos catálogos); 43e-2 antes de 43e-5/6 para que sus errores usen `CoreError`.

## Review Focus

- Que cada prueba falle ANTES del arreglo y que el error esperado sea el de catálogo, no cualquiera.
- 43e-2: que `CoreError` nunca esconda un error de usuario (un status con `ErrorInfo.Reason` pasa tal cual, solo sin el prefijo) ni rompa los códigos de salida.
- Compatibilidad: nada de lo guardado (auditoría, prefs, carpetas, informes) cambia de forma; lo nuevo se escribe nuevo y lo viejo se lee con alias.
- Ningún texto en español en `--lang en` (prueba de 43e-9) ni «0700» ni «GetFileAttributesEx» ni «rpc error» en pantalla.
- 43e-6 punto 5: espacio solo donde no llega a un shell remoto.
- Pruebas con tiempos o carga: una suite a la vez, `-p 2`, `GOMAXPROCS=4`.

## Preguntas para Release

1. 43e-2: ¿qué comando exacto dio el error con «GetFileAttributesEx» y la ruta relativa? El código admite varios (`prefs outputs set`, ruta de `--out`, `ilegible` con `err` crudo); sin el comando no se fija la prueba.
2. 43e-6 punto 1: ¿el pie con «remove it:» vacío salió en Windows o en Linux, y con qué `--listen` (IP real o 127.0.0.1)? Por el código solo imprime con `Cleanup` no vacío.
3. 43e-6 punto 4: ¿un IOS real acepta `%20` en `copy tftp://…`? Si no, el aviso es «renombra el archivo» y no se escapa.
4. Fase 46: ¿se agrega «46c2» (cancelar el job y quitar el `lote-*` vacío al fallar `ArmJob`) a esa fase o a 43e? Este plan lo deja fuera de 43e.
