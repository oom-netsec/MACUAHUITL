# Fase 28a — Receptor syslog: control de inundación, rotación y formato

Pedido del dueño (vía la sesión de front). El receptor (`internal/diag/syslogd`, servicio `ToolsService.Syslog`) hoy no limita tasa ni rota archivos. La vista la hace la sesión de front. Esta rama entrega: núcleo → proto → mctl → puente → `api.ts`/`fake.ts`, más su sección en `docs/plans/contratos-front.md`.

## Reglas globales
- Sin dependencias nuevas: el token bucket y la rotación se escriben aquí (unas decenas de líneas cada uno).
- Valores 0 en el proto = default seguro. Fuera de rango = `InvalidArgument` con el mensaje en español.
- Todo queda auditado: la configuración efectiva al empezar (`tools.syslog`), cada archivo borrado por retención (`tools.syslog.retencion`) y el resumen al terminar con descartes (`tools.syslog.done`).
- TDD; lógica nueva con al menos una mutación a mano. `go test -race`.

## 1. Tope de tasa y cola acotada (`internal/diag/syslogd`)
- `Config` gana `Limits`: `PerSource` (msg/s, default 100, 1–10000), `PerSourceBurst` (default 2×), `Global` (default 1000, 1–100000), `GlobalBurst` (default 2×), `Queue` (default 4096, 64–65536).
- Token bucket propio (`bucket{rate, burst, tokens, last}`), con reloj inyectable para las pruebas. Por origen (IP sin puerto): mapa con tope de 1024 orígenes; pasado el tope, los nuevos comparten un cubo «otros».
- Lectura: el lector (UDP, y cada conexión TCP) revisa los cubos y hace un envío NO bloqueante a un canal de tamaño `Queue`. Si no cabe, o si no hay ficha, descarta y cuenta por motivo: `por_origen`, `global` o `cola_llena`. El lector nunca espera al escritor.
- Una gorutina consumidora hace lo que hoy hace `emit`: parsear, escribir y llamar a `OnMessage`.
- Descartes: `OnDrops func(Drops)` a lo más una vez por segundo y solo si cambiaron, más una llamada final al cerrar. `Drops{Total, PorOrigen, Global, ColaLlena uint64; Desde time.Time (primer descarte); Top []SourceDrops (máx. 10, mayor primero)}`.

## 2. Archivo: rotación, nombre, retención, formato (`rotate.go` en el mismo paquete)
- `Sink` con: `Dir`, `Template`, `RotateBytes` (0 = sin rotar por tamaño), `RotateEvery` (0 = sin rotar por tiempo), `MaxFiles`, `Format`.
- Defaults desde el servicio: rotar a 50 MB, sin rotación por tiempo y 20 archivos. Con eso el tope es de ~1 GB en disco.
- Rangos: MB 1–1024; tiempo de 1 min a 7 días (el proto lo pide en minutos); archivos 1–1000.
- Plantilla:
  - Tokens `{fecha}` (AAAAMMDD), `{hora}` (HHMMSS) y `{origen}` (la IP con `:` cambiado a `-`). El resto, solo `[A-Za-z0-9_.-]`; 1–64 caracteres; sin `/`, `\`, `..`, ni otros tokens. Debe llevar `{fecha}` o `{hora}`.
  - La extensión la pone el formato (`.log` o `.jsonl`). Si el nombre ya existe se agrega `_N`. Default `syslog_{fecha}_{hora}`.
  - Validación en una función pública `ValidateTemplate` que también usa el servicio.
- Con `{origen}` hay un archivo por origen. Se mantienen abiertos a lo más 64; el menos usado se cierra y se reabre en modo append.
- Retención: tras cada rotación se cuentan los archivos de `Dir` cuyo nombre encaja con la plantilla (la plantilla se convierte a regex). Se borran los más viejos por mtime hasta quedar en `MaxFiles`, y cada borrado se reporta por un callback que el servicio audita. Nunca se toca otro archivo.
- Formatos:
  - `texto` (default; lo de hoy: `RFC3339 origen raw`);
  - `crudo` (solo `Raw`, una línea);
  - `jsonl` (el `Message` en JSON).
- Archivos 0600 y carpeta 0700.

## 3. Proto, servicio, mctl, puente
- `SyslogRequest` agrega (sin renumerar):
  - `rate_per_source`, `burst_per_source`, `rate_global`, `burst_global`, `queue_size`;
  - `rotate_mb`, `rotate_minutes`, `name_template`, `max_files`, `format`.
- `SyslogResponse` agrega `SyslogDrops drops = 4` (total, por_origen, global, cola_llena, `since_ms` y `repeated SyslogSourceDrops top`) y `string rotated_path = 5`, que se envía cuando se abre un archivo nuevo.
- `buf lint && buf generate`.
- `mctl tools syslog`: banderas para todo lo anterior. Actualiza su `help.golden`.
- Puente y TS: amplía la función del puente de syslog que ya existe y su tipo en `api.ts`/`fake.ts`.
- Contrato: sección nueva al final de `docs/plans/contratos-front.md` con los campos, defaults, rangos y un ejemplo del evento de descartes.

## Pruebas mínimas
- El cubo: la ráfaga pasa y luego limita a la tasa (reloj falso).
- Un origen que inunda no le quita lugar a otro origen bajo su tasa.
- Cola llena: el lector no se bloquea (el consumidor está detenido y la lectura sigue), y los descartes se cuentan.
- Los descartes se reportan con `Desde` y `Top`.
- Rotación por tamaño y por tiempo (reloj falso). La retención borra solo lo que encaja con la plantilla y deja un archivo ajeno en la carpeta.
- `ValidateTemplate` rechaza `../x`, `a/b`, `{fecha`, `{otro}`, una plantilla sin `{fecha}` ni `{hora}`, y una vacía.
- Los tres formatos.
- `{origen}`: un archivo por origen y el tope de 64 abiertos.
- Servicio: los rangos inválidos dan `InvalidArgument` y la auditoría registra la config y los borrados.
