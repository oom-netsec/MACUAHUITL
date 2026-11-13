# Contratos para la sesión de front (fase 19)

Datos que necesitan las gráficas, el explorador de Transferencias, los selectores de equipos y la vista de frente del switch. Todo el backend está hecho; la vista es de la otra sesión. Cada sección trae: el RPC y su CLI, la función del puente, los tipos TS (están en el `api.ts` del módulo; aquí se copian los relevantes), el doble de pruebas (`fake.ts`) y un ejemplo.

Reglas comunes:

- Todas las llamadas salen de `core` (`CoreAPI`): `core.jobMetrics(...)`, `core.portStatus(...)`, `core.transferBrowse(...)`, `core.listDevices(...)`. Los tipos ya están reexportados desde `lib/core.ts`.
- Las listas llegan siempre como arreglos (nunca `null`). Los tiempos son milisegundos Unix (`atMs`, `modifiedMs`, `lastSeenMs`), `0` = no se sabe.
- Los textos que vienen de un equipo o de un servidor (nombres de archivo, descripciones) no son de fiar: React los escapa; no uses `dangerouslySetInnerHTML` ni los pongas en un SVG sin escapar. Los nombres de archivo remotos ya vienen saneados (sin caracteres de control ni invisibles).
- Cada `warnings` es texto listo para mostrar (en español). Lo que no se recolectó viene con aviso y la serie vacía; no es un error.
- Las pruebas usan `fakeCore()` (`lib/fake.ts`), que ya incluye los dobles de estos módulos: `fakeMetrics`, `fakeInventory`, `fakeTransfer` (ampliado).

Playbook para tener datos: `ios-xe/metricas` (show clock, show version, show processes cpu sorted, show memory statistics, show interfaces). Para la vista de frente, un trabajo con `show interfaces status`, `show interfaces trunk` y `show etherchannel summary` (por ejemplo `ios-xe/tac-baseline` o el playbook propio); o la consulta en vivo.

---

## 1. Series de métricas de un trabajo (gráficas)

- RPC: `MetricsService.GetJobMetrics`. CLI: `mctl job metrics TRABAJO|CARPETA [--device EQ] [--iface I]... [--top N] [--max-points N] [--csv|--json]`.
- Puente: `Bridge.JobMetrics(MetricsQueryDTO)` (ui/bridge/metrics.go). TS: `core.jobMetrics(q)` en `modules/metrics/api.ts`.
- `job` es el ID de un trabajo de esta sesión del núcleo o la carpeta de salida absoluta de uno.

```ts
interface MetricsQuery {
  job: string; device?: string;          // device: dirección o nombre; vacío = todos
  maxPoints?: number;                    // por serie, las rondas más recientes (0 = 500, máx. 5000)
  maxInterfaces?: number;                // las de mayor utilización pico (0 = 12, máx. 64)
  interfaces?: string[];                 // concretas (Gi1/0/1 o GigabitEthernet1/0/1); anula maxInterfaces
}
interface CpuPoint { round: number; atMs: number; fiveSec: number; oneMin: number; fiveMin: number }      // %
interface MemoryPoint { round: number; atMs: number; used: number; free: number; total: number }           // bytes
interface MemorySeries { pool: string; points: MemoryPoint[] }                  // «Processor», «I/O», «lsmpi_io»…
interface InterfacePoint {
  round: number; atMs: number; inBps: number; outBps: number;
  source: "counters" | "5min" | "";      // de dónde sale la tasa (ver abajo)
  inUtilPct: number; outUtilPct: number; // 0 si bwKbit es 0
  deltaOk: boolean;                      // las diferencias de abajo valen
  inErrors: number; outErrors: number; crc: number; resets: number; inDrops: number; outDrops: number;
  reboot: boolean;                       // el equipo se reinició desde la ronda anterior
}
interface InterfaceSeries { name: string; description: string; bwKbit: number; peakUtilPct: number; points: InterfacePoint[] }
interface RebootEvent { round: number; bootMs: number }
interface DeviceMetrics {
  address: string; hostname: string; rounds: number;
  cpu: CpuPoint[]; memory: MemorySeries[]; interfaces: InterfaceSeries[];
  interfaceTotal: number;                // interfaces con datos antes del tope (para «mostrando 12 de 48»)
  reboots: RebootEvent[]; truncated: boolean; warnings: string[];
}
interface JobMetrics { devices: DeviceMetrics[]; warnings: string[] }
```

Cómo leer los datos:

- Una serie por equipo y ronda; `atMs` es la hora de la salida del comando (la de las interfaces es la de `show interfaces`, unos segundos después de la del CPU).
- **Tasa (`inBps`/`outBps`)**: `source: "counters"` es la diferencia de contadores de octetos entre dos rondas dividida entre el tiempo (lo más exacto). `"5min"` es el promedio de 5 minutos que imprime el equipo y se usa en la **primera ronda** (no hay con qué restar), tras un **reinicio** del equipo y cuando el contador bajó, pudo dar más de una vuelta o el equipo limpió los contadores (`clear counters`) desde la ronda anterior (esa ronda trae `deltaOk: false`). Marca esos puntos distinto en la gráfica (por ejemplo línea punteada) y no los mezcles en una sola línea sin avisar.
- **Diferencias** (`inErrors`, `outErrors`, `crc`, `resets`, `inDrops`, `outDrops`): contra la ronda anterior y solo si `deltaOk`. Con `deltaOk: false` los valores son 0 y **no son datos**: no dibujes barras en cero.
- `reboot: true` y `reboots[]` sirven para marcar una línea vertical «reinicio». La hora de arranque sale del uptime de `show version`; sin ese comando el reinicio solo se ve cuando un contador baja.
- Tope: `truncated: true` = se recortó por `maxPoints` (se quedan las rondas más recientes). Las interfaces vienen ordenadas por utilización pico; si `interfaceTotal > interfaces.length`, ofrece pedir interfaces concretas con `interfaces: [...]`.
- Un trabajo que no recolectó un comando: la serie viene vacía y `warnings` dice cuál falta («falta el comando show interfaces: el playbook no lo recolectó»). Muéstralo en lugar de un gráfico vacío.
- No lee trabajos comprimidos: con `ZIP_POLICY_AT_END` o `PER_ROUND` Patrol borra los `.txt` sueltos. Si el trabajo no tiene `.txt`, la respuesta trae `devices: []` y un aviso.

Ejemplo (recortado; el completo está en `modules/metrics/fake.ts`, `sampleMetrics`):

```json
{
  "devices": [{
    "address": "10.0.0.1", "hostname": "SW1", "rounds": 3, "interfaceTotal": 2, "truncated": false, "warnings": [],
    "cpu": [{ "round": 1, "atMs": 1793959200000, "fiveSec": 5, "oneMin": 4, "fiveMin": 3 }],
    "memory": [{ "pool": "Processor", "points": [{ "round": 1, "atMs": 1793959200000, "used": 269484032, "free": 804257792, "total": 1073741824 }] }],
    "interfaces": [{
      "name": "Gi1/0/1", "description": "to-DIST1", "bwKbit": 1000000, "peakUtilPct": 62.5,
      "points": [
        { "round": 1, "atMs": 1793959205000, "inBps": 2000, "outBps": 5000, "source": "5min", "inUtilPct": 0.0002, "outUtilPct": 0.0005, "deltaOk": false, "inErrors": 0, "outErrors": 0, "crc": 0, "resets": 0, "inDrops": 0, "outDrops": 0, "reboot": false },
        { "round": 2, "atMs": 1793959505000, "inBps": 1000000, "outBps": 625000000, "source": "counters", "inUtilPct": 0.1, "outUtilPct": 62.5, "deltaOk": true, "inErrors": 4, "outErrors": 0, "crc": 4, "resets": 0, "inDrops": 0, "outDrops": 12, "reboot": false }
      ]
    }],
    "reboots": [{ "round": 3, "bootMs": 1793959740000 }]
  }],
  "warnings": []
}
```

---

## 2. Estado de puertos (vista de frente del switch)

- RPC: `MetricsService.GetPortStatus`. CLI: `mctl ports status TRABAJO|CARPETA [--device EQ] [--json]` y `mctl ports status --device HOST[:PUERTO] --cred ID [--accept-host-key SHA256:...] [--legacy-ssh] [--json]`.
- Puente: `Bridge.PortStatus(PortStatusQueryDTO)`. TS: `core.portStatus(q)` en `modules/metrics/api.ts`.
- Con `job` lee la evidencia (la ronda más reciente de cada comando); **sin `job`** consulta en vivo a `device` por SSH: solo lectura (los tres comandos pasan por `CheckDenied`), con el EgressGuard y llave de host estricta. Una llave nueva falla con `FailedPrecondition` y la huella en el mensaje (`SHA256:...`); se acepta reintentando con `acceptedHostKeys: [huella]`, igual que en Transferencias.

```ts
interface PortStatusQuery {
  job?: string;                  // ID o carpeta absoluta; sin él, en vivo
  device?: string;               // con trabajo: el equipo si hay varios; en vivo: switch (dirección o nombre)
  port?: number; credentialId?: string; acceptedHostKeys?: string[]; legacySsh?: boolean;   // en vivo
}
interface PortInfo {
  name: string; kind: string;                 // «Gi1/0/12», «Gi» (Gi, Fa, Te, Twe, Fo, Hu, Eth)
  module: number; stack: number; number: number;   // Gi1/0/12 → 1, 0, 12 (ver nota)
  description: string;
  status: string;                             // connected | notconnect | disabled | err-disabled (también inactive, suspended…)
  vlan: string;                               // «10», «trunk», «routed»
  duplex: string; speed: string;              // como los imprime el equipo: «a-full», «a-1000», «auto», «10G»
  duplexMode: string; speedMbps: number; autoNegotiated: boolean;   // «full»|«half»|«auto»|«»; 0 = auto o no se sabe
  type: string;                               // «10/100/1000BaseTX», «1000BaseSX SFP»; vacío si el equipo no lo da
  trunk: boolean; trunkNative: string;
  channel: string; channelFlags: string;      // «Po1» y «P» si es miembro de un port-channel
}
interface PortChannel { name: string; state: string; protocol: string; members: { port: string; flags: string }[] }
interface PortStatus {
  source: "job" | "live"; address: string; hostname: string; atMs: number;
  ports: PortInfo[]; channels: PortChannel[]; warnings: string[];
}
```

Notas para dibujar:

- `module`/`stack`/`number` son los números del nombre en orden: en `Gi1/0/12`, `module` es el primero (1), `stack` el segundo (0) y `number` el último (12). En un switch apilable de 3 números el primero es el **miembro del stack** y el segundo la **ranura**; con nombres de dos números (`Fa0/24`, `Eth1/5`) `stack` vale 0. Agrupa la cuadrícula por `module` (una caja por miembro del stack) y ordena por `stack`, `number`. Los puertos de uplink suelen tener `stack` 1 (`Gi1/1/1`).
- Solo vienen puertos **físicos** y en el orden del equipo. Los port-channel (`Po1`) no son puertos: salen en `channels`, y cada miembro trae `channel` y `channelFlags`.
- `trunk` sale de la columna VLAN (`trunk`) y de `show interfaces trunk` (`trunking`); `trunkNative` solo si ese comando se recolectó.
- Si falta `show interfaces status` la respuesta trae `ports: []` y un aviso (no es un error). Si faltan `trunk` o `etherchannel` los puertos vienen igual y el aviso dice qué se deduce y qué no.
- Con varios equipos en el trabajo y sin `device`, la llamada falla con `FailedPrecondition` y el mensaje lista los equipos («el trabajo tiene 2 equipos (SW1 (10.0.0.1), SW2 (10.0.0.2)): indica uno»): muestra un selector (usa `listDevices`).

Ejemplo (recortado; el completo es `samplePorts` en `modules/metrics/fake.ts`):

```json
{
  "source": "job", "address": "10.0.0.1", "hostname": "SW1", "atMs": 1793959200000, "warnings": [],
  "ports": [
    { "name": "Gi1/0/1", "kind": "Gi", "module": 1, "stack": 0, "number": 1, "description": "to-DIST1", "status": "connected", "vlan": "trunk",
      "duplex": "a-full", "speed": "a-1000", "duplexMode": "full", "speedMbps": 1000, "autoNegotiated": true, "type": "10/100/1000BaseTX",
      "trunk": true, "trunkNative": "1", "channel": "Po1", "channelFlags": "P" },
    { "name": "Gi1/0/6", "kind": "Gi", "module": 1, "stack": 0, "number": 6, "description": "loop detectado", "status": "err-disabled", "vlan": "20",
      "duplex": "auto", "speed": "auto", "duplexMode": "auto", "speedMbps": 0, "autoNegotiated": true, "type": "10/100/1000BaseTX",
      "trunk": false, "trunkNative": "", "channel": "", "channelFlags": "" }
  ],
  "channels": [{ "name": "Po1", "state": "SU", "protocol": "LACP", "members": [{ "port": "Gi1/0/1", "flags": "P" }, { "port": "Gi1/0/2", "flags": "P" }] }]
}
```

---

## 3. Explorador remoto de Transferencias

- RPC: `TransferService.Browse`. CLI: `mctl transfer ls URL [--cred ID] [--path CARPETA] [--max N] [--insecure] [--legacy-ssh] [--accept-host-key SHA256:...] [--json]`.
- Puente: `Bridge.TransferBrowse(TransferBrowseDTO)`. TS: `core.transferBrowse(p)` en `modules/transfer/api.ts`.
- FTP: `MLSD` y, si el servidor no lo entiende, `LIST` (formato Unix y DOS). SFTP: `ReadDir`. SCP: por el subsistema SFTP si el servidor lo tiene. HTTP(S): índice HTML simple. **TFTP y un SCP sin SFTP no listan.**
- Mismas reglas que Get/Put: EgressGuard con `Revoke`, credencial de la bóveda, llave de host estricta (huella en el error, `acceptedHostKeys` para aceptarla), TLS verificado (`insecure` explícito, solo https y auditado), topes de entradas (2000, máx. 20000), de bytes del listado (4 MiB) y de tiempo (30 s, máx. 5 min).

```ts
interface TransferBrowseParams {
  url: string; credentialId?: string; path?: string;       // path vacío = el de la URL
  acceptedHostKeys?: string[]; insecure?: boolean; legacySsh?: boolean; maxEntries?: number; seconds?: number;
}
interface RemoteEntry {
  name: string;                                // ya saneado
  type: "file" | "dir" | "link" | "other";
  size: number;                                // bytes; -1 si el servidor no lo dice (carpetas, HTML sin tamaño)
  modifiedMs: number; perms: string;           // perms: «rw-r--r--», «0644» o los de MLSD; vacío si no hay
  downloadable: boolean;                       // archivo cuyo nombre Get puede pedir
  unsafeName: boolean;                         // el nombre original traía control/invisibles: muéstralo con aviso
}
interface TransferListing {
  listable: boolean; reason: string;           // listable=false NO es un error: reason es el mensaje para mostrar
  path: string; entries: RemoteEntry[];        // carpetas primero, luego por nombre (sin importar mayúsculas)
  truncated: boolean; method: "mlsd" | "list" | "sftp" | "http" | "";
}
```

Notas:

- `listable: false` con `reason` «este servidor no permite listar: …» es el caso TFTP / SCP puro: muestra el mensaje y deja que el usuario escriba el nombre del archivo a mano.
- `downloadable: false` en archivos con **espacios** u otros caracteres fuera de `[A-Za-z0-9._-:@+,=~]` en el nombre: el cliente de descarga no los acepta (la ruta remota va como texto de un protocolo o a un shell en scp). Deshabilita la casilla/botón y explica por qué en el tooltip.
- Para entrar a una carpeta, vuelve a llamar con `path` = ruta de la carpeta + `/` + `name`. Los nombres con `/` o `\` nunca llegan en un listado.
- Un error de verdad (conexión, credencial, llave de host nueva) llega como excepción de la promesa, con el mismo mensaje que `transferGet` (la huella `SHA256:` va en el texto).

Ejemplo:

```json
{ "listable": true, "reason": "", "path": "/imagenes", "truncated": false, "method": "mlsd",
  "entries": [
    { "name": "respaldos", "type": "dir", "size": -1, "modifiedMs": 1793872800000, "perms": "0755", "downloadable": false, "unsafeName": false },
    { "name": "c9300-universalk9.17.09.04a.SPA.bin", "type": "file", "size": 1288490188, "modifiedMs": 1793959200000, "perms": "rw-r--r--", "downloadable": true, "unsafeName": false },
    { "name": "sala de juntas.cfg", "type": "file", "size": 512, "modifiedMs": 0, "perms": "", "downloadable": false, "unsafeName": false },
    { "name": "evil?gnp.exe", "type": "file", "size": 7, "modifiedMs": 0, "perms": "", "downloadable": false, "unsafeName": true }
  ] }
```

TFTP: `{ "listable": false, "reason": "este servidor no permite listar: TFTP no tiene comando para listar carpetas", "path": "", "entries": [], "truncated": false, "method": "" }` (`noListing` en el `fake.ts`).

---

## 4. Avance de Get y Put, descarga múltiple y cancelar

- RPC: `TransferService.GetStream`, `PutStream`, `GetMany` (streams de eventos). `Get` y `Put` de siempre siguen igual (sin avance). CLI: no hay (la CLI usa `get`/`put`).
- Puente: `TransferGetAsync(TransferGetDTO)`, `TransferPutAsync(TransferPutDTO)`, `TransferGetMany(TransferGetManyDTO)` devuelven un `runId` y el resto llega por eventos; `TransferCancel(runId)` cancela. TS: `core.transferGetAsync(p)`, `transferPutAsync(p)`, `transferGetMany(p)`, `transferCancel(runId)` y `core.onTransferRun(cb)` en `modules/transfer/api.ts`.
- Los eventos de avance salen **a lo más 10 veces por segundo** (más uno final al terminar); la limitación está en el cliente de transferencia, no hace falta limitarla en la vista.

```ts
interface TransferGetManyParams {
  url: string;                    // la CARPETA remota (ftp://host/dir/, sftp://…, http://…/dir/)
  names: string[];                // nombres base, hasta 200 (sin «/»)
  destDir: string; credentialId?: string; acceptedHostKeys?: string[]; insecure?: boolean; legacySsh?: boolean;
  maxBytes?: number; seconds?: number;   // por archivo
}
interface TransferProgress { runId: string; index: number; count: number; name: string; bytes: number; total: number; bytesPerSec: number }  // total 0 = no se conoce
interface TransferFileDone { runId: string; index: number; name: string; ok: boolean; error?: string; result?: TransferResult }
interface TransferFinished { runId: string; ok?: number; failed?: number; canceled?: boolean; error?: string }   // ok y failed solo en el lote
type TransferRunEvent = ({ kind: "progress" } & TransferProgress) | ({ kind: "file" } & TransferFileDone) | ({ kind: "finished" } & TransferFinished);
```

Flujo:

1. `const runId = await core.transferGetMany({...})`; suscríbete con `core.onTransferRun(cb)` **antes** de llamar y filtra por `runId`.
2. `progress` (por archivo: `index` de `count`, `bytes` de `total`, `bytesPerSec`), luego `file` (ese archivo terminó: `ok`, o `error` con el motivo; `result` trae ruta, bytes, MD5 y SHA-256), y al final **un** `finished`. En una descarga múltiple el límite de 10 avisos por segundo es de todo el lote: un archivo pequeño puede no traer ningún `progress`; el fin de cada archivo es siempre su evento `file`.
3. En `transferGetAsync`/`transferPutAsync` `count` es 1 y `index` 0; si falla, `finished` trae `error` (con la huella `SHA256:` si es una llave nueva, igual que `transferGet`) y no hay `file`.
4. Un archivo que falla no detiene el lote; el resumen es `finished.ok` / `finished.failed`. `transferCancel(runId)` detiene la descarga en curso y el resto del lote: `finished.canceled: true` (lo ya descargado se queda; lo incompleto se borra).
5. Cada archivo del lote es una descarga completa (su propia autorización del guard y, en SCP/SFTP, su propia sesión), y queda en la bitácora; los nombres que ya existen en `destDir` fallan (no se sobrescribe).

Ejemplo de eventos de un lote de dos archivos:

```json
{ "kind": "progress", "runId": "run-7", "index": 0, "count": 2, "name": "a.cfg", "bytes": 4096, "total": 12288, "bytesPerSec": 81920 }
{ "kind": "file", "runId": "run-7", "index": 0, "name": "a.cfg", "ok": true, "result": { "path": "/home/u/recibidos/a.cfg", "bytes": 12288, "md5": "…", "sha256": "…", "verified": "", "seconds": 0.2, "report": "guardado …" } }
{ "kind": "file", "runId": "run-7", "index": 1, "name": "b.cfg", "ok": false, "error": "FTP respondió 550 …" }
{ "kind": "finished", "runId": "run-7", "ok": 1, "failed": 1 }
```

---

## 5. Equipos conocidos (selectores y lista de IP permitidas)

- RPC: `InventoryService.ListDevices` (`PutDevice` y `DeleteDevice` son la libreta de hosts, ver «Libreta de hosts (fase 29b)» al final). CLI: `mctl devices [TEXTO] [--json]`.
- Puente: `Bridge.ListDevices(query)`. TS: `core.listDevices(query?)` en `modules/inventory/api.ts`.
- Junta, sin duplicados por dirección: los **objetivos de los trabajos de Patrol** (`manifest.json`, también los que fallaron), la **evidencia de la flota** (carpetas `<equipo>_<IP>` y zips de `outputs/`) y los **respaldos** (`outputs/respaldos/<equipo>/`). Un respaldo no trae dirección: se une al equipo que tenga ese nombre y, si no hay, queda como equipo **sin dirección**.

```ts
type DeviceSource = "patrol" | "flota" | "respaldos";
interface KnownDevice {
  address: string;              // vacío si solo se conoce por sus respaldos: no sirve para una lista de IP
  hostname: string; platform: string;     // platform: la que detectó Patrol; vacío si no se sabe
  lastSeenMs: number;           // evidencia más reciente; 0 = nunca se alcanzó (solo apareció como objetivo que falló)
  sources: DeviceSource[];      // en este orden fijo: patrol, flota, respaldos
}
interface KnownDevices { devices: KnownDevice[]; warnings: string[] }
```

Notas:

- Orden: IPv4 por valor numérico, IPv6, otros nombres de destino y, al final, los que no tienen dirección. `query` filtra por dirección, nombre o plataforma (sin importar mayúsculas).
- `address` puede ser un nombre de host (el objetivo de un trabajo se pudo dar como nombre): para una lista de IP, filtra con una validación de IP en la vista.
- «Visto» es la hora de la evidencia más reciente, no un ping. Los zips solo aportan la hora del archivo.
- Si `outputs/` aún no existe la llamada falla con un mensaje claro (no devuelve una lista vacía que parezca «no hay equipos»).

Ejemplo:

```json
{ "devices": [
    { "address": "10.0.0.1", "hostname": "SW-CORE", "platform": "ios-xe", "lastSeenMs": 1793959200000, "sources": ["patrol", "flota", "respaldos"] },
    { "address": "10.0.0.9", "hostname": "CAIDO", "platform": "ios-xe", "lastSeenMs": 0, "sources": ["patrol"] },
    { "address": "", "hostname": "SOLO-RESP", "platform": "", "lastSeenMs": 1793527200000, "sources": ["respaldos"] }
  ], "warnings": [] }
```

---

## 6. Catálogo de snippets por tecnología (formularios sin código por snippet)

Fase 28b (infraestructura y lote L2 por puerto). Núcleo y puente hechos; la vista arma el formulario de cada plantilla desde su descripción. Todo cambia la red solo por el modo asistido (ADR 0007): planear solo lee, el plan trae la reversa y la ejecución pide confirmación por paso con el flujo de siempre (`assistStart`, `assistWatch`, `assistConfirm`).

Llamadas (módulo Snippets, `modules/snippets/api.ts`; puente `AssistListSnippetTemplates` y `AssistPlanSnippet`):

- `core.listSnippetTemplates(platform?)` devuelve `SnippetTemplate[]` en orden de catálogo: por tecnología (`l2`, `l3`, `gestion`, `seguridad`, `qos`, `etherchannel`) y, dentro de cada una, el orden en que el núcleo las declara. `platform` (`ios` o `ios-xe`) filtra; vacío = todas. Agrupa por `tech`.
- `core.planTemplateSnippet({ target, id, values, writeMemory?, acceptedHostKeyFingerprints? })` planea y devuelve lo mismo que `assistPlanSnippet` (`PortsPlanResult`). `values` es `Record<string,string>` con todo el formulario por nombre de campo: un valor vacío cuenta como ausente. Las plantillas que ya existían (`vlan`, `trunk`, `svi`) también están en el catálogo con su formulario; sus llamadas de antes siguen valiendo.

```ts
interface SnippetTemplate { id: string; tech: string; name: string; platforms: string[]; fields: SnippetField[] }
interface SnippetField {
  name: string; label: string; type: SnippetFieldType;
  required?: boolean; min?: number; max?: number; pattern?: string;
  choices?: string[]; defaultValue?: string; help?: string;   // protojson omite los ceros y los vacíos
}
```

Cómo mapear cada `type` a un control (los valores siempre viajan como texto):

| type | Control | Valor |
|---|---|---|
| `text` | campo de texto; `max` = largo máximo (200 si falta), `pattern` = expresión regular que el valor debe cumplir | tal cual |
| `int` | numérico entero; `min`/`max` = rango (`max` 0 = sin tope) | `"30"`, sin signo ni ceros a la izquierda |
| `decimal` | numérico con hasta dos decimales; `min`/`max` = rango | `"20"`, `"5.5"`, `"100.00"` |
| `bool` | casilla | `"true"` o `"false"` |
| `choice` | selector con `choices`; sin opción vacía si es `required` | una de `choices` |
| `ipv4` | texto con máscara de entrada de IPv4 | `"10.9.9.1"` |
| `ipv4_mask` | texto con máscara decimal (no prefijo) | `"255.255.255.0"` |
| `interface` | un puerto (físico o Port-channel; el plan puede ser más estricto) | `"Gi1/0/48"` |
| `interfaces` | selector múltiple de puertos (la vista de frente, `ports status`) o texto | lista separada por comas o espacios, con rangos del último número: `"Gi1/0/1-4, Gi1/0/9"`; hasta 48 puertos, sin repetidos |
| `vlan_id` | numérico de 1 a 4094 (`min` y `max` ya vienen en 1-4094, o más estrechos) | `"30"` |
| `secret` | campo de contraseña (sin eco, `autocomplete="off"`); nunca se guarda ni se registra en la UI | texto sin espacios ni `?` |

Reglas del formulario:

- La validación de la UI es solo ayuda (deshabilitar el botón, marcar el campo). La autoritativa es la del núcleo (`ValidateValues`): rechaza campos desconocidos, obligatorios que faltan, tipo, rango y todo lo que no sea ASCII imprimible, y responde `InvalidArgument` con todos los problemas juntos. Los `secret` jamás aparecen en un error ni en el plan.
- Una negativa por el estado del equipo (`FailedPrecondition`: puerto miembro de canal, port-security que ya existe, un valor que la reversa no sabría restaurar...) trae el motivo en español: muéstralo tal cual.
- El plan trae `notes` por equipo (avisos como que el enlace rebota o que la reversa no saca un puerto de err-disabled): muéstralos junto al plan, sin pedir confirmación aparte. Son texto informativo.
- `required` aplica al campo solo. Hay reglas entre campos que solo el núcleo conoce (por ejemplo «al menos un umbral»): confía en su mensaje.
- Un plan cubre todos los puertos de `interfaces` en un solo equipo; la reversa los deshace en orden inverso.

Textos: usa las claves i18n `snippet.<id>.name` y `snippet.<id>.field.<name>` (y `snippet.<id>.field.<name>.help`) y, si no existen, el `name`, `label` y `help` en español que manda el núcleo como respaldo. Los nombres técnicos de comandos (`speed`, `storm-control`...) no se traducen.

Plantillas de esta fase (lote L2; ids y campos):

| id | Campos |
|---|---|
| `vlan` | `id` vlan_id*, `name` text, `remove` bool, `accept_vtp` bool, `accept_trunk` bool |
| `trunk` | `interface` interface*, `op` choice add\|remove*, `vlan` vlan_id* |
| `descripcion` | `interfaces` interfaces*, `description` text, `remove` bool (una de las dos). Solo toca la descripción: no cambia el modo del puerto (antes mandaba `switchport mode access` a un puerto dynamic) |
| `speed-duplex` | `interfaces`*, `speed` choice auto\|10\|100\|1000, `duplex` choice auto\|full\|half (al menos uno) |
| `storm-control` | `interfaces`*, `broadcast`/`multicast`/`unicast` decimal 0-100, `action` choice shutdown\|trap (al menos uno; son banderas independientes: el puerto puede tener las dos) |
| `portfast-bpduguard` | `interfaces`*, `portfast` bool, `bpduguard` bool (al menos uno) |
| `port-security` | `interfaces`*, `maximum` int 1-3072, `violation` choice protect\|restrict\|shutdown, `aging_time` int 0-1440 |
| `errdisable-recovery` | `cause_bpduguard`, `cause_psecure_violation`, `cause_storm_control`, `cause_link_flap`, `cause_udld`, `cause_loopback` bool; `interval` int 30-86400, sin valor sugerido: no lo prellenes, pisaría el que ya tenga el equipo (al menos uno) |
| `modo-puerto` | `interfaces`*, `mode` choice access\|dynamic auto\|dynamic desirable\|fabrica* (`fabrica` = `no switchport mode`, el valor de fábrica; nunca trunk). Rechaza trunk, canal, ruteado/L3, private-vlan/túnel y un dynamic que opera como trunk; un puerto que ya está en ese modo se salta con una nota «ya estaba». Avisa en `notes` que pasar a dynamic permite negociar un trunk (DTP) |
| `svi` (tecnología `l3`) | `vlan` vlan_id*, `description` text, `address` ipv4*, `mask` ipv4_mask* |

(* = obligatorio.) El lote siguiente (28e: QoS y EtherChannel) solo agrega plantillas al catálogo: la vista no cambia.

Lote L3, gestión y seguridad (fase 28d; mismas reglas de formulario, ninguna plantilla pide una vista nueva):

| id (tecnología) | Campos |
|---|---|
| `ruta-estatica` (`l3`) | `network` ipv4*, `mask` ipv4_mask*, `next_hop` ipv4, `exit_interface` text (al menos uno de los dos), `distance` int 1-255 (vacío o 1 = la de fábrica), `name` text. La ruta por defecto 0.0.0.0/0 no se admite |
| `loopback` (`l3`) | `number` int 0-2147483647*, `address` ipv4*, `mask` ipv4_mask* (sugerida 255.255.255.255), `description` text |
| `helper-address` (`l3`) | `interface` text* (SVI, puerto ruteado, Port-channel o subinterfaz), `address` ipv4* |
| `ntp-server` (`gestion`) | `address` ipv4*, `prefer` bool |
| `logging-host` (`gestion`) | `address` ipv4*, `transport` choice udp\|tcp, `port` int 1-65535, `level` choice emergencies\|alerts\|critical\|errors\|warnings\|notifications\|informational\|debugging (vacío no toca el trap). Sin `transport` ni `port`: `logging host IP` (udp 514). Con alguno: `logging host IP transport T port N` (solo port: udp; solo transport: 514 en udp y 601 en tcp; udp 514 se manda como `logging host IP`) y su reversa es el `no` completo. La misma IP con otro transporte, puerto u opciones se rechaza (un solo destino por IP); la misma, «ya estaba» (IOS puede omitir `port 514` o el sufijo entero en el running: se compara el transporte y puerto efectivos; sin validar en laboratorio). El puerto del receptor de la app (5514 por defecto) va aquí |
| `snmp-community` (`gestion`) | `community` **secret*** (4-32, sin espacios ni @), `acl` text. Solo lectura (RO): RW nunca |
| `snmpv3-usuario` (`gestion`) | `user` text*, `group` text*, `auth` choice sha, `auth_password` **secret*** (8-64), `priv` choice aes 128, `priv_password` **secret*** (8-64) |
| `banner-motd` (`gestion`) | `text` text* (una línea de ASCII, 1-200, sin `#` ni `^`) |
| `vty-acl` (`seguridad`) | `acl` text* (ACL estándar que ya exista), `lines` choice 0 4\|0 15* |

Notas de este lote para la vista:

- Los campos `secret` (la community y las contraseñas SNMPv3) usan un `<input type="password">` y nunca se muestran de vuelta: ni en el resumen, ni en el plan (las líneas de `apply` y `rollback` llegan con la community y las contraseñas ya ocultas), ni en errores o en la auditoría. No los guardes en el estado de la vista tras enviar.
- `snmpv3-usuario`: IOS no escribe los usuarios SNMPv3 en el running-config. El post-check y la verificación de la reversa se hacen con `show snmp user` (viene en `pre` y `post` del plan). Un equipo con el agente SNMP apagado se rechaza («no se pudo leer show snmp user»).
- `vty-acl`: el núcleo comprueba que la ACL permita la IP de origen que el equipo ve (de `show users`) y también la IP local de la app si difiere (NAT o VPN), y rechaza («te dejaría fuera») si no la permite, si no la menciona (deny implícito) o si no puede saber la que ve el equipo. El `note` del plan dice qué IP validó. Si la ACL cambia entre planear y confirmar, la ejecución se detiene antes de aplicar.
- `ruta-estatica` y `loopback`: se rechazan si el prefijo de la ruta (o la subred de la loopback) contiene la IP de origen de la sesión, porque se tragaría el regreso de la conexión SSH.
- `banner-motd`: la línea que se manda usa `#` como delimitador y IOS la muestra como `^C`; por eso el texto no admite `#` ni `^`. Un banner actual de varias líneas se rechaza (la reversa no lo restauraría).
- Agregar lo que ya está (la misma ruta, el mismo servidor NTP, el mismo helper...) responde `InvalidArgument` con «no hay nada que cambiar»; una variante que la reversa no restauraría (la misma ruta con otra distancia, el mismo NTP con `key`, una community que ya existe...) responde `FailedPrecondition`.

Ejemplo de respuesta de `listSnippetTemplates` (recortado):

```json
[ { "id": "speed-duplex", "tech": "l2", "name": "Velocidad y duplex de puertos", "platforms": ["ios", "ios-xe"],
    "fields": [
      { "name": "interfaces", "label": "Puertos", "type": "interfaces", "required": true, "help": "Lista separada por comas o rangos como Gi1/0/1-4; solo puertos físicos." },
      { "name": "speed", "label": "Velocidad", "type": "choice", "choices": ["auto", "10", "100", "1000"] } ] } ]
```

---

## Guardar archivos (exportar y descargar)

Hecho en el front y el puente, sin núcleo: el diálogo nativo de guardar lo abre el runtime de Wails (`Dialogs.SaveFile`) y `Bridge.WriteFile(path, data, encoding, overwrite)` (`ui/bridge/files.go`) escribe en la ruta elegida: temporal en la misma carpeta y renombrado, permisos 0600, tope de 64 MiB; `encoding` es `utf8` o `base64` (PNG de gráficas). El diálogo GTK3 de Wails no confirma la sobrescritura: sin `overwrite`, una ruta que existe devuelve «el archivo ya existe» y el front pregunta antes de reintentar. En TS: `core.saveFile(name, data, encoding)`, que devuelve la ruta, o `""` si se cancela o falla (el fallo se muestra en un diálogo de error).

---

## Bóveda de scripts (fase 28c)

Scripts de comandos del usuario más una **biblioteca predefinida** de solo lectura, con favoritos y export/import a un archivo. La vista la hace la sesión de front; el núcleo, el puente y el contrato ya están.

- RPC: `ScriptsService` (`ListScripts`, `GetScript`, `SaveScript`, `DeleteScript`, `SetFavorite`, `DuplicateScript`, `ExportScripts`, `PreviewImport`, `ApplyImport`). CLI: `mctl scripts list|show|add|edit|rm|fav|dup|export|import`.
- Puente: `ListScripts(filter)`, `GetScript(id)`, `SaveScript(draft)`, `DeleteScript(id)`, `SetScriptFavorite(id, favorite)`, `DuplicateScript(id)`, `ExportScripts(ids, path, overwrite)`, `PreviewScriptsImport(path)`, `ApplyScriptsImport(token, decisions)`. TS: los mismos nombres con la primera letra en minúscula en `core` (`modules/scripts/api.ts`; el doble está en `modules/scripts/fake.ts`: `sampleScripts` y `sampleImport`).
- **Un script nunca se aplica a un equipo desde esta área** (ADR 0007). La vista tiene dos usos: «enviar a la terminal» (inserta el texto **sin Enter**; la terminal ya es manual) y, en otra rama, Patrol, que solo acepta los `readOnly`.

```ts
interface ScriptItem {
  id: string;            // 32 hex (usuario) o «lib-<nombre>» (biblioteca: no se edita ni se borra)
  name: string;          // 1 a 64; único entre los del usuario sin importar mayúsculas
  tech: "l2" | "l3" | "gestion" | "seguridad" | "qos" | "etherchannel" | "wireless" | "diagnostico" | "otro";
  platform: "ios" | "ios-xe" | "nx-os" | "asa" | "cualquiera";
  description: string;   // hasta 512
  commands: string[];    // 1 a 200 líneas de hasta 512; ASCII imprimible (sin tabuladores ni acentos: IOS con 7 bits rompe lo demás)
  tags: string[];        // hasta 10, cada una [a-z0-9-]{1,24}, sin repetir
  origin: "biblioteca" | "usuario";
  createdMs: number; updatedMs: number;
  readOnly: boolean;     // lo calcula el núcleo; ver las reglas abajo
  favorite: boolean;     // lo calcula el núcleo; no viaja en el export
}
interface ScriptFilter { tech?: string; platform?: string; tag?: string; text?: string; onlyFavorites?: boolean }
```

Notas:

- **`readOnly`** es verdadero solo si la plataforma es `ios` o `ios-xe` y todos los comandos pasan `playbook.CheckDenied` y ninguno lleva `;`. Para `nx-os`, `asa` y `cualquiera` es **siempre falso** mientras `CheckDenied` solo modele IOS (cuando tenga reglas por plataforma se mide contra ellas). Las **líneas que empiezan con «!» en la columna 0 son comentario y se ignoran** (` !x`, con espacio, no lo es y cuenta como comando). Quien ejecute un script (Patrol, en otra rama) debe usar la misma regla con `scripts.Runnable(cmds)`, que devuelve los comandos sin esas líneas, y exigir `readOnly`.
- `listScripts` junta biblioteca y usuario, por nombre sin importar mayúsculas. `text` busca en nombre, descripción, etiquetas y comandos. Con `platform` también entran los `cualquiera`.
- `saveScript`: sin `id` crea; con el `id` de un script del usuario edita (conserva `createdMs`). Origen, fechas, `readOnly` y `favorite` se ignoran al guardar. Rechaza `lib-*` y un nombre repetido (`AlreadyExists`). El nombre se recorta de espacios.
- `duplicateScript` acepta también los de la biblioteca y crea un script del usuario llamado «<nombre> (copia)», con número si ya existe. Es la forma de «editar» uno de la biblioteca.
- `setScriptFavorite` vale para ambos orígenes. Borrar un script borra su favorito.
- La **biblioteca** (IDs estables `lib-<nombre>`): un script de diagnóstico por cada playbook de `playbooks/cisco/ios-xe` (mismos comandos; `readOnly` verdadero) más 10 de configuración comunes (`lib-cfg-*`: VLAN de acceso, trunk, NTP, logging, SNMP RO, banner, BPDU Guard, EtherChannel LACP, SSH, puertos sin uso; `readOnly` falso, plantillas «sin validar en laboratorio»). Se deriva de los playbooks al cargar, así que no se desincroniza. El ID es `lib-<id>` para `ios-xe` y `lib-<plataforma>-<id>` para las demás plataformas (los de ios-xe no cambian); la carga falla con un error claro si dos scripts de la biblioteca repiten ID o nombre.
- **Nombres**: se comparan sin importar mayúsculas (una sola regla, también para «ς» y «σ») y **los nombres de la biblioteca cuentan como ocupados**: `saveScript` y `duplicateScript` no los dan a un script del usuario (`AlreadyExists`). Así un export de scripts propios y de biblioteca siempre se puede reimportar.

**Export** (`exportScripts(ids, path, overwrite)`): `ids` de 1 a 1000, de usuario o de biblioteca; `path` **absoluta**. Devuelve cuántos exportó. El archivo se crea 0600 y sin seguir enlaces simbólicos. Sin `overwrite`, una ruta que existe da `AlreadyExists`; con `overwrite` solo reemplaza un archivo regular (temporal y renombrado). Se rechaza (`InvalidArgument`) si el archivo pasaría de 5 MB, que es lo que el import acepta, o si dos de los scripts elegidos se llaman igual. Ojo: `core.pickSavePath` ya deja el archivo creado vacío tras confirmar con la persona, así que tras ese diálogo se llama con `overwrite: true`. Los favoritos no viajan.

```json
{"formato":"macuahuitl-scripts","version":1,"exportado":"2026-11-07T12:00:00Z","scripts":[ … ],"sha256":"<hex>"}
```

`sha256` es la suma del JSON canónico del arreglo `scripts`. Es integridad contra corrupción, **no autenticidad**: quien edite el archivo puede recalcularla, así que un archivo de otra persona se revisa como cualquier script antes de usarlo.

**Import en dos pasos.**

1. `previewScriptsImport(path)` (ruta absoluta; archivo regular de hasta 5 MB y 1000 scripts; valida formato, versión, suma y las reglas de cada script, sin IDs ni nombres repetidos dentro del archivo). No escribe nada. Devuelve `{ token, expiresMs, items }` (el token vale 10 minutos y se gasta al aplicar). Cada `item` trae el script tal como viene y su `state`:
   - `nuevo`: se importa solo.
   - `igual`: mismo ID y contenido; un `lib-*` igual al de la biblioteca local (`conflictsWith` = ese `lib-*`) o a una copia propia con su nombre; se omite solo.
   - `conflicto_id`: mismo ID, contenido distinto; `conflictsWith` es ese ID.
   - `conflicto_nombre`: otro ID, mismo nombre; `conflictsWith` es el script propio que lo tiene, o un `lib-*` local si el nombre es de la biblioteca (un `lib-*` ajeno que difiere del local, o un script de usuario con un nombre de la biblioteca). Un `lib-*` de otra instalación sin coincidencia es `nuevo` y se importa como script del usuario con ID nuevo.
2. `applyScriptsImport(token, decisions)` con `{ scriptId, action }` por cada conflicto (`scriptId` es el ID del script **en el archivo**):
   - `renombrar`: ID nuevo y nombre «<nombre> (importado)», con número si choca con un guardado, con la biblioteca o con otro nombre del mismo archivo.
   - `reemplazar`: pisa el script propio con el que choca (conserva su ID, su fecha de creación y su favorito). No vale contra la biblioteca, y dos decisiones `reemplazar` que apunten al mismo script guardado son un error.
   - `omitir`.

   Falta una decisión para un conflicto → error y **no se escribe nada** (el token sigue vivo). También falla una acción desconocida, una decisión para un ID que no está en el archivo, y `renombrar` o `reemplazar` sobre un script que no es conflicto (sobre un `nuevo` solo vale `omitir`). Todo va en una transacción y se compara de nuevo contra lo guardado en ese momento. Devuelve `{ created, replaced, renamed, skipped }` (`skipped` incluye los `igual`).
   - Lo importado queda con `origin: "usuario"`; un ID `lib-*` de otra biblioteca recibe uno nuevo.
   - Token desconocido o ya usado → `NotFound`; vencido → `FailedPrecondition` (volver a abrir el archivo). Dos `applyScriptsImport` a la vez con el mismo token: solo uno se aplica. Una decisión inválida (`InvalidArgument`) deja el token vivo para corregirla; un fallo interno lo gasta.
   - El archivo debe ser JSON de un solo valor (sin datos después) y una `version` distinta de 1 da «versión N no soportada».

Todo cambio queda en la auditoría: `scripts.crear`, `scripts.editar`, `scripts.borrar`, `scripts.favorito`, `scripts.exportar` (ruta y cuántos) y `scripts.importar` (ruta, conteos y decisiones).

Ejemplo de vista previa con un conflicto de nombre:

```json
{ "token": "9f1c…", "expiresMs": 1794139200000, "items": [
    { "script": { "id": "bbbb…", "name": "Nuevo", "origin": "usuario", "readOnly": true, "commands": ["show clock"] }, "state": "nuevo", "conflictsWith": "" },
    { "script": { "id": "cccc…", "name": "Mi OSPF", "origin": "usuario", "readOnly": true, "commands": ["show ip route"] }, "state": "conflicto_nombre", "conflictsWith": "aaaa…" }
  ] }
```

## Receptor syslog: tope de tasa, rotación y formato (fase 28a)

- RPC: `ToolsService.Syslog` (stream), ampliado sin renumerar. CLI: `mctl syslog listen` con `--rate --burst --rate-global --burst-global --queue` y, con `--save`, `--rotate-mb --rotate-min --name --max-files --format`.
- Puente: `Bridge.SyslogStart(addr, proto, allowAny, save, opts)`; el quinto argumento es obligatorio para Wails (`{}` = todos los defaults). TS: `core.syslogStart(addr, proto, allowAny, save, opts?)` ya lo manda así. Los eventos siguen siendo `syslog:msg` y `syslog:done`; `onSyslog` los entrega con `done` marcado al terminar.
- Todo valor en `0` o `""` es el default. Un valor fuera de rango hace fallar el inicio con el motivo en español (no se abre el socket), y la vista lo muestra como cualquier otro error de `syslogStart`.

```ts
interface SyslogOptions {
  ratePerSource?: number; burstPerSource?: number;  // msg/s por IP de origen
  rateGlobal?: number; burstGlobal?: number;        // msg/s en total
  queueSize?: number;                               // mensajes en espera de escribirse
  rotateMb?: number; rotateMinutes?: number;        // solo con save
  nameTemplate?: string; maxFiles?: number;         // solo con save
  format?: "texto" | "crudo" | "jsonl";             // solo con save
}
interface SyslogDrops { total: number; porOrigen: number; global: number; colaLlena: number; sinceMs: number; top: { source: string; count: number }[] }
interface SyslogEvent { runId: string; listening?: string; outputPath?: string; json?: string; done?: boolean; error?: string;
                        rotatedPath?: string; drops?: SyslogDrops }
```

| Campo | Default | Rango |
|---|---|---|
| `ratePerSource` | 100 | 1–10000 |
| `burstPerSource` | 2x la tasa | 1–1000000 |
| `rateGlobal` | 1000 | 1–100000 |
| `burstGlobal` | 2x la tasa | 1–1000000 |
| `queueSize` | 4096 | 64–65536 |
| `rotateMb` | 50 | 1–1024 |
| `rotateMinutes` | 0 (no rota por tiempo) | 1–10080 (7 días) |
| `nameTemplate` | `syslog_{fecha}_{hora}` | ver abajo |
| `maxFiles` | 20 | 1–1000 |
| `format` | `texto` | `texto`, `crudo`, `jsonl` |

Con los defaults el tope en disco es de ~1 GB (20 archivos de 50 MB).

Cómo se comporta:

- **Tasa.** Cada IP de origen (sin puerto) tiene su cubo; después se aplica el global. Un origen que inunda gasta solo su parte y no le quita lugar a otro. Hay cubo propio para 1024 orígenes; los siguientes comparten uno llamado `otros`. El lector nunca espera: si no hay ficha o la cola está llena, el mensaje se descarta y se cuenta (`porOrigen`, `global` o `colaLlena`).
- **Descartes.** `drops` es el **acumulado** desde que empezó la escucha (no un incremento). Llega a lo más una vez por segundo y solo si cambió, más una última vez al cerrar si hubo descartes. `sinceMs` es el primer descarte; `top` trae hasta 10 orígenes, el que más descartó primero. No viene `drops` si no se ha descartado nada. El mismo evento no trae `json` ni `listening`.
- **Archivo (solo con `save`).** `outputPath` del primer evento es la **carpeta** (`outputs/syslog`); no se crea ningún archivo hasta el primer mensaje. Cada archivo nuevo (por rotación, o por origen con `{origen}`) llega en un evento con `rotatedPath`. Rota al llegar a `rotateMb` o, si se pide, cada `rotateMinutes` desde que se abrió. Tras crear un archivo, la retención borra los más viejos que encajan con la plantilla hasta dejar `maxFiles`; no toca otros archivos de la carpeta ni los que están abiertos. Cada borrado y la configuración efectiva quedan en la auditoría.
- **Plantilla.** 1–64 caracteres, solo `[A-Za-z0-9_.-]` y los tokens `{fecha}` (AAAAMMDD), `{hora}` (HHMMSS) y `{origen}` (la IP con `:` cambiado a `-`). Debe llevar `{fecha}` o `{hora}`; sin `/`, `\`, `..` ni otros tokens. La extensión la pone el formato (`.log` o `.jsonl`) y si el nombre ya existe se agrega `_N`. Con `{origen}` hay un archivo por origen (hasta 64 abiertos a la vez; el menos usado se cierra y se reabre al volver). La vista puede validar en vivo con la misma regla.
- **Formatos.** `texto`: `RFC3339 origen:puerto mensaje` por línea. `crudo`: solo el mensaje, una línea. `jsonl`: el mensaje ya interpretado (los mismos campos que el evento `json`), uno por línea.
- **Interfaz lenta.** Los eventos pasan por una cola de 1024 hacia la vista; si la vista no los consume y se llena, los que no caben se pierden para la vista (no para el archivo) y quedan contados en la auditoría (`perdidos_en_la_interfaz`). Al terminar se espera unos 2 s a que reciba lo que quedó en cola.
- Valores que no caben en un entero de 32 bits se rechazan al llamar al puente.
- Si el archivo deja de poder escribirse (disco lleno, carpeta borrada) la escucha termina con error en `syslog:done`.

Ejemplo del evento de descartes (llega por `onSyslog`):

```json
{ "runId": "run-3", "drops": {
    "total": 1200, "porOrigen": 1100, "global": 80, "colaLlena": 20, "sinceMs": 1793959200000,
    "top": [ { "source": "10.0.0.9", "count": 1100 }, { "source": "otros", "count": 100 } ] } }
```

Y el de archivo nuevo: `{ "runId": "run-3", "rotatedPath": "/home/…/outputs/syslog/syslog_20261107_120000.log" }`.

Doble de pruebas: `fakeTools()` (ya dentro de `fakeCore()`) tiene `emitSyslog(e)` y `sampleSyslogDrops` (en `modules/tools/fake.ts`).

## Colecciones de scripts y fijados (fase 29c)

Amplía la bóveda de scripts (fase 28c). Las vistas las hace la sesión de front; el núcleo, `mctl scripts col|pin`, el puente y el doble ya están.

- RPC (`ScriptsService`): `ListCollections`, `GetCollection`, `SaveCollection`, `DeleteCollection`, `ReorderCollections`, `SetCollectionScripts`, `SetPinned`, `ListPinned`, `ReorderPinned`, `ExportCollections`, `PreviewImportCollections`, `ApplyImportCollections`. CLI: `mctl scripts col list|show|add|edit|rm|set|order|export|import` y `mctl scripts pin`.
- Puente → `core` (`modules/scripts/api.ts`): `ListCollections()` → `listCollections()`, `GetCollection(id)`, `SaveCollection(id, name, description)` → `saveCollection({ id?, name, description? })`, `DeleteCollection(id)`, `ReorderCollections(ids)`, `SetCollectionScripts(id, scriptIds)`, `SetScriptPinned(id, pinned)` → `setScriptPinned`, `ListPinnedScripts()` → `listPinnedScripts()`, `ReorderPinnedScripts(ids)` → `reorderPinnedScripts`, `ExportCollections(ids, path, overwrite)`, `PreviewCollectionsImport(path)` → `previewCollectionsImport`, `ApplyCollectionsImport(token, scriptDecisions, collectionDecisions)` → `applyCollectionsImport`. El doble está en `modules/scripts/fake.ts` (`sampleCollectionsImport`).
- `ScriptItem` gana `pinned: boolean` y `collections: string[]` (IDs de las colecciones que lo contienen, en el orden de las colecciones). Los dos los calcula el núcleo y no viajan en el export. `favorite` sigue existiendo y ahora significa «está en la colección `favoritos`».

```ts
interface Collection {
  id: string;            // 32 hex, o «favoritos»
  name: string;          // 1 a 64; único sin importar mayúsculas (la misma clave de nombre que los scripts, también contra «Favoritos»)
  description: string;   // hasta 512
  order: number;         // posición entre todas las colecciones, desde 0
  scriptIds: string[];   // en orden; de usuario o de biblioteca («lib-*»); hasta 1000
  createdMs: number; updatedMs: number;
}
```

Reglas:

- **Un nivel y por referencia.** Una colección guarda IDs de script, también `lib-*`, y nunca copia nada. Un script puede estar en varias. Borrar un script de usuario lo quita de todas las colecciones y de los fijados. Un `lib-*` que una biblioteca futura ya no trae se oculta de las colecciones al leerlas.
- **`favoritos`** es la colección por defecto (ID fijo `favoritos`, nombre «Favoritos»). Existe siempre: la migración 0005 convirtió la tabla de favoritos de la 0004 en ella sin perder ninguno (orden por nombre sin importar mayúsculas, porque no había fecha de marcado; los `lib-*` no tienen nombre en la base y ordenan por su ID). No se borra (`FailedPrecondition`) ni se renombra (`InvalidArgument`); su descripción sí se edita y se reordena como las demás. `setScriptFavorite(id, bool)` es el atajo: agrega al final o quita en `favoritos` (idempotente).
- `saveCollection`: sin `id` crea (queda al final; hasta 100 colecciones, el tope da `FailedPrecondition`); con `id` edita solo nombre y descripción. Los scripts **no** se tocan por aquí. Nombre repetido → `AlreadyExists`; nombre o descripción inválidos → `InvalidArgument`; ID desconocido → `NotFound`.
- `setCollectionScripts(id, scriptIds)` deja la colección con **exactamente** esa lista y en ese orden: sirve para agregar, quitar y reordenar de una vez. Sin repetidos (`InvalidArgument`); cada ID debe existir (`NotFound`). Si falla no cambia nada.
- `reorderCollections(ids)` debe traer **todas** las colecciones, también `favoritos`, una sola vez (`InvalidArgument` si no).
- **Fijados** (`pinned`): flag por script, independiente de las colecciones, para la barra corta de la terminal. Vale para scripts de usuario y de biblioteca. **Máximo 5**: el sexto da `FailedPrecondition` con el motivo («ya hay 5 scripts fijados…»); volver a fijar uno ya fijado no cuenta. Se fijan al final; `listPinnedScripts()` los da en su orden y `reorderPinnedScripts(ids)` exige exactamente los fijados una vez cada uno.

**Export** (`exportCollections(ids, path, overwrite)`): `ids` de 1 a 100 colecciones; `path` absoluta; devuelve `{ collections, scripts }`. Usa el mismo canon, la misma suma, el tope de 5 MB y las mismas reglas de archivo que el export de scripts (0600, sin enlaces, `overwrite` solo sobre archivos regulares; tras `pickSavePath` se llama con `overwrite: true`).

```json
{"formato":"macuahuitl-colecciones","version":1,"exportado":"2026-11-07T12:00:00Z","colecciones":[ … ],"scripts":[ … ],"sha256":"<hex>"}
```

`scripts` trae **solo los scripts de usuario** que las colecciones referencian; los de biblioteca viajan por ID. `sha256` es la suma del JSON canónico de `colecciones` y `scripts` juntos (integridad, no autenticidad). Un archivo de scripts no vale como archivo de colecciones, ni al revés. El import rechaza el archivo si una colección referencia un script de usuario que no viaja en él o si trae scripts de biblioteca dentro de `scripts`.

**Import en dos pasos** (el token es de un tipo: el de scripts no vale para aplicar colecciones, ni al revés, y el equivocado no se gasta).

1. `previewCollectionsImport(path)` → `{ token, expiresMs, collections, scripts, warnings }`. No escribe nada. Cada colección trae su `state`:
   - `nueva`: se importa sola, al final del orden.
   - `igual`: mismo ID, nombre, descripción y scripts; se omite sola.
   - `conflicto_id`: mismo ID, contenido distinto; `conflictsWith` es ese ID.
   - `conflicto_nombre`: otro ID, mismo nombre; `conflictsWith` es la colección local que lo tiene (también si el nombre es «Favoritos»).
   - `fusionar`: solo `favoritos` cuando trae scripts que a la local le faltan; no pide decisión (`omitir` vale). Si no le falta nada es `igual`.

   Los `scripts` llevan el estado de siempre (`nuevo`, `igual`, `conflicto_id`, `conflicto_nombre`). `warnings` avisa de cada `lib-*` que esta biblioteca no trae: se omite de la colección al importar.
2. `applyCollectionsImport(token, scriptDecisions, collectionDecisions)` con `{ scriptId, action }` (el campo se llama `scriptId` en las dos listas; en `collectionDecisions` es el ID de la **colección** del archivo). Mismas acciones y reglas que el import de scripts: `renombrar` (ID nuevo y «<nombre> (importado)»), `reemplazar` (conserva el ID local, la fecha de creación y el lugar en el orden), `omitir`. Falta una decisión, una acción desconocida, una decisión para un ID ajeno, dos `reemplazar` sobre la misma colección local, un reemplazo que dejaría dos nombres iguales o pasar de 100 colecciones → `InvalidArgument`, **sin escribir nada** y con el token vivo. `favoritos` solo admite `omitir`: nunca se reemplaza ni se renombra.
   - Scripts y colecciones se aplican **en una sola transacción**: si falla uno, no entra ninguno.
   - Los IDs de script que cambian al importar (renombrados, o un `lib-*` ajeno que pasa a ser de usuario) se reflejan en las referencias de las colecciones importadas. Un script omitido o un `lib-*` inexistente se quita de la colección y sale en `warnings`.
   - `favoritos` importado se **fusiona**: se agregan los que falten, sin duplicar, después de los locales.
   - Devuelve `{ scriptsCreated, scriptsReplaced, scriptsRenamed, scriptsSkipped, collectionsCreated, collectionsReplaced, collectionsRenamed, collectionsMerged, collectionsSkipped, warnings }` (los `skipped` incluyen los `igual`).
   - Token desconocido o gastado → `NotFound`; vencido (10 minutos) → `FailedPrecondition`; dos aplicaciones a la vez con el mismo token: solo una.

Auditoría: `scripts.coleccion.crear`, `.editar`, `.borrar`, `.reordenar`, `.scripts` (agregados y quitados), `.exportar` y `.importar` (ruta, conteos y decisiones); `scripts.fijar` y `scripts.fijados.reordenar`. `scripts.favorito` sigue igual.

### Plantilla, descripción del formato y suma opcional (fase 29c, sección Datos de Ajustes)

Para la sección Datos de Ajustes: descargar un archivo de ejemplo y mostrar qué lleva cada campo.

- RPC: `ScriptsService.ImportTemplate(kind)` e `ImportFormat(kind)`, con `kind` = `scripts` o `colecciones` (otro valor → `InvalidArgument`). CLI: `mctl scripts template [--kind scripts|colecciones] [--fields]`.
- Puente → `core`: `ImportTemplate(kind)` → `importTemplate(kind): Promise<string>` (el JSON, con sangría) e `ImportFormat(kind)` → `importFormat(kind): Promise<ImportFormatField[]>` con `{ name, type, required, example, description }`. El doble los tiene en `modules/scripts/fake.ts`.
- La plantilla y la lista de campos **salen de los mismos tipos, constantes y listas cerradas que validan el import**: los nombres se leen de las etiquetas json de `Script`, `Coleccion` y de la cabecera del archivo, los ejemplos son los valores de la plantilla, y una prueba comprueba que cada «obligatorio» coincide con lo que de verdad rechaza el validador. Si se agrega un campo sin describirlo, falla la prueba. Por eso la vista no debe copiar esos textos: que los pida.
  - `scripts`: 3 scripts válidos (uno de `show`, de solo lectura y con una línea de comentario; uno de configuración; uno con etiquetas).
  - `colecciones`: 1 colección con 2 scripts propios (que viajan en `scripts`) y 1 `lib-*` real de la biblioteca (que viaja solo por ID).
  - Los IDs de la plantilla son fijos: importarla dos veces da `igual` la segunda. Pasa la vista previa con todo `nuevo`/`nueva` y **solo** con el aviso de que no trae suma.
  - Los nombres de campo son rutas: `formato`, `version`, `exportado`, `sha256`, `scripts`, `scripts[].name`, `colecciones[].script_ids`… Los de la cabecera van incluidos. El ejemplo de `sha256` es la suma real de la plantilla.
- **`sha256` es opcional al importar** (scripts y colecciones; el export lo escribe siempre). Sin él se valida campo por campo igual y la vista previa trae `warnings: ["archivo sin suma de verificación"]` (`ImportPreview.warnings` para scripts y `CollectionsImportPreview.warnings` para colecciones, junto con los demás avisos). Con él y sin coincidir → `InvalidArgument`, como antes. Vacío (`"sha256": ""`) vale como ausente. Sin suma un byte cambiado en un valor ya no se detecta: la vista debe mostrar el aviso.
- YAML no: solo JSON.

### Vistas (fase 19v)

- **Scripts → Colecciones** (`CollectionsPanel`): alta, edición, borrado con confirmación, orden con botones subir/bajar (el foco se queda en el botón), scripts de la colección agregados por ID desde un selector y ordenados o quitados con `setCollectionScripts`. Cada fila de script trae el fijado (`setScriptPinned`) y el menú «Agregar a colección» (selección múltiple; lee la colección al día antes de escribirla). El sexto fijado se muestra con el motivo, traducido al idioma elegido.
- **Terminal SSH**: la barra rápida lleva los comandos fijos, los fijados en su orden (`listPinnedScripts`) y «Scripts ▾» (menú con búsqueda, agrupado por colección con favoritos primero). Todo entra por la misma ruta segura de inserción: una línea sin Enter con Ctrl+U antes; varias líneas de solo lectura piden confirmación; configuración de varias líneas se copia y avisa.
- **Ajustes → Datos**: tarjetas de Scripts y de Colecciones de scripts con la tabla de `importFormat(kind)` (nombre, tipo, obligatorio y ejemplo; la descripción del núcleo viene en español y no se muestra para no mezclar idiomas), plantilla (`importTemplate` → `pickSavePath` → `writeFile`), exportar todo e importar con la misma vista previa. Equipos y bóveda quedan como líneas de «todavía no disponible».
- Los avisos del import (`warnings`) llegan en español del núcleo: la vista traduce los tres conocidos («sin suma de verificación», `lib-*` ausente y script no importado) y muestra cualquier otro tal cual. `favoritos` se muestra con su nombre en el idioma elegido.
## Libreta de hosts (fase 29b)

Los equipos que la persona agrega a mano. **No es una segunda lista**: es la fuente nueva `manual` del mismo inventario. Aparecen en `listDevices` con `"manual"` en `sources`, fusionados por dirección con lo descubierto, y la terminal SSH elegirá el host de ahí y conocerá su plataforma. La vista la hace la sesión de front; el núcleo, el puente y el contrato ya están.

- RPC: `InventoryService` (`ListDevices` con `folder` y `tag`, `PutDevice`, `DeleteDevice`, `ExportHosts`, `PreviewImportHosts`, `ApplyImportHosts`, `HostsImportTemplate`, `HostsImportFormat`). CLI: `mctl hosts list|add|edit|rm|export|import|template` (y `mctl devices` ya muestra la fuente `manual`).
- Puente: `ListHosts(query, folder, tag)` (solo los de la libreta), `SaveHost(draft)`, `DeleteHost(id)`, `ExportHosts(ids, path, overwrite, format)`, `PreviewHostsImport(path, format)`, `ApplyHostsImport(token, decisions)`, `HostsImportTemplate(format)`, `HostsImportFormat()`; `ListDevices(query)` sigue igual y suma campos. TS: los mismos nombres con la primera letra en minúscula en `core` (`modules/inventory/api.ts`; el doble está en `modules/inventory/fake.ts`: `sampleHosts`, `sampleHostsImport`, `sampleHostFields` y `fakeInventory(initial?)`, que guarda en memoria y respeta las reglas básicas).
- **Nunca un secreto en la libreta ni en el archivo.** `credentialId` es el id de una credencial de la bóveda (la lista de `core.listCredentials` o `mctl cred list`); `credentialLabel` es de solo lectura y vale `""` si no hay credencial, la bóveda está cerrada o la credencial ya no existe. Al guardar se comprueba que exista y no sea una entrada del sistema (`InvalidArgument`); con la bóveda cerrada se guarda la referencia **sin validar** y la respuesta trae un aviso en `warnings`.

```ts
type HostPlatform = "" | "ios" | "ios-xe" | "nx-os" | "asa" | "iosxr" | "wlc";   // vacío = sin definir
interface Host {
  id: string;                  // 32 hex; vacío al crear
  name: string;                // 1 a 64, sin espacios en los extremos ni caracteres de control; único sin importar mayúsculas
  address: string;             // IP o nombre DNS; sin espacios, @, esquema, puerto ni ruta. Se guarda canónica (minúsculas, IPv6 abreviada)
  port: number;                // 1 a 65535; 0 al guardar = 22
  platform: HostPlatform;
  folder: string;              // un solo nivel [A-Za-z0-9 _.-]{1,48}, sin espacios en los extremos; vacío = sin carpeta
  tags: string[];              // hasta 10, [a-z0-9-]{1,24}, sin repetir
  credentialId: string; credentialLabel: string;
  notes: string;               // hasta 2000 caracteres
}
```

`KnownDevice` (de `listDevices`) gana `id`, `name`, `port`, `folder`, `tags`, `credentialId`, `credentialLabel` y `notes`. Solo los equipos con host manual traen `name`, `port`, `folder`, `credentialId`, `credentialLabel` y `notes`; su **`id` es el del host de la libreta** (con él se edita y se borra), y en los demás sigue siendo la dirección o «nombre:<host>». `tags` va siempre como `[]`.

Notas:

- **Dedupe y fusión.** Un host con la misma dirección que un equipo descubierto sale en **una sola fila**, con las dos fuentes (por ejemplo `["flota", "manual"]`); `hostname` y `name` son el nombre del host, su `platform` manda si no está vacía, y `lastSeenMs` es el de la evidencia. Si varios hosts comparten dirección con puertos distintos, solo el primero (por nombre) se funde con lo descubierto y los demás son filas aparte. Borrar el host **no borra la evidencia** de las otras fuentes: la fila descubierta vuelve a verse sola. Sin `outputs/` pero con hosts, la lista sale igual con un aviso en `warnings`; sin ninguno sigue el error de siempre.
- **Unicidad.** El nombre (sin importar mayúsculas) y el par dirección + puerto no se repiten entre los hosts de la libreta: `AlreadyExists` al crear o editar. El mismo equipo en otro puerto sí.
- `listDevices(query)` busca también en carpeta y etiquetas. `listHosts({ query, folder, tag })` es la lectura para **editar**: devuelve solo los hosts de la libreta **con sus propios valores**, sin fusionar con lo descubierto (en el núcleo es `ListDevices` con `manual_only`; no lee `outputs/`, así que tampoco falla si aún no existe). Así un host sin plataforma sigue sin plataforma aunque Patrol haya detectado `ios-xe` en esa dirección, y guardarlo desde la vista no la fija. `query` busca solo en los valores del host; `folder` se compara sin importar mayúsculas y `tag` es exacta. Usa `listDevices` para elegir un host en la terminal (ahí sí ves la fila fusionada).
- `saveHost`: sin `id` crea; con el `id` de un host de la libreta edita (conserva la fecha de creación; un id que no existe da `NotFound`, también uno de dirección). Hasta 5000 hosts. Devuelve `{ id, warnings }`. `deleteHost(id)`: `NotFound` si no existe.
- Orden de `listHosts`: por nombre sin importar mayúsculas (la misma regla de Unicode que la unicidad: «ñ» y «Ñ» se juntan). Sin carpetas anidadas: la carpeta es solo un texto para agrupar.

**Formatos: JSON y CSV.** Los dos sirven para exportar e importar. El formato sale de la extensión de la ruta (`.csv` / `.json`) o del argumento `format` (`"csv"` / `"json"`, que manda sobre la extensión); sin ninguno de los dos, `InvalidArgument`. Tope de **5 MB y 1000 hosts** por archivo, los mismos en los dos; `exportHosts` rechaza (`InvalidArgument`) más de 1000 porque el import no los aceptaría; el mensaje explica cómo partirlo: varios archivos, eligiendo los hosts por `ids` (por ejemplo, los de cada carpeta, que sale de `listHosts({ folder })`).

**Export** (`exportHosts(ids, path, overwrite, format?)`): `ids` vacío = todos; `path` **absoluta**; devuelve `{ count, warnings }`. Mismas reglas de archivo que los scripts: 0600, sin seguir enlaces, sin `overwrite` una ruta que existe da `AlreadyExists` (`core.pickSavePath` deja el archivo creado vacío tras confirmar, así que ahí va `overwrite: true`). La **credencial viaja solo como su etiqueta** (`credential_label`), nunca como id ni como secreto; si no se puede leer (bóveda cerrada o credencial borrada) ese host sale sin credencial y hay un aviso en `warnings`. Las notas sí viajan.

```json
{"formato":"macuahuitl-hosts","version":1,"exportado":"2026-11-07T12:00:00Z","hosts":[
  {"name":"LAB-CORE","address":"10.9.0.1","port":22,"platform":"ios-xe","folder":"Lab","tags":["core"],"credential_label":"admin lab","notes":""} ],"sha256":"<hex>"}
```

- **JSON**: `sha256` es la suma del JSON canónico del arreglo `hosts` (integridad contra corrupción, **no autenticidad**). Es **opcional al leer**: con suma que no coincide se rechaza **todo** el archivo («la suma de verificación no coincide»); sin suma se valida host por host y la vista previa trae el aviso «archivo sin suma de verificación». El export siempre la escribe.
- **CSV** (para Excel): UTF-8 **con BOM** al escribir, para que Excel muestre bien los acentos (al leer se acepta y se quita; también sin él), separador coma, comillas RFC 4180, **sin suma**. Encabezado fijo `name,address,port,platform,folder,tags,credential_label,notes`: al leer debe coincidir en nombres y orden, sin importar mayúsculas ni espacios alrededor; columnas de menos, de más, repetidas o en otro orden rechazan el archivo con un mensaje que dice cuáles. `tags` va separada por `;`. **Seguro contra fórmulas**: al escribir, una celda que empieza con `=`, `+`, `-`, `@`, tabulador o CR lleva un `'` delante; al leer se quita ese `'` si va seguido de uno de esos caracteres (una celda que ya empezaba con `'` y luego uno de ellos recibe otro `'`, así ir y volver no cambia nada).

**Plantilla y descripción de campos (una sola tabla).** `hostsImportTemplate(format)` devuelve `{ format, filename, content }`: el archivo de ejemplo con el encabezado y **3 filas válidas** (en JSON, el archivo versionado **sin** `sha256`), listo para que la persona lo guarde con `filename` (p. ej. `hosts-plantilla.csv`) y lo llene; sin `format` o con uno desconocido, `InvalidArgument`. `hostsImportFormat()` devuelve `{ fields, maxRows, maxBytes }` con `fields: { name, type, required, example, description }[]` en el orden del encabezado (`type`: `texto`, `entero` o `lista`; obligatorios solo `name` y `address`). Las dos salen de la **misma tabla de campos** que valida el import, el encabezado del CSV y las claves del JSON (una prueba lo exige), así que no se desalinean. La plantilla pasa por `previewHostsImport` sin errores y con todos sus hosts `nuevo`. La vista puede pintar la ayuda de columnas directamente de `fields`.

**Import en dos pasos** (como el de scripts):

1. `previewHostsImport(path, format?)` (archivo regular de hasta 5 MB y 1000 hosts). Solo un formato, versión, cabecera, tamaño, tope de filas o suma rota rechazan **todo el archivo** (`InvalidArgument`). Un host inválido es **error de su fila**: no bloquea las demás. No escribe nada. Devuelve `{ token, expiresMs, format, items, errors, warnings }` (el token vale 10 minutos y un solo uso).
   - `errors: { line, field, reason }[]` con **una entrada por fila inválida**, p. ej. `{ line: 14, field: "address", reason: "dirección \"admin@x\": use una IP…" }` («línea 14: address inválida»). `line` es la línea del archivo en CSV (el encabezado es la 1) y la posición, desde 1, dentro de `hosts` en JSON. `field` es el nombre del campo de la tabla (`name`, `address`, `port`, `platform`, `folder`, `tags`, `credential_label`, `notes`) o vacío si falla la fila entera (columnas de menos, comillas mal cerradas, entrada JSON ilegible). Son errores de fila: tipos mal puestos, valores fuera de las reglas, y un nombre o un `dirección:puerto` repetido (la **segunda** fila que repite es la inválida).
   - Cada `item` es una fila **válida**, tal como viene (sin `credentialId`, con su `credentialLabel`), con su `key` (`dirección:puerto`, que identifica al host en las decisiones) y su `state`:
     - `nuevo`: se importa solo.
     - `igual`: misma dirección y puerto y los mismos datos; se omite solo.
     - `conflicto` con `reason: "direccion"`: misma dirección y puerto con otros datos; `conflictsWith` es el id del host guardado. Solo `reemplazar` u `omitir`.
     - `conflicto` con `reason: "nombre"`: otro destino pero el mismo nombre. `renombrar`, `reemplazar` u `omitir`. Si chocan las dos cosas con hosts distintos, manda la dirección.
     - `credentialMissing`: el archivo trae una etiqueta y en la bóveda local no hay credencial con ella (o hay varias): el host quedaría **sin credencial**. Con la bóveda cerrada pasa con todas; `warnings` lo explica.
2. `applyHostsImport(token, decisions)` con `{ key, action }` por cada conflicto:
   - `renombrar`: id nuevo y nombre «<nombre> (importado)», con número si choca con un guardado o con otro nombre del archivo.
   - `reemplazar`: pisa el host guardado con el que choca (conserva su id y su fecha de creación). Falla si el nombre o el destino resultante ya es de otro host, y dos `reemplazar` sobre el mismo host guardado son un error.
   - `omitir`.

   **Se aplican solo las filas válidas con sus decisiones; las inválidas no necesitan decisión y se reportan como omitidas.** La credencial de cada host se resuelve **una sola vez, en la vista previa**, y se aplica tal cual: cerrar la bóveda entre los dos pasos no cambia nada (si estaba cerrada en la vista previa, ya hubo aviso y los hosts quedan sin credencial). Falta una decisión, una acción desconocida o inválida para ese estado (`renombrar` en un conflicto de dirección; algo distinto de `omitir` en un `nuevo` o `igual`), una clave que no es de una fila válida del archivo, o una decisión repetida → `InvalidArgument`, no se escribe nada y el token sigue vivo. Todo va en una transacción y se compara de nuevo contra lo guardado en ese momento. Devuelve `{ created, replaced, renamed, skipped, invalid }`: `skipped` incluye los `igual` y las filas inválidas, e `invalid` es cuántas de las omitidas eran inválidas. Token desconocido o ya usado → `NotFound`; vencido → `FailedPrecondition`; dos aplicaciones a la vez con el mismo token: solo una se aplica.

Auditoría (sin notas ni credenciales en el detalle): `hosts.crear`, `hosts.editar`, `hosts.borrar` (id y «nombre dirección:puerto»), `hosts.exportar` (ruta, cuántos y formato) y `hosts.importar` (ruta y conteos, con los inválidos).

Ejemplo de `listDevices` con un host fusionado:

```json
{ "devices": [
    { "id": "aaaa…", "address": "10.9.0.1", "hostname": "LAB-CORE", "name": "LAB-CORE", "platform": "ios-xe", "port": 22, "folder": "Lab", "tags": ["core"],
      "credentialId": "cccc…", "credentialLabel": "admin lab", "notes": "", "lastSeenMs": 1793959200000, "sources": ["flota", "manual"] },
    { "id": "10.0.0.9", "address": "10.0.0.9", "hostname": "CAIDO", "name": "", "platform": "ios-xe", "port": 0, "folder": "", "tags": [],
      "credentialId": "", "credentialLabel": "", "notes": "", "lastSeenMs": 0, "sources": ["patrol"] }
  ], "warnings": [] }
```

## Traps y flujos: los mismos topes y archivo que syslog (fase 29a)

Traps SNMP y flujos (NetFlow, IPFIX, sFlow) dan lo mismo que el receptor syslog de la sección anterior: tope de tasa por origen y global con ráfaga, cola acotada que descarta y cuenta, y archivo con rotación, plantilla, retención y formato. **Todo lo que no se dice aquí es igual**: los campos, defaults, rangos, el evento de descartes, la rotación, la retención, la plantilla y el comportamiento con una interfaz lenta.

- RPC: `VisibilityService.SnmpTraps` y `VisibilityService.Flows` (streams), ampliados sin renumerar con los mismos campos de `SyslogRequest` (`rate_per_source` … `format`); sus respuestas ganan `drops` (el mismo `SyslogDrops`) y `rotated_path`. CLI: `mctl snmp traps listen` y `mctl flows listen` con las mismas banderas que `mctl syslog listen` (`--rate --burst --rate-global --burst-global --queue` y, con `--save`, `--rotate-mb --rotate-min --name --max-files --format`).
- Puente: `Bridge.TrapsStart(addr, allowAny, save, v3Cred, auth, priv, opts)` y `Bridge.FlowsStart(addr, allowAny, save, top, opts)`; `opts` es el mismo `SyslogOptions` y es argumento obligatorio para Wails (`{}` = todos los defaults). TS: `core.trapsStart(…, opts?)` y `core.flowsStart(…, top, opts?)` ya mandan `{}` si falta. Los eventos siguen siendo `traps:msg`/`traps:done` y `flows:msg`/`flows:done`; `onVis(kind, cb)` los entrega con `done` al terminar. `VisEvent` gana `rotatedPath?` y `drops?` (el mismo `SyslogDrops`).
- Con `save`, `outputPath` del primer evento pasa a ser la **carpeta** (`outputs/snmp-traps` u `outputs/flows`), ya no un archivo por sesión. Cada archivo nuevo llega en un evento con `rotatedPath`. Sin `save` no cambia nada.
- Un valor fuera de rango hace fallar el inicio con `InvalidArgument` y el motivo en español, antes de abrir el socket; una carpeta de salida que no se puede crear es `Internal`. Se rechazan igual los que no caben en 32 bits (puente y `mctl`). Auditoría: `visibility.traps` / `visibility.flows` (configuración efectiva al iniciar), `visibility.traps.retencion` / `visibility.flows.retencion` (cada borrado) y `visibility.traps.done` / `visibility.flows.done` (resumen con los descartes y lo perdido hacia la interfaz).

Diferencias con syslog:

| | Syslog | Traps | Flujos |
|---|---|---|---|
| Qué cuenta la tasa | mensajes | traps (un datagrama cada uno) | **datagramas de exportación**, no registros: uno puede traer decenas de flujos |
| Defaults de tasa | 100/s por origen, 1000/s global | los de syslog | **1000/s por exportador y 5000/s global** (ráfaga 2x), porque un exportador real manda muchos más datagramas que un equipo syslog |
| Cuándo rige el tope | siempre | siempre | **solo con `save`**: sin archivo no se aplica (el resumen en memoria ya está acotado) |
| `nameTemplate` por defecto | `syslog_{fecha}_{hora}` | `traps_{fecha}_{hora}` | `flujos_{fecha}_{hora}` |
| `{origen}` | IP del emisor | IP del agente (sin puerto) | IP del exportador |
| Formato por defecto | `texto` | `texto` (`.log`) | `texto` (`.log`) |

- **Traps.** Un trap sin ficha o con la cola llena se descarta y se cuenta; si era un inform v1/v2c, no se le responde (la respuesta sale solo cuando el trap entró a la cola) y el equipo lo reintenta. `texto`: `RFC3339 ip:puerto <línea>`. `crudo`: solo `<línea>`, el PDU decodificado en una línea de texto: `v2c [inform] <resumen o nombre> OID=valor …` (por ejemplo `v2c linkDown Gi1/0/7 oper down .1.3.6.1.2.1.2.2.1.8.7=2`); si no se pudo decodificar, `error: <motivo> raw=<hex sin la comunidad>`. Los caracteres de control salen como `.`. **Traps v3 sin decodificar**: nunca se guarda el paquete (trae el usuario USM y los parámetros de autenticación, con los que se podría atacar la clave sin conexión); el evento y el archivo traen solo `v3 sin decodificar (N bytes): <motivo>`, sin `raw`, en todos los formatos. `jsonl`: el trap ya interpretado (los mismos campos que el evento `json`).
- **Flujos.** Con `save`, la tasa y los descartes se aplican al datagrama **antes** de decodificarlo: un datagrama descartado por tasa no entra ni al resumen ni al archivo, y si era una plantilla NetFlow v9/IPFIX, los datos que dependen de ella no se decodifican hasta que el exportador la repita. Sin `save` no hay tope ni descartes. Si pasó la tasa pero la cola hacia el archivo estaba llena, el resumen en pantalla sí lo cuenta y el archivo no (queda en `colaLlena`). `texto`: `RFC3339 exportador <línea>`. `crudo`: solo `<línea>`, el registro de flujo en una línea: `tcp 10.0.0.1:51000 -> 10.0.0.2:443 bytes=1500 packets=10 exp=10.0.0.9` (sin puerto si el protocolo no lo tiene). `jsonl`: `{"Time":…,"Exporter":…,"Src":…,"Dst":…,"SrcPort":…,"DstPort":…,"Proto":…,"Bytes":…,"Packets":…}`. El resumen final (`final: true`) llega por la misma cola que el resto y, si el cliente está atascado, puede perderse como cualquier otro evento.

Doble de pruebas: `fakeVisibility()` (ya dentro de `fakeCore()`) tiene `emitVis(kind, e)`; `sampleSyslogDrops` está en `modules/tools/fake.ts`.

## Opciones de traps y flujos en la interfaz (fase 19y)

La vista Visibilidad usa para traps y flujos las mismas piezas que el receptor syslog. Viven en `ui/frontend/src/components/ingest/` y se parametrizan con `kind` (`syslog | traps | flows`): `ingestOpts.ts` (formulario, validación, `buildOpts`, nombre de ejemplo, `rangeOf` y `kindKey`), `IngestOptions.tsx` (bloque «Opciones» plegado con los grupos «Contra inundación» y «Archivos»), `IngestStatus.tsx` (línea de estado y aviso de descartes) y `useIngest.ts` (`useIngestOpts`: formulario, errores de inicio junto a su campo, archivo actual y descartes; `useBatch`: juntado cada 100 ms con tope). `trapsStart` y `flowsStart` mandan `opts` (`{}` = todos los defaults); el resto del contrato es el de la sección anterior.

- **Defaults que muestra la ayuda** («Por defecto N · Rango a–b»): traps igual que syslog (100/s por origen, 1000/s global); flujos 1000 datagramas/s por exportador y 5000/s global (mismos rangos que syslog). Plantillas: `syslog_{fecha}_{hora}`, `traps_{fecha}_{hora}`, `flujos_{fecha}_{hora}`. Formato `texto` en los tres.
- **Flujos sin «Guardar cada flujo en archivo»**: no hay tope ni descartes en el núcleo, así que la vista no muestra los campos de tasa, ráfaga ni cola y no los manda aunque se hayan escrito (se conservan si se activa guardar). Con guardar, la tasa cuenta datagramas de exportación y la ayuda lo dice.
- **Errores de inicio**: un rechazo de `trapsStart`/`flowsStart` y un `done{error}` del stream pasan por el mismo mapeo; si nombran un campo (tasa, ráfaga, cola, rotación, plantilla, formato, dirección) se marcan junto a él y se abren las opciones (no la dirección); si no, van en un aviso.
- **Eventos**: `outputPath` del evento `listening` es la carpeta; `rotatedPath` actualiza «Archivo actual» (con `{origen}` en la plantilla: «Un archivo por origen en <carpeta>»); `drops` pinta el aviso (frase fija en la región viva; cifras y top de orígenes o exportadores fuera de ella). El conteo de la línea de estado son traps recibidos o, en flujos, los flujos contados del resumen.
- **Listas en vivo**: los traps se juntan y pasan a la lista una vez cada 100 ms, que conserva los últimos 5000 (el conteo sigue y un aviso dice qué pasa con los archivos). De los resúmenes de flujos se pinta solo el último de cada ventana.
- **Trap v3 sin decodificar**: el núcleo manda `Error: "v3 sin decodificar (N bytes): <motivo>"`. La fila muestra la etiqueta traducida (`visibility.traps.v3`) y el motivo tal como lo dio el núcleo, que no se traduce.

## Respaldo cifrado de la bóveda (fase 29d)

Exportar todas las credenciales a un archivo cifrado con una frase **distinta de la maestra**, e importarlo después. Nunca forma parte de los exports generales (scripts, colecciones, equipos).

- **Formato.** El respaldo es un archivo de bóveda nuevo (mismo formato que `vault.mcv`), con su propio VaultID, su propia sal y una DEK nueva sellada con la frase del respaldo: no comparte llaves con la bóveda viva. Los parámetros de Argon2id son, como mínimo, los de la bóveda viva. Abrirlo con la maestra falla. Extensión sugerida: `.mcvault`. Las entradas reservadas del sistema (`macuahuitl:*`, p. ej. la llave de las fichas de respaldos) no viajan.
- RPC (`VaultService`): `ExportBackup`, `PreviewBackupImport`, `ApplyBackupImport`. CLI: `mctl cred backup export RUTA [--overwrite] [--yes]` e `import RUTA [--decision ID|ETIQUETA=acción]... [--all=acción] [--preview]`; las frases se leen sin eco o de stdin, nunca como argumento.
- Puente → `core` (módulo `vault`): `exportVaultBackup(path, passphrase, overwrite, confirm): Promise<{ count, noPermissions }>`, `removeEmptyFile(path): Promise<void>`, `previewVaultBackupImport(path, passphrase): Promise<VaultBackupPreview>` y `applyVaultBackupImport(token, decisions): Promise<VaultBackupResult>`. El doble está en `modules/vault/fake.ts` (`sampleVaultBackup`). La vista es `BackupSection` dentro de la vista de la bóveda (solo con la bóveda abierta).

**Export** (`exportVaultBackup(path, passphrase, overwrite, confirm)`): devuelve `{ count, noPermissions }`: cuántas credenciales guardó y si el sistema de archivos (p. ej. una memoria vfat) no admitió los permisos 0600 (el archivo va cifrado igual; la vista lo avisa).
- `confirm: true` es obligatorio; sin ella → `FailedPrecondition` («el respaldo contiene todas tus credenciales…»). La vista lo liga a una casilla.
- `passphrase`: al menos 12 caracteres y distinta de la maestra (se comprueba contra la bóveda viva sin cambiar su estado) → si no, `InvalidArgument`. Bóveda cerrada → `FailedPrecondition`. `path` absoluta; si no, `InvalidArgument`.
- Bóveda cerrada → `FailedPrecondition` **antes** de evaluar la frase: con la bóveda cerrada, una frase igual a la maestra y una distinta dan el mismo error.
- `path` dentro de la carpeta de datos del núcleo (la bóveda, su `.bak` o cualquier archivo ahí, también por enlaces simbólicos) → `InvalidArgument`.
- Si la bóveda tiene parámetros de Argon2id que un respaldo no podría abrir después (más de 1 GiB o 8 hilos) → `FailedPrecondition`.
- Si el export falla después de `pickSavePath`, la vista llama a `removeEmptyFile(path)`, que borra **solo** un archivo regular de 0 bytes en esa ruta exacta (sin seguir enlaces; si ya no existe no es error) para no dejar el archivo vacío del diálogo.
- Archivo 0600, escrito a un temporal contiguo y movido con rename; sin `overwrite` no pisa nada (`AlreadyExists`) y nunca sigue un enlace simbólico; con `overwrite` solo reemplaza un archivo regular (o el enlace, no su destino). Tras `pickSavePath` se llama con `overwrite: true`.

**Import en dos pasos.**
1. `previewVaultBackupImport(path, passphrase)` → `{ token, expiresMs, items }`. No escribe nada. Cada `item` es `{ id, label, username, state }` (nunca secretos); `id` es el de la credencial **dentro del respaldo** y las decisiones van por él. `state`:
   - `nueva`: la etiqueta no existe en la bóveda viva; se importa sola.
   - `igual`: misma etiqueta y mismo contenido (usuario y los tres secretos); se omite sola.
   - `conflicto_etiqueta`: misma etiqueta, otro contenido; pide decisión.
   - `reservada`: entrada del sistema; se omite sola.
   - Errores: no es un respaldo (texto, JSON, vacío, truncado) → `InvalidArgument` «no es un respaldo de bóveda de MACUAHUITL»; frase incorrecta (o archivo alterado, no se distingue) → `PermissionDenied`; archivo inexistente → `NotFound`; bóveda viva cerrada → `FailedPrecondition`.
   - Un respaldo con más de 10 000 credenciales o con parámetros de Argon2id fuera de tope → `InvalidArgument` / «no es un respaldo», sin descifrar nada.
   - El token vale 10 minutos y es de un solo uso. Las credenciales descifradas quedan en el núcleo, en memoria protegida, solo hasta que se aplique, venza el token o se cierre la bóveda (por cualquier vía: botón, inactividad, pantalla bloqueada, suspensión). No hay forma de «descartar» una vista previa: cancelar en la vista solo la cierra y el núcleo la borra al vencer o al cerrar la bóveda.
2. `applyVaultBackupImport(token, decisions)` con `{ id, action }`, `action` = `renombrar` (`<etiqueta> (importada)`, o `(importada 2)`… si ya existe), `reemplazar` (conserva el ID local) u `omitir`. Se vuelve a comparar contra la bóveda viva al aplicar (pudo cambiar tras la vista previa). Cada `conflicto_etiqueta` necesita decisión; falta una, una acción desconocida, un `id` ajeno o una decisión repetida → `InvalidArgument`, **sin escribir nada** y con el token vivo. Dos `reemplazar` hacia la misma credencial local también son una decisión mala. Una decisión sobre `nueva` es válida (`omitir` la salta). Todo o nada: se escribe en una sola operación.
   - Devuelve `{ created, replaced, renamed, skipped, same }`; `skipped` incluye las reservadas.
   - Bóveda viva cerrada al aplicar → `FailedPrecondition`. Cerrar la bóveda descarta la vista previa por seguridad (ya borró lo descifrado), así que el token **no sobrevive**: la vista debe decirlo («La bóveda se cerró y, por seguridad, se descartó la vista previa del respaldo…») y pedir abrir la bóveda y el archivo de nuevo. La vista lo detecta por el **estado** de la bóveda (`vaultStatus`), no por el texto del error, tanto si el cierre llega con la vista previa abierta como si se descubre al aplicar (token desconocido o gastado → `NotFound`; vencido → `FailedPrecondition`; dos aplicaciones a la vez con el mismo token: solo una).

Auditoría: `vault.respaldo.exportar` (ruta y conteo) y `vault.respaldo.importar` (ruta, conteos y decisiones por etiqueta). Nunca secretos, usuarios ni frases.

Límite declarado: las frases llegan del webview como `string` y no se pueden borrar de su memoria; la vista vacía los campos al enviarlas y no las guarda. La sección Datos de Ajustes (`settings.data.body`) todavía dice que el respaldo de la bóveda «no está disponible»: cuando la conecte, que use estas tres llamadas.

## Preferencias del núcleo: carpeta de salidas y defaults de archivo (fase 29e)

Para la pantalla Ajustes. Son preferencias tipadas, aparte de `getPreference`/`setPreference` (que siguen siendo clave/valor de la interfaz y **no pueden escribir** las claves reservadas `core.*`: dan `InvalidArgument`).

- RPC: `PrefsService.GetCorePrefs` y `SetCorePrefs`. CLI: `mctl prefs show [--json]` y `mctl prefs set [--outputs DIR] [--rotate-mb N] [--rotate-min N] [--max-files N] [--format F]` (set cambia solo lo que se pide). Puente: `Bridge.GetCorePrefs()` y `Bridge.SetCorePrefs(CorePrefsDTO)`. TS (`modules/settings/api.ts`): `core.getCorePrefs()` y `core.setCorePrefs(p)`; doble en `modules/settings/fake.ts` (ya dentro de `fakeCore()`).
- `CorePrefs`: `outputsDir` (string; `""` = la de fábrica), `rotateMb`, `rotateMin`, `maxFiles` (`0` = el de fábrica) y `format` (`""` = el de fábrica). `CorePrefsState` agrega `outputsDirEffective` (la que rige hoy), `outputsDirDefault` (`~/MACUAHUITL/outputs`) y `note`.
- **`setCorePrefs` reemplaza todo**: lo que va en 0 o vacío vuelve al de fábrica. Para cambiar un solo campo, léelo con `getCorePrefs` y reenvía los demás.
- Rangos de los defaults (los mismos de syslog, traps y flujos): `rotateMb` 1-1024, `rotateMin` 1-10080, `maxFiles` 1-1000, `format` `texto`, `crudo` o `jsonl`. Fuera de rango es `InvalidArgument` con el motivo en español y no se guarda nada. Los de **tasa** (`rate`, `burst`, `queue`) no son configurables.
- **Carpeta de salidas.** Debe ser absoluta y sin `..`; existir y ser una carpeta (los enlaces simbólicos se siguen y se guarda la ruta ya resuelta); ser del usuario que corre el núcleo; ser escribible; tener modo **exactamente 0700**; no ser `/`, `$HOME`, `/tmp` ni `~/.ssh`, ni estar dentro de las carpetas de datos, configuración, estado o ejecución del núcleo, ni **contener** a alguna de ellas (por eso `~/.local` o `~/.config` se rechazan); y **no colgar de un ancestro que otros puedan escribir** (grupo u otros) y no sea tuyo: `/tmp`, `/var/tmp` y `/dev/shm` caen aquí, porque otro usuario podría reemplazar la ruta tras un reinicio o una limpieza de tmpfiles. **El núcleo no cambia los permisos del usuario**: si la carpeta es más abierta, la rechaza y el mensaje trae la orden (`chmod 700 <ruta>`) para que la vista la muestre y la persona la corra.
- Los rechazos de la carpeta son `InvalidArgument` y el mensaje empieza con un código estable `prefs.outputs.<motivo>: texto`: `relativa`, `punto_punto`, `no_existe`, `ilegible`, `no_directorio`, `otro_dueno`, `reservada`, `permisos`, `ancestro_inseguro`, `no_escribible`. La vista puede mostrar el texto tal cual o, en la fase 30a, traducir por el código.
- **Cuándo aplica.** Lo que empiece después: los trabajos y escuchas en curso conservan la carpeta con que arrancaron. **Los datos de la carpeta anterior no se mueven**, y las vistas que leen de la carpeta vigente (respaldos, historial de syslog, evidencia reciente) dejan de ver los anteriores hasta volver a esa carpeta. Al guardar un cambio de carpeta, `note` trae ese aviso en español; vacío si no cambió. **Las capturas que siguen corriendo** (syslog, traps, flujos, consola, respaldos) escriben en la carpeta vieja hasta terminar, y el análisis, que lee de la vigente, no las ve hasta entonces. Un respaldo en curso guarda sus respaldos y borra su lote temporal en la carpeta con que arrancó.
- **Revalidación al arrancar y avisos.** Al abrir el núcleo se revalida la carpeta guardada (dueño, 0700, ancestros y reservadas; sin la prueba de escritura). Si ya no vale, rige la de fábrica (`outputsDirEffective` lo dice, `outputsDir` sigue mostrando lo guardado), queda una entrada `prefs.core` en la auditoría con el motivo y `note` de `getCorePrefs` lo avisa. Lo mismo si la persona guarda solo los defaults de ingest con la carpeta guardada ya inválida: el cambio de ingest se aplica, no se rechaza, y `note` avisa; al corregir la carpeta y volver a guardar, rige otra vez.
- Los defaults de archivo rigen cuando la petición deja el campo en 0 o vacío (`syslogStart`, `trapsStart`, `flowsStart` con `{}`); lo explícito en `opts` los ignora. Persisten entre reinicios del núcleo.
- Auditoría: `prefs.core` con cada campo cambiado, `campo: anterior -> nuevo` (rutas sí; no se audita si nada cambió).

## Hallazgos del 3560CX (fase 31)
- **Fase `JOB_PHASE_KIND_ARM_CHECK_DONE` (11).** El Login Test que `ArmJob` repite, sin interacción, justo antes de armar. El Login Test manual sigue registrando `LOGIN_TEST_DONE`; un trabajo armado trae cada una una vez. Etiqueta `patrol.phase.ARM_CHECK_DONE`.
- **`getRun` manda el puerto efectivo.** `devices[].target.port` es el puerto con que se conectó (0 en la spec sale como 22); la vista ya no muestra `host:0`.
- **`output_dir` y carpetas del cliente se validan como la de Ajustes.** `createJob` (`outputDir`) y `diag.run` (`outputDir`) rechazan una carpeta explícita con `InvalidArgument` y el mismo código `prefs.outputs.<motivo>: texto` de 29e (absoluta, sin `..`, existe, del usuario, 0700, ancestros sin escritura para todos, no `/`, `$HOME`, `/tmp`, datos ni config). La carpeta debe existir: el núcleo no la crea. Vacío = la vigente (`outputs/`, `outputs/diag`). Las carpetas de destino de `transfer` (`recvDir`, `destDir`) no pasan por esta validación: son el destino que elige la persona, por ejemplo `~/Descargas`.
- **Campo `platforms` por comando de un playbook.** Opcional: `platforms: [ios-xe]` hace que el comando solo corra si la plataforma detectada está en la lista; vacío = en todas las compatibles. Una plataforma desconocida hace fallar la carga con el nombre del archivo. El comando omitido no corre y queda en el `manifest.json`, en `devices[].Skipped` (texto de cada comando omitido por plataforma). `devices[].ran` (opcional): IDs de los gemelos que de verdad corrieron cuando difieren de los elegidos. `dir bootflash:` lo lleva en `upgrade-check`, `plat-flash-fs`, `flota` y `plat-reloads-crashinfo`. `listPlaybooks` con `platform: ios` devuelve los de `ios-xe` (misma regla que al ejecutar) y sin los comandos que ahí no corren.
- **FTP: ruta remota con `/` inicial = absoluta** (decisión del 2026-11-12), igual que SCP y SFTP; sin `/` es relativa a la carpeta de inicio. En la URL la absoluta lleva `//` (`ftp://host//x/y`); la vista la arma así (`buildURL`) y `getMany` conserva el `//` de la carpeta del lote. El campo de listado `path` ya iba tal cual (`CWD /x/y` absoluta, `CWD x/y` relativa).
- **Tipo de trabajo (`kind`).** `JobSpec.kind` (15) y `JobSummary.kind` (14), y `kind` en el DTO de `listJobs` del puente. Valores cerrados: `patrol` (vacío en la spec = patrol), `adhoc`, `backup`, `change`; cada servicio pone el suyo y `createJob` rechaza otro valor con `InvalidArgument`. Se persiste con el trabajo; uno guardado antes de la fase sale como `patrol`. El resumen siempre trae un valor (nunca vacío).

## Idioma del núcleo: errores con código estable, fases y nombres de playbooks (fase 30a)

Paso 1 de 3 del inventario `docs/plans/2026-11-07-idioma-nucleo.md`: la infraestructura y los primeros códigos. El núcleo ya no obliga a leer su texto en español para saber qué pasó: cada error migrado lleva un **reason** estable y su **metadata**, y con el idioma pedido el texto sale en inglés.

### Regla de compatibilidad
Sin el metadato `accept-language`, o con `es` (o con cualquier idioma que no sea `en`), cada respuesta del núcleo es **idéntica byte por byte** a la de antes de la fase: mismos mensajes de error, mismos detalles de fase, mismos nombres. Lo único que cambia son campos nuevos (`reason`, `args`, la metadata del error). Lo fijan pruebas de regresión con el texto en español literal. El front puede seguir parseando texto mientras no encienda la bandera.

### Cómo se activa: `core.localize`
- La bandera vive en el puente: `Bridge.Localize` (Go), apagada por omisión. En `ui/main.go` es la constante `coreLocalize` (`false`); la sesión de front la pasa a `true` cuando termine de migrar. Para probar sin recompilar: `MACUAHUITL_CORE_LOCALIZE=1` al lanzar la app.
- Encendida, **toda** llamada y todo stream del puente lleva `accept-language` con el valor de la preferencia `ui.language` (`es` o `en`; sin valor guardado o desconocido = `es`). El puente la lee una vez y la mantiene al día cuando `setPreference("ui.language", v)` pasa por él; si la interfaz no guarda esa preferencia, no hay idioma que mandar y todo sale en español.
- `ui.language` es una clave nueva de `getPreference`/`setPreference` (la lista cerrada la acepta; el núcleo solo guarda `es` o `en` y rechaza cualquier otro valor con `InvalidArgument`).
- El núcleo acepta `es`, `en`, `es-MX`, `en-US`… y listas con `q` (`fr, en;q=0.8` da `en`); ausente o desconocido es `es`.
- **La auditoría no depende del idioma** (decisión del 2026-11-12, rama 30a-2): su detalle irá fijo en inglés; esta fase no toca sus textos y la infraestructura no los pasa por el catálogo.
- CLI: `mctl --lang es|en` (también `-lang`, `--lang=en` y etiquetas como `en-US`) es una bandera global que solo vale **antes** del comando; un valor que no sea idioma es un error (no se come el nombre del comando). **mctl no lee `LC_ALL`, `LC_MESSAGES` ni `LANG`**: mientras sus textos propios sigan en español, pedir un idioma solo con `--lang` evita mezclarlos; sin la bandera todo sale en español.

### Forma exacta del error en TS
Todo método del puente que devuelve `error` rechaza la promesa con un `RuntimeError` de Wails cuyo `message` es el texto de siempre (`rpc error: code = X desc = …` para lo que viene del núcleo) y cuyo **`cause`** es:

```ts
interface CoreError {
  message: string;                   // el mismo texto que e.message
  code: string;                      // código gRPC por nombre: "InvalidArgument", "AlreadyExists"…; "" si no vino del núcleo (p. ej. «núcleo desconectado»)
  reason: string;                    // motivo estable de abajo; "" si el error aún no tiene código
  metadata: Record<string, string>;  // argumentos del motivo; {} si no hay. Nunca trae secretos ni valores de campos secretos
}
// const info = (e as { cause?: CoreError }).cause;
```
`reason` y `metadata` salen del `ErrorInfo` (`domain: "macuahuitl"`) que el núcleo agrega a los detalles del error gRPC junto con un `LocalizedMessage`. Un error sin reason sigue siendo texto en español (o el del idioma pedido, si ya tiene código).

**Eventos de cierre de los streams.** Los RPC de servidor (syslog, traps, flujos, diag, consola, serve, transferencias, terminal y asistente) devuelven su error de validación en el primer `Recv()`, y el puente lo emite en el evento `*:done` (`syslog:done`, `traps:done`, `flows:done`, `diag:done`, `console:done`, `serve:done`, `transfer:done`, `terminal:done`, `assist:done` y `transfer:finished`) como `{runId, error, errorInfo, ...}`. `error` sigue siendo el texto de siempre; `errorInfo` es `{code: string, reason: string, metadata: Record<string,string>}` (la misma forma que `CoreError` sin `message`; `metadata` nunca es `null`) y solo está cuando hay `error`.

### Reasons y metadata de esta fase
| reason | code gRPC | metadata |
|---|---|---|
| `ingest.invalid` | `InvalidArgument` (al validar; `Unavailable` si lo detecta la escucha ya abierta) | `field` y, según el campo, `min`, `max`, `value`, `template_problem` |
| `file.exists` | `AlreadyExists` | `path` |
| `assist.invalid_value` | `InvalidArgument` | `template`, `field` y `why` del **primer** problema |
| `assist.refused` | `FailedPrecondition` | `template` (id de la plantilla del catálogo, el mismo que en `assist.invalid_value`; `vlan`, `trunk` y `svi` para esos snippets) y `device` |

- **`ingest.invalid`** (syslog, traps SNMP, flujos y los defaults de `setCorePrefs`). `field` ∈ `rate_per_source`, `burst_per_source`, `rate_global`, `burst_global`, `queue_size` (con `min`, `max` y `value`), `rotate_mb` (`min` 1, `max` 1024), `rotate_minutes` (1, 10080), `max_files` (1, 1000), `format` (con `value`), `protocol` (con `value`; solo syslog), `addr` (dirección de escucha: formato, puerto, privilegiado, host, todas las interfaces) y `name_template`; además `dir` si falta la carpeta de salida (no lo manda la interfaz). Para `name_template` viene `template_problem` ∈ `len` (con `min` 1 y `max` 64), `need` (falta `{fecha}` o `{hora}`), `tokens`, `chars` (con `ch`, el carácter) y `dots`. Reemplaza el `grep` de «tasa por origen», «plantilla», «dirección inválida»… de `ingestOpts.ts`.
- **Sinónimos de la plantilla del nombre:** `{date}`, `{time}` y `{source}` valen igual que `{fecha}`, `{hora}` y `{origen}`, en la validación, en el nombre del archivo y en la retención (que reconoce los archivos de la misma plantilla escrita de cualquiera de las dos formas, y también mezclada). Siguen siendo sintaxis del usuario; el núcleo no las traduce en lo que escribe.
- **`file.exists`**: los export de scripts, colecciones, hosts y respaldo de bóveda con `overwrite: false`, y `writeFile` del puente. Reemplaza `/ya existe/` de `lib/core.ts`: usa `reason === "file.exists"`. Los textos de hoy se conservan (`el archivo ya existe`, `vault: el archivo de respaldo ya existe`, `guardar: el archivo ya existe`).
- **`assist.invalid_value`**: `why` ∈ `required`, `range`, `pattern`, `choice`, `type`, `unknown_field`. El texto junta todos los problemas con «; » y lleva el prefijo `assist: valores del snippet inválidos: ` (en inglés, `assist: invalid snippet values: `); la metadata describe solo el primero. Los secretos nunca van en la metadata ni en el texto. **`assist.refused`**: el texto es `assist: el equipo no admite este snippet: <motivo>`; el motivo concreto sigue en español hasta su fase de traducción (pasos 2 y 3).

**Prefijos de envoltorio.** Con `en` el mensaje es el del catálogo y se pierden los prefijos con que otras capas envuelven el error (`flows: `, `snmp traps: `, `syslogd: ` cuando no es parte del texto). Con `es` el texto es el de siempre, envoltorios incluidos. La interfaz no debe depender de esos prefijos: use `reason` y `metadata`.

### Detalle de las fases del Job
- `JobPhase` gana `reason` y `args` (campos 5 y 6, sin renumerar); el puente los expone en `PhaseDTO` como `reason` y `args` (ausentes si la fase no lleva detalle) y en los eventos `phaseAdded` (protojson).
- `detail` sigue siendo el texto de hoy en `es` y sale traducido con `en`. Las fases guardadas antes de esta fase no traen `reason` y salen siempre en español.
- Reasons y args: `phase.devices {n}`, `phase.devices_excluded {n, excluded}`, `phase.ok_failed {ok, failed}`, `phase.rounds {n}`, `phase.packaged {path}`, `phase.round_zip_failed {error}`, `phase.close_failed {error}`, `phase.before_arming {}`, `phase.core_stopped {}`. (`error` y `path` vienen tal cual del sistema; no se traducen.)
- Quedan fuera de esta fase, y siguen en español: `DeviceStateChanged.detail`, los `detail` de los equipos de `GetRun` y los motivos de los demás servicios del inventario.

### Nombres de playbooks
Los YAML de `playbooks/` llevan `name_en` (obligatorio en los incrustados; una prueba falla si falta). `listPlaybooks` devuelve `name` en el idioma del contexto: `es` es el nombre de siempre y `en` es `name_en`, con la misma separación « · » entre el área y el nombre, así la agrupación del selector no cambia. Un playbook del usuario sin `name_en` sale con su nombre en los dos idiomas.

## Auditoría siempre en inglés (fase 30a-2)
- El `detail` de cada registro de auditoría se escribe en inglés fijo, con formato `clave=valor` (`passed=1 of 2`, `reason=user`, `guard=revoked`, `devices=2`). No depende de `accept-language` ni de ningún idioma del cliente.
- La acción (`job.logintest`, `vault.respaldo.exportar`, `hosts.importar`, …) no cambia: sigue siendo el identificador fijo que usan la interfaz y las búsquedas, aunque lleve palabras en español.
- Los valores que son datos (rutas, IPs, usuarios, ids, nombres) salen tal cual. Los verbos de decisión de importación (`reemplazar`, `renombrar`, `omitir`, `fusionar`) siguen siendo así en el cable y se auditan como `replace`, `rename`, `skip` y `merge`.
- Cuando el detalle lleva el texto de un error del núcleo con código del catálogo, sale el texto en inglés del catálogo. Un error sin código se audita con su texto original (puede estar en español): es el caso de los mensajes de errores de otras capas, de las advertencias de respaldo y del `detail` de equipos que ya traen los trabajos.
- Los registros anteriores a esta fase no se reescriben (la cadena de hashes no se toca): una misma bitácora mezcla detalles en español (viejos) y en inglés (nuevos), y `audit verify` sigue íntegro.
- La interfaz no interpreta el detalle de auditoría (la vista solo verifica la cadena y copia el comando de exportación), así que no hay cambio de pantalla. Quien lea la exportación por su cuenta debe aceptar las dos formas para los registros anteriores: por ejemplo `razon=`/`reason=`, `pasaron=1 de 2`/`passed=1 of 2`, `guard=revocado`/`guard=revoked`.


## Datos estructurados: calculadoras, seguridad y captura (fase 30b)

Paso 2 de 3 del inventario `docs/plans/2026-11-07-idioma-nucleo.md`. Los tres módulos que dibujaban sus tarjetas leyendo el español del núcleo (`security/parse.ts`, `calc/bars.ts`, `tools/pcapParse.ts`) reciben los mismos datos en forma estructurada, con claves estables. Esta fase no toca la vista: la migración es de la sesión de front.

### Reglas
- **Compatibilidad.** Sin `accept-language`, o con `es`, el texto de siempre (`text`, `json`, tablas, notas) es idéntico byte por byte; lo fijan pruebas de regresión por RPC y por dominio. Solo se suman campos de proto (sin renumerar) y de DTO (con `omitempty`). Los métodos de texto del puente (`secRadius`, `secTacacs`, `secPkiDecode`, `toolsPcap`) no cambian.
- **Con `en`** el texto de esos RPC y los campos `text`/`message`/`title` salen en inglés. La bandera `core.localize` de 30a decide si el puente manda el idioma.
- **Claves y valores.** Títulos, encabezados, etiquetas de fila, notas y avisos viajan como clave del catálogo (`internal/i18n`) con sus `args`; los **valores** (IPs, cifras, fechas, nombres, atributos del servidor) viajan tal cual y no se traducen.
- **Códigos cerrados en inglés:** `severity` ∈ `warning`, `error`, `info` (el texto en español sigue diciendo `aviso`); `messageAuthenticator` ∈ `absent`, `valid`, `invalid`; `direction` ∈ `sent`, `received`; `kind` de un certificado ∈ `certificate`, `csr`. `lib/vocab.ts` mapea hoy `aviso`/`ausente`/`válido`/`inválido`: la vista que migre debe pasar a estos códigos.
- **Sin secretos.** Ningún campo nuevo trae el secreto compartido, la contraseña, llaves privadas ni sus longitudes (una prueba lo verifica).

### Puente (métodos nuevos y campos nuevos)
| Método / DTO | Devuelve |
|---|---|
| `calc(kind, req)` → `CalcResultDTO` | gana `notesStructured` y, en cada tabla, `titleKey`, `titleArgs`, `columns`, `rowLabels` |
| `secRadiusReport(RadiusDTO)` → `RadiusReportDTO` | `text`, `server`, `method`, `exchanges`, `findings` |
| `secTacacsReport(TacacsDTO)` → `TacacsReportDTO` | `text`, `server`, `steps`, `findings` |
| `secPkiDecodeReport(text)` → `PkiReportDTO` | `text`, `certificates` |
| `secPkiCsr`, `secPkiCaInit`, `secPkiCaSign` → `PkiResultDTO` | ganan `certificates` y `labWarning` (con `omitempty`) |
| `toolsPcapReport(path, top)` → `PcapReportDTO` | `text` y todas las secciones de abajo |

En TS los métodos nuevos son opcionales en `SecurityAPI` y `ToolsAPI` (`secRadiusReport?`…), y los tipos nuevos de `api.ts` son opcionales en `CalcResult`/`CalcTable`.

### Calculadoras
```ts
interface CalcKey { key: string; args?: Record<string,string> }
interface CalcTable {
  title: string; head: string[]; rows: string[][];      // lo de siempre, en el idioma pedido
  titleKey?: string; titleArgs?: Record<string,string>; // calc.title.*
  columns?: CalcKey[];                                  // una por celda de head (calc.col.*)
  rowLabels?: CalcKey[];                                // una por fila (calc.row.*); key "" si la primera celda es un dato
}
interface CalcResult { text: string; tables: CalcTable[]; notes: string[]; notesStructured?: CalcKey[] } // calc.note.*, mismo orden que notes
```
Las etiquetas de fila viven en las tablas campo/valor (subred, conversión, ACL, IPv6, TCP, presupuesto óptico, potencia, resultado de MTU) y en las filas fijas «Exacta/Una sola ruta» de la sumarización y las de pérdidas de óptica; el valor es la última celda. En las demás tablas (VLSM, octetos, DSCP, desglose de MTU, BGP) lo fijo son las columnas.

- **Subred** (lo que lee `bars.ts`): título `calc.title.subnet {prefix}`; filas `calc.row.network`, `broadcast`, `first_usable`, `last_usable`, `addresses`, `usable_hosts`, `prefix`, `mask`, `wildcard`, `class`, `kind`.
- **VLSM:** título `calc.title.vlsm {parent}` (el largo del prefijo es lo que sigue a `/` en `parent`); columnas `calc.col.name`, `hosts`, `prefix`, `mask`, `first`, `last`, `broadcast`, `capacity`, `waste`; notas `calc.note.vlsm_free {free}` (prefijos separados por espacio, como en el texto) y `vlsm_unplaced {names}`.
- **Claves, por área:**
  - Títulos: `calc.title.{subnet, vlsm, summary, conversion, acl, octets, covered, covered_partial, ipv6, tcp, dscp, losses, budget, power, mtu_breakdown, result, bgp_routes, bgp_comparisons}`.
  - Columnas: `calc.col.{field, value, name, hosts, prefix, prefixes, mask, first, last, broadcast, capacity, waste, type, octet, wildcard, binary, matching, dscp, tos, tos_hex, precedence, cos, exp, af_drop, class, item, quantity, loss, layer, detail, bytes, remaining, route, weight, local_pref, local, as_path, origin, med, igp, router_id, cluster, neighbor, age, next_hop, comparison, step, value_a, value_b, winner}`.
  - Filas: `calc.row.{network, broadcast, first_usable, last_usable, addresses, usable_hosts, prefix, mask, wildcard, class, kind, exact, single, matches, first, last, equals, prefixes_needed, abbreviated, expanded, eui64, interface_id, mac_eui64, solicited, ptr, link, rtt, bdp, window_scale, window_limit, loss_limit, max_flow, limited_by, fiber, connectors, splices, total, tx, rx_sensitivity, budget, rx_expected, margin, spare, verdict, dbm, mw, overhead, effective_mtu, ip_mtu, adjust_mss, physical_1500}`.
  - Notas: `calc.note.{host_in_subnet, p2p_v6, anycast_v6, single_host, p2p_v4, vlsm_unplaced, vlsm_free, summary_covered, summary_extra, wildcard_host_bits, wildcard_noncontiguous, ipv6_eui64_mac, tcp_bdp, tcp_window_limit, tcp_loss_limit, tcp_single_flow, dscp_cos_map, dscp_rfc4594, optics_overload, optics_short, optics_typical, mtu_ipv6_min, mtu_outer_tag, mtu_esp_padding, mtu_vxlan, bgp_winner, bgp_local_weight, bgp_excluded, bgp_det_med, bgp_no_det_med, bgp_always_med, bgp_med_same_as, bgp_multipath, bgp_multipath_relax, bgp_unvalidated}`.
- **Siguen en español con `en` (cambia en 30c-A, ver abajo):** los valores con palabras (`Lo limita`: «ventana»/«pérdida»; el veredicto óptico; `Tipo` y `Clase` de una dirección; las clases de DSCP; los pasos de BGP; «sí/no», «accesible/inaccesible» y los nombres de capa de MTU). Son datos del cálculo, no etiquetas.

### Seguridad
```ts
interface SecText { key: string; args?: Record<string,string>; text: string }          // text en el idioma pedido
interface SecFindingData { code: string; severity: "warning"|"error"|"info"; args?: Record<string,string>; message: string }
interface RadiusReportData { text; server; method?: string /* PAP, CHAP, MSCHAPV2 como en el texto */;
  exchanges: { kind; code?; rttMs; attempts; messageAuthenticator?: "absent"|"valid"|"invalid"; error?: SecText; attrs: {name; value}[] }[]; findings: SecFindingData[] }
interface TacacsReportData { text; server /* host:puerto */;
  steps: { kind; status?; rttMs; error?: SecText; prompts: string[]; message?; data?; avPairs: { direction: "sent"|"received"; value }[] }[]; findings: SecFindingData[] }
interface Certificate { kind: "certificate"|"csr"; subject; issuer?; serial?; notBefore?; notAfter?; daysLeft?: number;
  key: { algorithm /* RSA, ECDSA */; bits; curve?; description /* «RSA 2048» */ }; signature: { algorithm; valid?: boolean /* solo CSR */ };
  san: string[]; keyUsage: string[]; extKeyUsage: string[]; isCa: boolean; selfSigned: boolean; sha1?; sha256?;
  warnings: { code; args?; message }[] }
interface PkiReportData { text; certificates: Certificate[] }
```
- Un intercambio sin respuesta no trae `code`; un paso sin respuesta no trae `status`. `avPairs` guarda el orden: primero lo enviado y luego lo recibido, igual que en el texto.
- **`findings[].code`** (identificadores estables, en español como los de hoy; cambia en 30c-A, ver abajo: pasan a inglés): RADIUS `sin-respuesta {kind, port}`, `respuesta-invalida {kind, error}`, `blast-radius {kind}`, `ma-invalido {kind}`, `reject {reply}` (sin `reply` si el servidor no mandó Reply-Message); TACACS+ `secreto {kind}`, `sin-respuesta {kind, error, port}`, `authen-fail`, `author-fail`, `estado {kind, status, message}`. El `error` de los argumentos va en el idioma pedido.
- **`error.key`**: `security.radius.err.{system {error}, unauth {code}, no_response {attempts, timeout}}` y `security.tacacs.err.{system {error}, closed, out_of_sequence {session, type, seq}, unencrypted, bad_secret, too_many_prompts}`. `system` es un texto del sistema (por ejemplo «connection refused») y no se traduce.
- **`warnings[].code`** de un certificado: `rsa_small`, `weak_sig {algorithm}`, `no_san`, `expired`, `not_yet`, `expires_soon {days}`, `self_signed`, `csr_signature`.
- Claves del texto del informe: `security.{severity, ma}.*`, `security.findings_head`, `security.{yes, no}`, `security.radius.{text, err, finding}.*`, `security.tacacs.{text, err, finding}.*`, `security.pki.{kind, label, warn}.*`, `security.pki.validity` y `security.pki.lab_warning`.
- `labWarning` (en `PkiResult`) indica que el texto abre con el aviso de CA de laboratorio.
- **Siguen como vienen del servidor:** los valores de los atributos RADIUS (incluido el veredicto de MS-CHAP2-Success y «(truncado)»), los mensajes y datos del servidor TACACS+ y los nombres de usos de llave.

### Captura (pcap)
```ts
interface PcapReportData { text;
  summary: { file; packets; bytes; durationMs; start /* RFC 3339 UTC */ };
  conversations: { proto; a; b; packets; bytes }[];          // las del texto, en su orden
  topTalkers: { ip; packets; bytes }[];
  protocols: { proto; packets; bytes }[];                     // suma de conversations por proto, de más a menos bytes (lo que hoy calcula pcapParse.ts)
  neighbors: { protocol /* cdp, lldp */; deviceId; port; platform; mgmtIp; nativeVlan }[];
  tcp: { handshakes; rttMinMs; rttAvgMs; rttMaxMs; retransmissions; zeroWindow; failedHandshakesTotal; failedHandshakes: {client; server; count /* intentos */}[]; resets: {client; server; count}[] };
  dns: { queries; responses; errors; slow; unanswered: { client; server; name; type; rcode?; latencyMs }[] };
  tls: { client; server; sni }[]; icmp: { unreachable; ttlExceeded: { from; target; code }[] };
  arpConflicts: { ip; macs: string[] }[]; fragments: number;
  warnings: { key; args?; text }[];                           // pcap.warn.*
  sections: { key; args?; title }[] }                         // encabezados que imprime el texto, en orden
```
- `sections[].key` ∈ `pcap.section.{neighbors, tcp, dns, tls, icmp, arp_conflict {ip, macs}, conversations, top_talkers}`; `title` es el encabezado en el idioma pedido (sin el «== »). El front deja de buscar «== Conversaciones» y usa `conversations` y `topTalkers`.
- Avisos: `pcap.warn.truncated {packets}`, `pcap.warn.interrupted {packets, error}` (`error` es del sistema), `pcap.warn.flow_limit {max}`.
- Frases del texto: `pcap.text.*` (no las necesita la vista; salen en el `text`).
- Los números de 64 bits viajan como número JSON (exactos hasta 2^53).

### Qué cubre cada archivo del front
- `security/parse.ts`: servidor, método, intercambios (tipo, código, RTT, intentos, estado del Message-Authenticator, error, atributos), pasos TACACS+ (estado, RTT, error, preguntas, mensaje, datos, enviado/recibido), hallazgos (severidad y detalle) y los certificados (sujeto, emisor, serie, vigencia y días, llave, firma, SAN, CA, huellas, avisos), más lo nuevo (usos de llave, autofirmado, validez de la firma del CSR).
- `calc/bars.ts`: título de la subred y del VLSM, las filas por clave, el prefijo y largo del padre, las columnas por clave y el espacio libre (`calc.note.vlsm_free`).
- `tools/pcapParse.ts`: equipos con más tráfico, conversaciones y protocolos.
- **No cubierto:** ver los «Siguen en español con `en`» de cada módulo; además, los errores de validación que rechazan la petición (`InvalidArgument`) siguen su propio camino de 30a, y IKE, DNS y TLS de `tools` quedan para otra fase (cambia en 30c-A, ver abajo).

## Asistente de cambios y snippets en el idioma pedido (fase 30c, bloque B)

Cubre `internal/assist` y `internal/service/assist`. Compatibilidad: sin `accept-language`, o con `es`, todo texto es idéntico byte por byte (lo fija un golden de regresión por RPC). La auditoría no cambia. Las líneas de configuración de IOS y los comandos `show` no se traducen; tampoco las IP, interfaces, VLAN, usuarios ni nombres, que viajan como argumentos.

### Campos nuevos
- `AssistDevicePlan.notes_structured` (campo 8; en el puente `notesStructured`, ausente si no hay): una `{key, args}` por aviso, en el mismo orden que `notes`. `notes` sale en el idioma pedido. En TS: `DevicePlan.notesStructured?: AssistNote[] | null`.
- Claves `assist.note.*`: `errdisabled`, `port_mode`, `port_mode_same {port, mode}`, `speed_duplex`, `snmpv3`, `vty_acl {acl, ip1, what1}` y `vty_acl_two {acl, ip1, what1, ip2, what2}`. `what1` y `what2` valen `"1"` (la IP que ve el equipo) o `"2"` (la IP local de la app); el catálogo escribe la frase en cada idioma.
- `AssistRunState.fail_reason`, `AssistEvent.text` del evento `fail` y `PlanRestoreResponse.reason` salen en el idioma pedido. `AssistEvent.text` de los eventos `output` es salida del equipo y no se traduce.

### Códigos nuevos (reason y metadata)
Los códigos con argumentos declaran sus `args` en el catálogo; la metadata solo trae esos argumentos (nunca secretos: la community, las contraseñas y los hashes no se citan).
- **`assist.refused`** (ya existía): su motivo concreto ahora también se traduce; su texto y su metadata (`template`, `device`) no cambian. Los textos en inglés ya existentes de `assist.invalid_value`, `assist.refused` y sus piezas no se tocaron.
- **`assist.port_refused`**, **`assist.rotate_refused`** y **`assist.restore_refused`** (`FailedPrecondition`): antes sin reason. El texto es `<centinela>: <motivo>`; metadata vacía.
- **Estado de la ejecución** (`FailedPrecondition`): `assist.not_assisted`, `assist.bad_state`, `assist.no_pending`, `assist.wrong_step`, `assist.wrong_step_why` y `assist.bad_state_why` (con la razón detrás de `: `).
- **Errores de armado** (`InvalidArgument`): `assist.err.*`, con nombres estables en inglés (por ejemplo `assist.err.nothing_to_change`, `assist.err.not_physical_port {port}`, `assist.err.interface_required`, `assist.err.output_missing {command}`, `assist.err.vlan_range {vlan}`). El reason es el propio código.
- **Errores del servicio**: `assist.svc.*` (bóveda cerrada, objetivo, plan inexistente o usado, ejecución inexistente, respaldos no restaurables…), con el código gRPC de siempre.
- Los motivos de cada negativa viven en `assist.refused.*`, `assist.port_refused.*`, `assist.rotate_refused.*` y `assist.restore_refused.*`; viajan dentro del mensaje, no como reason.

### Qué no cambió
- Con `en`, los errores con código pierden los prefijos de envoltorio de otras capas (como en 30a).
- La forma del error de `assist.invalid_value` que reconoce `mapInvalid` del front («campo: …» y «campo is required») no cambió.

### No cubierto
- Los motivos por línea de la restauración por diff (`RestoreRefusal.why`, sus ~45 frases) siguen en español: viajan como texto plano por todo el motor y cambiarlos exige un tipo nuevo; queda para otra fase.
- Los errores de validación internos del plan (`ErrInvalidPlan`, las funciones `Check`/`CheckDevice` y los `parse*Line`) siguen en español: solo se disparan ante un fallo del propio núcleo, no por entrada del usuario.
- `rotate.go` del servicio (errores de la bóveda al rotar) y las partes de `fail_reason` que repiten texto de otra capa (`%v` de un error sin código) siguen como vienen.

### Revisión del bloque B
- **Descripción no válida** (la de `PlanPorts` y la del SVI): reason `assist.err.description_invalid` con metadata `{field: "description"}`; ya no usa `assist.invalid_value` ni lleva `why`.
- **Texto de auditoría de los fallos:** el detalle de `assist.fail` (lo que arma `failT`/`failMsg`) sale ahora en inglés completo, también cuando el fallo cita fallos del post-check o errores con código del catálogo.
- **Eventos del motor:** los textos propios del motor que viajan como evento `output` (`assist.run.matches_baseline`, `assist.run.rollback_failed_matches`, `assist.run.post_check_after_rollback`, `assist.run.vault_not_restored`) salen en el idioma pedido; la salida del equipo no se traduce.

## Valores de las calculadoras, RADIUS/TACACS+, DNS, TLS e IKE (fase 30c, bloque A)

Bloque A del paso 3 de 3 (`docs/plans/2026-11-12-fase-30c-idioma-resto.md`). Misma regla de compatibilidad que 30a y 30b: sin `accept-language`, o con `es`, el texto y el JSON de cada RPC son idénticos byte por byte a los de antes (lo fijan pruebas de regresión con golden generado antes del cambio), con **una excepción deliberada**: los `code` de hallazgo de RADIUS y TACACS+ pasan a inglés (ver abajo). Lo demás son campos nuevos (proto sin renumerar; DTO con `omitempty`). Con `en` el texto sale en inglés; la bandera `core.localize` decide si el puente manda el idioma. Esta fase no toca ninguna vista: no hay claves nuevas en `i18n/{es,en}.ts`.

### Cambio que rompe: slugs de hallazgo de RADIUS y TACACS+
`findings[].code` de `secRadiusReport` y `secTacacsReport` (y el `Code` del JSON del informe de texto) cambian. **El front debe cambiar los slugs que compare**:

| Antes | Ahora | Prueba |
|---|---|---|
| `sin-respuesta` | `no_response` | RADIUS y TACACS+ |
| `respuesta-invalida` | `invalid_response` | RADIUS |
| `blast-radius` | `blast_radius` | RADIUS |
| `ma-invalido` | `ma_invalid` | RADIUS |
| `reject` | `reject` (igual) | RADIUS |
| `secreto` | `secret` | TACACS+ |
| `authen-fail` | `authen_fail` | TACACS+ |
| `author-fail` | `author_fail` | TACACS+ |
| `estado` | `status` | TACACS+ |

Los argumentos de cada código no cambian. `severity` ya era cerrada en inglés (30b).

### RADIUS: `mschap2Verified`
`RadiusExchangeData` gana `mschap2Verified?: boolean`: solo aparece en MS-CHAPv2 (en la solicitud de acceso), `true` si el `MS-CHAP2-Success` verificó al servidor (autenticación mutua) y `false` si llegó y no verificó. Ausente en PAP, CHAP, Status-Server y contabilidad, y también en MS-CHAPv2 cuando no llega `MS-CHAP2-Success` (la contraseña se rechazó o el servidor no respondió). Antes solo estaba en el texto del atributo; el atributo `MS-CHAP2-Success` sigue trayendo ese texto del servidor, sin traducir.

### Calculadoras: celdas con código
Los valores con palabras dejan de ser texto libre: viajan como código cerrado y su texto sale traducido. `CalcTable` gana `rowCoded?: CalcCoded[][]`, una lista por fila (vacía si ninguna celda de esa fila es un código); falta si la tabla no tiene ninguna.
```ts
interface CalcCoded { col: number; key: string; args?: Record<string,string> } // col desde 0; key calc.val.*
```
La celda de `rows` ya viene en el idioma pedido; la clave dice qué es. El `json` de cada calculadora no cambia (sigue en español: `"limit":"ventana"`); el código está en la clave de la celda.

| Valor | Dónde | Claves `calc.val.*` |
|---|---|---|
| Veredicto óptico | fila `calc.row.verdict` | `verdict.closes`, `verdict.closes_overload`, `verdict.not_closes`, `verdict.not_closes_overload` |
| «Lo limita» (TCP) | fila `calc.row.limited_by` | `limit.link`, `limit.window`, `limit.loss` |
| sí/no | columna «Local» de las rutas BGP y los valores del paso «originada localmente» | `yes`, `no` |
| next-hop | última columna de las rutas BGP | `nexthop.reachable`, `nexthop.unreachable` |
| Tipo de dirección o prefijo | fila `calc.row.kind` (subred e IPv6) | `kind.*`: `any`, `this_network`, `private`, `cgnat`, `loopback4`, `linklocal4`, `ietf_protocol`, `doc4`, `relay6to4`, `benchmark`, `mcast_local`, `mcast_ssm`, `mcast_admin`, `mcast4`, `limited_bcast`, `reserved`, `mixed`, `public`, `unassigned6`, `unspecified`, `loopback6`, `v4mapped`, `nat64`, `discard`, `teredo`, `doc6`, `sixtofour`, `global6`, `ula`, `linklocal6`, `sitelocal`, `solicited_node`, `mcast6` y `mcast6_{1,2,3,4,5,8,e}` (alcance) |
| Clase DSCP y descarte AF | últimas columnas de la tabla DSCP | `dscp.*` (`none`, `default`, `le`, `scavenger`, `high_volume`, `oam`, `low_latency`, `cs3`, `streaming`, `realtime`, `video_conf`, `cs5`, `voice_admit`, `voice`, `network`, `cs7`) y `drop.{low,medium,high}` |
| Paso de BGP | columna «Paso» de las comparaciones, y el argumento `step` de la nota `calc.note.bgp_winner` | `step.{weight, local_pref, local_origin, as_path_len, origin, med, ebgp_over_ibgp, igp_metric, oldest_ebgp, router_id, cluster_list, neighbor_addr, tie, reachable}` |
| Detalle de capa de MTU | columna «Detalle» del desglose | `mtu.{gre, gre_key, nat_t, vxlan, lisp, pppoe, mpls, tag_inner, tag_outer, esp}` con sus `args` (`ip`, `iv`, `icv`, `tbar`, `align`, `block`, `n`, `bytes`); `ip` y `tbar` valen otras claves `calc.val.mtu.*` |

Un argumento de una nota o de una celda cuyo valor es una clave `calc.val.*` (o varias separadas por coma) se escribe en el idioma pedido al armar el texto; en `notesStructured[].args` llega la clave (p. ej. `step: "calc.val.step.local_pref"`). Los nombres de capa (`gre`, `esp-tunnel:aes-cbc:sha256`), los nombres de ruta y los valores numéricos son datos y no cambian.

### DNS
- `toolsDnsReport(DnsRequest) → DnsReportData { text, json, findings }`, método nuevo y opcional en `ToolsAPI`; `toolsDns` (texto) no cambia.
- `findings[]`: `{ code, severity: "warning"|"error"|"info", key?, args?, message }`. `code` es el de siempre (`fragmentacion`, `tcp-bloqueado`, `sin-edns`, `ttl-bajo`, `cname-larga`, `sin-ptr`, `ptr-no-coincide`, `sin-spf`, `spf`, `spf-multiple`, `sin-dmarc`, `dmarc`, `sin-dkim`, `dkim`, `sin-caa`, `caa`, `sin-delegacion`, `ns-padre-hijo`, `glue-faltante`, `ns-sin-direccion`, `ns-lame`, `axfr-abierto`, `serial-distinto`; siguen en español, ya eran estables). `key` y `args` son los del detalle (`dns.finding.*`); **no hay `key` cuando el detalle es un dato** (`spf`, `dmarc`, `dkim`, `caa`, `ns-sin-direccion`).
- Solo hay `findings` en los modos transporte, higiene y zona. Exposición no los trae: sus dos líneas de `Details` del `json` salen traducidas (`dns.exposure.*`).
- El `json` y el `text` del informe traen el detalle (`Detail` / `Details`) en el idioma pedido. El `json` en español es idéntico al de siempre.

### TLS
- `toolsTlsReport(host, port, sni) → TlsReportData { text, json, findings, verifyCode? }`, método nuevo y opcional; `toolsTls` no cambia.
- `findings[]` igual que DNS (`tls.finding.*`; `code`: `tls-antiguo`, `vencido`, `aun-no-valido`, `vence-pronto`, `nombre-no-coincide`, `autofirmado`, `cadena-incompleta`, `llave-debil`, `firma-debil`). Las fechas, nombres y algoritmos de los `args` son datos.
- **`verifyError` NO se traduce**: es el texto de la biblioteca x509 de Go (inglés) y con `es` ya era así. Se agrega `verifyCode` ∈ `unknown_authority`, `hostname`, `expired`, `not_yet_valid`, `other` (ausente si la cadena verificó) para que la vista no lea el texto.

### IKE
- `secIkeReport(text) → IkeReportData { text, json, phase1, phase2, findings, proposals, note }`, método nuevo y opcional en `SecurityAPI`; `secIkeDecode` (texto) no cambia.
- `phase1` y `phase2` ∈ `established`, `failed`, `mixed`, `incomplete`, `no_data` (el `json` conserva `establecida`, `falló`… en español con `es`).
- `findings[]`: `{ code, severity, phase?, key, explanationKey, args?, title, explanation, action, evidence }`. `code` es el de siempre (19, en español: `p1-propuesta`, `p2-propuesta`, `pfs`, `psk`, `psk-ausente`, `sin-respuesta`, `retrans-key-exch`, `proxy-id`, `identidad`, `nat-t`, `lifetime`, `dpd`, `sa-estado`, `ipsec-sin-sa`, `ipsec-unidireccional`, `ipsec-solo-entrada`, `ipsec-sin-trafico`, `ipsec-errores`, `limite-sas`). `key` es `ike.finding.<código con _>` (con `.title` y `.action`); `explanationKey` es la de la explicación, que tiene variantes: `…p1_propuesta.explanation_attrs` (arg `attrs`: claves `ike.val.attr.*` separadas por coma), `…pfs.explanation_rejected`; `limite-sas` lleva `max`, `sa` e `ipsec`. `evidence` son líneas del equipo, sin traducir, salvo que `sa-estado` agrega «  → significado» (`ike.state.*`).
- `proposals[]`: `{ phase, sourceKey, sourceArgs?, source, detail, result? }`; `sourceKey` ∈ `ike.proposal.source.{v1_transform {transform, policy}, v1_proposal {n}, received, expected}`; `detail` es salida del equipo; `result` ∈ `accepted`, `rejected`.
- **Siguen como vienen:** los nombres de fuente detectada («debug crypto isakmp (IOS/IOS-XE)»), los estados de SA (`MM_NO_STATE`, `QM_IDLE`…), el detalle de las propuestas y las SA, y la línea «IPsec peer … encaps / decaps» del texto.

### Puente
| Método / DTO | Cambio |
|---|---|
| `calc(kind, req)` → `CalcResultDTO` | cada tabla gana `rowCoded` (`omitempty`) |
| `secRadiusReport` | cada intercambio gana `mschap2Verified` (`omitempty`) |
| `toolsDnsReport(DnsDTO)` → `DnsReportDTO` | nuevo |
| `toolsTlsReport(host, port, sni)` → `TlsReportDTO` | nuevo |
| `secIkeReport(text)` → `IkeReportDTO` | nuevo |

### Qué queda para otra fase
- `findings` de `dnssec` (`link.Error`, `Warnings`) y los errores de las sondas de DNS (`Probe.Error`, `Answer.Error`): siguen en español.
- Los errores de validación que rechazan la petición (`InvalidArgument`) de DNS, TLS e IKE siguen su camino de 30a o su texto de siempre.
- La vista que migre los slugs de RADIUS/TACACS+ y lea `rowCoded`, `findings` y `verifyCode`.

### Recordatorio: slugs de RADIUS y TACACS+ (fase 30c-A)
El front debe actualizar sus mapeos de `findings[].code`: ya no existen los slugs viejos. La tabla slug viejo → slug nuevo está arriba, en «Cambio que rompe: slugs de hallazgo de RADIUS y TACACS+».

## Idioma del núcleo: flota, análisis, ACL, cambios, deriva y limpieza (fase 30c, bloque C)

Los textos libres de estas áreas ya salen en el idioma pedido (`accept-language`, la bandera `core.localize` de 30a) y, además, cada texto que sale del catálogo viaja como clave. Sin idioma, o con `es`, el `json`, el `text` y los mensajes son **idénticos byte por byte** a los de antes (lo fijan pruebas de regresión por RPC y por dominio con golden generado antes del cambio).

### Cómo leer lo nuevo
- **`ToolReport.keys`** (proto, `map<string, TextRef>`; en el puente, `keys` en `FleetDTO`, `ReportDTO` y `CleanerDTO`): por cada texto libre del `json` que sale del catálogo, su clave (`fleet.warn.*`, `analyze.detail.*`…) y argumentos, bajo su **ruta JSON**: `rows.2.detail`, `warnings.0`, `hops.3.reason`, `findings.1.detail`. Los índices son los de las listas. Con `en`, el `json` ya trae ese texto en inglés; la clave sirve para dibujar sin leer el texto. Un texto sin clave plana (un literal de regla, una unión de varios textos como el detalle de varias interfaces) se traduce pero no trae clave.
- Los **valores** (equipos, IPs, MAC, puertos, interfaces, comandos, salidas de equipos, líneas de config) no se traducen.
- Los códigos cerrados en español que ya existían **no cambian** (la vista los mapea, `lib/vocab.ts`): `severity` (`critica`…), `kind` de inventario (`equipo`), `facet` de cambios (`versión`, `captura`…), `change` de vecinos en las diferencias (`cambió`, `apareció`, `desapareció`), `rule` de la limpieza (`linea-vacia`…), `source` de los eventos y de los resultados de búsqueda de flota (`log-equipo`, `auditoria`, `carpeta de Patrol`…) y `end` del rastreo (`trunk-sin-vecino`…). El **texto** de los cambios de vecino y los ids de vecino OSPF y grupo HSRP (`10.0.0.1 por Gi0/1`, `Vl10 grupo 10`) sí salen traducidos en el `text` y, el id, en `devices[].neighbors[].id` con `en`.

### Puente
| Método / DTO | Cambio |
|---|---|
| `FleetDTO`, `ReportDTO` (cambios, actualización, cumplimiento), `CleanerDTO` | ganan `keys?: Record<ruta, {key, args?}>` |
| `AclFindingDTO` | gana `detailKey?`, `detailArgs?` (el `detail` sale en el idioma pedido) |
| `analysisRunReport`, `analysisDiffReport`, `analysisTimelineReport`, `driftRunReport` | nuevos: devuelven `{report, text, keys?}`; `analysisRun`, `analysisDiff`, `analysisTimeline` y `driftRun` siguen devolviendo solo el JSON |

En TS los métodos nuevos son opcionales en `AnalysisAPI` y `DriftAPI`; `keys?` y `detailKey?` son opcionales en los tipos.

### Qué sale traducido, por área (claves nuevas)
- **Flota** (`fleet.*`): `warnings[]` de todos los resultados (`fleet.warn.*`), `PathHop.reason` (`fleet.reason.*`, también `arrived`/`cut` con su motivo), `TraceHop.note` (`fleet.note.*`), `rows[].value`/`detail` del tablero (`fleet.value.*`, `fleet.detail.*`: «no sincronizado», «NN % usada», «libre X de Y», «reinicio en las 24 h previas a la evidencia») y `Problem.evidence` de half-duplex (`fleet.evidence.half`). La evidencia que es salida del equipo no se traduce.
- **Análisis** (`analyze.*`): `Finding.title/explanation/action` (de la regla; los YAML ganan `title_en`, `explanation_en`, `action_en`, y una regla propia sin ellos sale en español), `Finding.detail` (`analyze.detail.*`), `warnings[].msg` (`analyze.warn.*`), `TimelineEvent.text/note` de los eventos que arma la app (`analyze.event.*`: rondas, hallazgos, pcap, marcas de reloj y «por <usuario>») y `TextDiff.note` (`analyze.diff.*`). Los mensajes del log del equipo y del syslog son datos; la ficha `kb` queda para el bloque D (msgkb).
- **ACL** (`acl.*`): `Finding.detail` (`acl.finding.covered`, o el error de validación `acl.err.*`) y los errores gRPC de importar, analizar y generar, con código (`acl.err.import` envuelve la línea con `acl.err.line`).
- **Cambios, actualización y cumplimiento** (`change.*`, `upgrade.*`, `compliance.*`): `findings[].detail`, la nota fija, `Item.title/detail`, los títulos y detalles de las reglas de endurecimiento y de la plantilla, y los errores de entrada con código (`upgrade.err.*`, `compliance.err.*`). Los comandos sugeridos y las líneas de config citadas no se traducen.
- **Deriva y limpieza** (`drift.*`, `cleaner.*`): `warnings` de la deriva, `Orphan.why` y el texto de los reordenamientos; la marca de la salida es `! HUERFANA: …` con `es` y `! ORPHAN: …` con `en`; errores gRPC `drift.err.no_pair` y `cleaner.err.empty`.
- El **texto del informe** (`text`) también sale en inglés en análisis, diferencias, línea de tiempo, cambios, actualización, cumplimiento, deriva y limpieza.

### No cubierto en este bloque
- El `text` de flota (encabezados, «AVISO», `Ago`/`Stamp` «hace 5 min», `DATO VIEJO`) y el CSV/Markdown del inventario siguen en español; los datos y avisos que trae adentro sí salen traducidos.
- Los errores gRPC de los demás servicios y los de lectura de archivos del sistema (permisos, zip dañado) siguen como vienen. Los de flota, análisis, deriva, cambios, actualización, cumplimiento, ACL y limpieza llevan código (`fleet.err.*`, `analyze.err.*`, `change.err.*`, `upgrade.err.*`, `compliance.err.*`, `acl.err.*`, `drift.err.*`, `cleaner.err.*`) y metadata; con `es` el texto es el de siempre.
- `kb` de la línea de tiempo (fase del bloque D) y los códigos cerrados en español de arriba.

### Ajustes tras la revisión del bloque C
- **Secretos.** El informe de cumplimiento oculta, además del valor de `password` y `secret`, la comunidad de `snmp-server community`, el `key-string` y la llave de `ntp authentication-key`. Eso cambia el texto en español de esos casos raros (por ejemplo, la línea citada de una regla prohibida de la plantilla) y cierra una fuga. La marca es `<oculto>` con `es` y `<hidden>` con `en`.
- **Errores con causa.** Un error que envuelve a otro (`acl.err.import` sobre `acl.err.line`) trae en su metadata la de la causa (`line`) y `cause_reason`; los argumentos de `Finding.detail_key` traen la `cause` (en español) cuando la plantilla la pide.
- **`fleetWails`** devuelve `keys` en cada resultado cuando el núcleo las manda.

## Idioma del resto del núcleo: bloque D (fase 30c)
Forense, métricas, Patrol, scripts y transferencias. Sin `accept-language`, o con es, cada RPC devuelve los mismos bytes de antes (lo fijan los golden `testdata/*_es.golden.json`); con `en` el texto sale traducido.

### Reglas
- Los errores gRPC de estas áreas usan `service.Err`/`ErrFrom`: el texto sigue al idioma y `ErrorInfo.reason` + `metadata` viajan siempre (el puente ya los lleva con `wrapErr`).
- Los informes JSON no ganan campos: el JSON de forense, métricas y transferencias trae los mismos campos que antes, con el texto en el idioma pedido (`meaning`, `cause`, `action`, `hint`, `warnings`, `reason` de las anomalías, `source`…). Lo que el front dibuja sigue saliendo de los campos de siempre (`id`, `severity`, `count`…), que no cambian.
- Los nombres de equipo, IP, comandos de IOS, mnemónicos y la salida de los equipos no se traducen.

### Campos nuevos (puente, todos `omitempty`)
| DTO | Campos | Qué traen |
|---|---|---|
| `LoginDTO` (`LoginTest`) | `reason`, `args` | código y argumentos del error de `detail` (`transport.hostkey.unknown {host, fingerprint}`, `transport.err.auth`, `platform.err.closed`…); vacíos si `detail` es texto de sistema |
| `RunDeviceDTO` (`GetRun`) | `reason`, `args` | igual, para el `detail` de un equipo que falló |
| `DeviceStateChanged` (evento) | `reason`, `args` (proto `reason = 4`, `args = 5`) | igual, para el `detail` del evento |

`detail` sigue siendo el texto en el idioma pedido. Los códigos nuevos son `patrol.field.*` (validación del trabajo, con `metadata.field`), `patrol.svc.*`, `transport.err.*`, `transport.hostkey.{unknown,changed,known}`, `platform.err.*`, `backup.err.*`, `terminal.err.*`, `visibility.err.*`, `metrics.svc.*`, `forensic.err.*`, `scripts.err.*`, `scripts.col.*`, `scripts.svc.*`, `xfer.err.*`, `transfer.svc.*` y `fileserve.err.*`.

### Forense
- `MsgLookup` y `Crashinfo`: `meaning`, `cause`, `action` y `source` de cada ficha salen en el idioma pedido (en el YAML de la base van `meaning_en`, `cause_en` y `action_en`). `verify` son comandos de IOS y no cambian. La fuente fija es «documentación pública de Cisco (sin validar en laboratorio)» / «Cisco public documentation (not validated in the lab)».
- `Crashinfo`: `hint` y `warnings` traducidos; `kind` conserva el código de siempre (`crashinfo`, `core`, `desconocido`).
- `LogPatterns`, `Flapping`, `MemLeaks`, `DebugFilter`: `warnings`, la `kb` por mnemónico, el `reason` de cada anomalía de `DebugFilter` y el texto del informe (`text`) en el idioma pedido; `source` es «texto pegado» / «pasted text», «captura del receptor syslog» / «syslog receiver capture» o `show logging del trabajo <carpeta>` / `show logging of job <carpeta>` (o la ruta del archivo, que es un dato).
- Siguen en español con `en`: el texto del sistema (`no such file…`) y los avisos del lector de carpetas de Patrol (`internal/analyze`, bloque C).

### Métricas
`GetJobMetrics` (`warnings` de la respuesta y de cada equipo) y `GetPortStatus` (`warnings`, en vivo y de un trabajo) salen en el idioma pedido; los comandos que citan no cambian. Los errores del servicio (`metrics.svc.*`, `metrics.err.*`) son de catálogo.

### Patrol
- `CreateJob`: los errores de validación son `patrol.field.*` con `metadata.field` (`targets`, `credential`, `window_hours`, `output_dir`, `commands`, `custom_commands`, `playbook_ids`, `overrides`, `schedule`) más los argumentos (`n`, `id`, `device`, `error`). El texto sigue siendo `patrol: <campo>: <mensaje>`.
- `LoginTest` y los eventos de equipo: ver la tabla de arriba. Los pasos (`failed_step`) no cambian.
- La auditoría del equipo (`device.round`) lleva ahora el detalle en inglés.

### Scripts
Los scripts de fábrica (origen `biblioteca`) salen con `name` y `description` en inglés con `en` (`name_en` y `description_en` en `configuracion.yaml`; los de playbook toman el `name_en` del playbook y «Read-only diagnostic of playbook <id>.»). Los scripts del usuario no se traducen, ni el archivo de export (siempre en español). Los errores de validación y de los RPC de scripts y colecciones son `scripts.err.*`, `scripts.col.*` y `scripts.svc.*`.

### Transferencias
- `StartServer`: el campo `Error` de `transfer_json` (motivo de rechazo o de falla) sale traducido: `origen no permitido` → `origin not allowed`, `archivo no publicado` → `file not published`, `método POST` → `method POST`… (`fileserve.reason.*`). `HTTP 404` y los textos del sistema no cambian. Lo que el servidor manda por el cable al equipo (respuestas FTP, errores TFTP y SCP) sigue en español.
- `TransferResult.report`: «guardado/enviado … (N bytes en T)» / «saved/sent … (N bytes in T)»; `verified` conserva sus códigos (`ok`, `distinto`) y la línea «verificado: …» se traduce.
- `TransferListing.reason` (el motivo de «no lista») sale en el idioma pedido (`xfer.no_listing`).
- Errores de validación: `fileserve.err.*`, `xfer.err.*` y `transfer.svc.*`.

### No cubierto en este bloque
Instrucciones de `ServerReady.hint` (la explicación paso a paso del servidor de archivos), los textos del informe de respaldos (`collected.text`, avisos de `CollectBackups`) y de `ListBackups`, el análisis de las salidas de Patrol (`internal/analyze`, bloque C), los errores de importación de archivos de scripts (`importar.go`, `exchange.go`, `formato.go` y las decisiones de colecciones en `coleccion.go`), `service.VaultErr` y los textos de `internal/sys`, `internal/backup` y `internal/playbook`.

### Ajustes tras la revisión del bloque D
- **Texto en español que cambió (cierra una fuga):** `URL inválida "<url>"` (en `Get`, `Put`, `Browse` y `GetMany`) cita la URL sin contraseña (`ftp://admin:xxxxx@/a`) en el texto y en `metadata.url`, con es y con en. Antes salía completa.
- **Puente:** `TransferListingDTO` gana `reasonCode` y `reasonArgs` (`omitempty`): el código estable del motivo de «no lista» (`xfer.no_listing.tftp`, `xfer.no_listing.scp`) y su metadata (`proto`). `reason` sigue siendo el texto.
- **`GetRun` tras reiniciar el núcleo** sale en español y sin `reason`: el error del detalle (`DetailErr`) no se guarda en disco.
- **Auditoría (siempre en inglés):** el detalle libre de `device.round` y de `transfer.serve.transfer` va como `error="…"`. El `target` de `forensic.patterns` y `forensic.flapping` es «pasted text», «syslog receiver capture», «show logging of job <carpeta>» o la ruta del archivo.
- **Severidades de syslog** con `en`, como las nombra Cisco: emergencies, alerts, critical, errors, warnings, notifications, informational, debugging.
- **Metadata de `ErrorInfo`** de los códigos nuevos: solo trae los argumentos declarados por el código (sin secretos); `xfer.no_listing.*` lleva `proto` y no texto traducido.
- **Sigue en español con `en`:** los errores de `internal/core/respaldo.go` (exportar e importar el respaldo de la bóveda) y los textos de `internal/analyze`.

## Paquetes de contenido (fase 32, ADR 0010)

`PackService` (gRPC) y `ui/bridge/pack.go`; tipos y Wails en `modules/packs/api.ts` (con su `fake.ts`). La vista, Ajustes → Paquetes, es de front.

### Métodos del puente
| Método | Argumentos | Devuelve |
|---|---|---|
| `PackInstall(path, allowUnsigned)` | ruta absoluta del `.mpack` (una relativa falla) que eligió el usuario; `allowUnsigned` es la confirmación del diálogo con aviso | `{pack, replacedVersion}` (`replacedVersion` vacío si era nuevo) |
| `PackList()` | | `PackInfo[]`, ordenados por id (nunca `null`) |
| `PackShow(id)` | id del paquete instalado | `{pack, readme, playbookIds, scriptIds}` |
| `PackRemove(id)` | id del paquete instalado | número de scripts del paquete que estaban en colecciones o fijados y se quitaron |

`PackInfo`: `id` (`<editor>/<nombre>`), `version`, `minCore`, `name`, `nameEn`, `description`, `descriptionEn`, `platforms`, `author`, `license`, `official`, `playbookCount`, `scriptCount` (derivados de playbooks más `scripts.json`) y `shadowed` (IDs de playbook que uno de `<config>/playbooks` tapa).

### Qué muestra la lista
- id, versión, origen (**oficial** si `official`, **de terceros** si no), cuántos playbooks y scripts trae.
- Si `shadowed` no viene vacío, avisa qué IDs quedan tapados por los playbooks propios del usuario.
- `official` se deriva en cada arranque de la firma; nunca es un dato guardado.

### Instalar
- El núcleo lee la ruta una sola vez (tope de 20 MB) y valida todo; la instalación es todo o nada y se refleja en caliente (playbooks, biblioteca de scripts) sin reiniciar.
- Un paquete sin firma oficial es de terceros: sin `allowUnsigned` falla con `pack.err.unsigned`. El diálogo debe avisar que el paquete no está firmado y que solo trae comandos de lectura.
- Para una versión igual o más vieja que la instalada, o para un oficial instalado reemplazado por uno de terceros, hay que quitar el instalado primero (`pack.err.version`, `pack.err.official_replace`).

### Reasons (`ErrorInfo.reason`; texto es/en en el catálogo, metadata solo con los argumentos declarados)
| Reason | Metadata | Código gRPC |
|---|---|---|
| `pack.err.path` | | InvalidArgument |
| `pack.err.read` | | InvalidArgument (archivo ilegible; el texto del sistema va en el mensaje, no en la metadata) |
| `pack.err.zip.invalid` | | InvalidArgument |
| `pack.err.zip.path`, `pack.err.zip.dup` | `name` | InvalidArgument |
| `pack.err.zip.too_big` | `what` (`archive`, `entries` o el nombre del archivo) | InvalidArgument |
| `pack.err.zip.missing` | `name` | InvalidArgument |
| `pack.err.index.mismatch` | `name` | InvalidArgument |
| `pack.err.signature.invalid` | | InvalidArgument |
| `pack.err.manifest.invalid` | `field` (`id` también cuando el editor de un paquete de terceros no cumple `^[a-z0-9]{1,16}$`, sin guion) | InvalidArgument |
| `pack.err.core.too_old` | `min_core`, `core` | InvalidArgument |
| `pack.err.playbook.denied`, `pack.err.playbook.invalid` (incluye un id que no sea `a-z0-9-` o distinto del nombre del archivo, o que haría inválido el script `lib-<id>`), `pack.err.script.invalid` | `cause_reason` si la causa trae código | InvalidArgument |
| `pack.err.playbook.platform` | `id`, `platform` | InvalidArgument |
| `pack.err.id.prefix` | `id`, `want` | InvalidArgument |
| `pack.err.editor.reserved` | `editor` | InvalidArgument (`oom`, nombres de plataforma y los primeros segmentos de ID del contenido base, del movido a `oom/ios-xe` y de los previstos para paquetes oficiales están reservados para paquetes con firma oficial) |
| `pack.err.unsigned` | | FailedPrecondition |
| `pack.err.collision` | `id`, `with` (`base` o el id del otro paquete) | FailedPrecondition |
| `pack.err.version` | `id`, `installed`, `version` | FailedPrecondition |
| `pack.err.official_replace` | `id` | FailedPrecondition |
| `pack.err.not_found` | `id` | NotFound |
| `pack.missing` | `playbook`, `pack`, más `field = playbook_ids` | InvalidArgument (en `CreateJob`) |

`pack.missing` sale de `CreateJob` (y de la ronda de un trabajo recargado) cuando el playbook pedido viene en un paquete que no está instalado: los movidos a `oom/ios-xe` o los de un paquete quitado. Dice qué paquete instalar (`pack`). Un ID inexistente que no es de ningún paquete sigue con `patrol.field.no_playbook`. Un trabajo ya creado conserva los playbooks que tenía: la foto del catálogo se toma al crear el trabajo (`CreateJob`), no al armarlo ni en cada ronda; instalar o quitar un paquete después no la cambia. Un trabajo recargado tras reiniciar el núcleo toma el catálogo vigente.

### README y textos del paquete
`readme`, `name`, `description`, `author` y los demás textos son **texto plano** (o Markdown sin interpretar). La vista no usa `dangerouslySetInnerHTML`, no carga imágenes y no hace clicables los enlaces: nada del paquete pide recursos a la red ni mete HTML en el webview. Se muestra `name`/`description` o `nameEn`/`descriptionEn` según el idioma de la interfaz; el README viene en español e inglés en el mismo texto.

### Auditoría (siempre en inglés)
- `pack.install`: `id=… version=… sha256=<del archivo> origin=official|third-party playbooks=N scripts=N [replaced=<versión>] [min_core_unchecked=true]`.
- `pack.remove`: `id=… version=… origin=… playbooks=N scripts=N favorites_removed=N`.
- `pack.rejected`: `id=… version=… sha256=… origin=… reason=<motivo sin el prefijo pack.err.> path="<la ruta que pasó el usuario>"`; al arrancar, `id=… dir=… reason=… stage=startup` por cada paquete instalado que no pasó la revalidación (se omite y el núcleo sigue).

### Compatibilidad
Los IDs de los playbooks movidos a `oom/ios-xe`, sus scripts `lib-<id>` y los favoritos no cambian. Quien venga de una versión anterior no tiene esos playbooks ni scripts hasta que instale el paquete. Las colecciones y los fijados que ya tenían `lib-<id>` de esos scripts se conservan en la base (no se podan) mientras el paquete no está instalado. En las colecciones la vista puede recibir IDs `lib-*` que todavía no resuelven a un script y debe tolerarlo. Los fijados retenidos NO aparecen en `ListPinned`, no cuentan para el tope de fijados y no hay que enviarlos en `ReorderPinned` (se comparan solo los visibles; los retenidos quedan al final, en su orden); al instalar el paquete vuelven a verse. Lo mismo vale para los scripts de playbooks de un paquete quitado.

## Idioma: pendientes de 30a-30c (fase 30d)

Cierra lo que 30a-30c dejaron en español. Misma regla de compatibilidad: sin `accept-language`, o con `es`, el texto y el JSON de cada RPC son idénticos byte por byte a los de antes (lo fijan pruebas de regresión con golden generado antes del cambio); con `en` el texto sale en inglés. Todo son campos que ya existían: no hay campos nuevos en proto ni en el puente, y los JSON de los informes no ganan campos. La auditoría va siempre en inglés (decisión del dueño): con 30d algunos detalles que antes salían con texto en español ahora salen en inglés completo, con cualquier `accept-language`: el motivo de `job.arm_failed` con bóveda cerrada (`vault is locked`), `adhoc.denied`, el motivo de `terminal.failed`, los detalles de `device.round` con error y los de `job.load_failed`. Lo demás de la auditoría no cambia.

### Qué sale ahora en el idioma pedido
- **DNS (RPC `Dns`, modos profundos).** En el informe de `dnssec`: `Chain[].Error`, `Warnings` y `Denial` (`ninguna`/`desconocido` con es; `none`/`unknown` con en; `NSEC` y `NSEC3` no cambian). En la traza: `Warnings` y `Steps[].Error`. En la consulta: `Answers[].Error`. En transporte: `Probes[].Error`. En zona: `Servers[].Error`. Los errores que rechazan la petición (servidor, tipo de registro, puerto, esquema DoT/DoH inválidos) y los de la traza abortada llevan `ErrorInfo.reason` (`dns.parse.err.*`, `dns.trace.err.*`). Los textos del sistema (`connection refused`, `lab: … no existe`) se citan tal cual.
- **Errores de validación de `tools`.** `tools.svc.{pcap_path, dns_mode, dns_deep, dns_name, dns_unknown, tls_host, tls_port}`, los errores del lector de capturas (`pcap.err.*`) y los de TLS (`tls.err.*`).
- **Servidor de archivos.** `ServerReady.hint` (`transfer`), `ServeFilesResponse.hint` (`field`) y `RedirectHintResponse.{nftables, setcap}` salen en el idioma pedido. Los comandos de IOS, nftables y setcap no cambian; con `en` el marcador de la ruta del servidor es `SERVER-PATH` (con es sigue `RUTA-DEL-SERVIDOR`) y el de IP es `IP-OF-THIS-MACHINE` (el mismo de `transfer.ios.ip` del front) (con es sigue siendo `IP-DE-ESTA-MÁQUINA`).
- **Bóveda y respaldo cifrado.** Los errores de la bóveda (`vault.err.*`: contraseña incorrecta, bóveda cerrada, credencial no encontrada, frase corta…) y los del respaldo (`respaldo.err.*`: confirmar, ruta absoluta, frase incorrecta, token desconocido o vencido, decisiones) llevan reason y salen en el idioma pedido en todos los servicios que los devuelven (`service.VaultErr` ahora recibe el contexto). Las etiquetas de credencial viajan como argumentos; nunca se citan frases ni secretos.
- **Flota.** El `text` de cada informe (encabezados, `AVISO`/`WARNING`, `LLEGÓ`/`ARRIVED`, `CABE`/`FITS`, «hace 5 min»/«5 min ago», `DATO VIEJO`/`OLD DATA`), y el CSV y el Markdown del inventario (encabezado y tipo: `equipo`→`device`, `modulo`→`module`; `sfp` igual). El JSON de flota no cambia: `kind` sigue siendo el código `equipo`/`modulo`/`sfp`.
- **Respaldos de configuración.** El `text` de `CollectBackups` (resumen y avisos), `ListBackups` y `DiffBackups`; los errores del almacén (`backup.store.*`: nombre de equipo, identificador, retención) llevan reason. Los avisos del lector de Patrol se traducen con su clave de `internal/analyze`.
- **Importación de scripts y colecciones.** Errores del archivo y de las decisiones (`scripts.imp.*`: formato, versión, suma, tope, decisión desconocida o faltante, choques de nombre) y avisos de la vista previa y de la aplicación (`archivo sin suma de verificación`, script de biblioteca ausente o no importado). Cuando el error envuelve una validación, la causa sale en el mismo idioma.
- **Lectura de playbooks y ad hoc.** El rechazo de un comando que no es de lectura (`playbook.err.denied_cmd`, con el motivo como causa: `playbook.why.*`), los errores de los archivos YAML de playbooks (`playbook.err.*`) y los de `StartAdhoc`. `errors.Is(err, playbook.ErrDenied)` sigue valiendo.
- `sys.ErrNotRegular` («la ruta no es un archivo regular») lleva reason `sys.err.not_regular`.
- **Archivos de export/import y validaciones sueltas (revisión de 30d).** `service.AbsPath`, `WriteExport` y `ReadImport` reciben el contexto y devuelven errores con código (`file.err.path_abs` para la ruta relativa de scripts, colecciones, hosts y paquetes; el respaldo cifrado conserva `respaldo.err.path_abs`; `file.err.export_not_regular`; `sys.err.not_regular` ya no se aplana a texto). También llevan reason y salen en el idioma pedido: `diag.err.no_tool`, `security.err.*` (bóveda, servidor, puerto, contraseña de la llave, entrada grande), `field.err.first_open`, `prefs.err.*` y `hosts.err.*` (host faltante, credencial inexistente, exportación vacía o demasiado grande, token y vista previa vencidos, formato). Con es el texto es el de siempre.
- **Un cambio de texto en es (el único):** un comando con caracteres fuera de ASCII que llega al ejecutor de assist (`devExec.Read`) ahora se rechaza con el mismo error de `CheckDenied` (`playbook.err.denied_cmd`, causa `playbook.why.ascii`) en vez de un texto propio.
- El error de campo de Patrol con causa del catálogo lleva la metadata del error (incluido `cause_reason`) más `field`.
- `ResultadoCol.WarningTexts` no viaja en el JSON; los avisos de `CollectBackups` en inglés nunca mezclan un aviso con la traducción de otro.
- Correcciones de texto en inglés: `respaldo.err.{action,undecided}` citan los valores de API entre comillas, `dns.exch.trunc_failed`, `backup.store.bad_meta` («invalid metadata file»), `fileserve.hint.std_port`, `adhoc.err.no_targets` («specify at least one device»). El texto de flota traduce el tipo del inventario y la fuente «carpeta de Patrol» (`Hit.Source` en el JSON sigue igual).

### Qué cambia para el front
- Nada que rompa. Lo que antes eran errores gRPC de texto plano en estas áreas ahora traen `ErrorInfo` (reason y metadata) y `LocalizedMessage`; el mensaje con es es el mismo texto de siempre. Quien comparaba texto sigue funcionando con es; con `en` debe usar el reason.
- No hay claves nuevas en `i18n/{es,en}.ts`: son textos que llegan ya traducidos del núcleo.

### Qué sigue sin cubrir
- `RestoreRefusal.why` (motivos por línea de la restauración por diff): exige un tipo nuevo, ver 30c-B.
- Lo que el servidor de archivos manda por el cable al equipo (respuestas FTP, errores TFTP y SCP): lo lee el equipo, no la UI.
- Los argumentos `error` de los hallazgos `ns-lame` de DNS y los textos del sistema que citan los errores (`connection refused`, mensajes de la biblioteca TLS o de JSON).
- `rotate.go` del servicio de cambio asistido (errores de la bóveda al rotar), las partes de `fail_reason` con `%v` de un error sin código, y los errores internos de `ErrInvalidPlan`/`Check`.
- Errores con argumentos que siguen en español (`status.Errorf`): `carpeta de salida`/`archivo de salida` (adhoc, diag, field), `protocolo %q no soportado` (field), los de la libreta de hosts (`la libreta llegó a %d hosts`, `no hay un host … con id`, `ya hay un host llamado`, `ya está en la libreta como`, `son más de %d hosts`, `decisión repetida`) y `trabajo %s no existe` (core). Tampoco la advertencia `la bóveda está cerrada: la credencial se guardó sin validar` de `PutDevice`, y los `status.Error(err.Error())` de `diag`, `terminal` y `servicetest` que envuelven errores del sistema.
- Los errores de lectura de archivos del sistema (permisos, zip dañado) y los de `internal/analyze` que no pasan por una clave de catálogo.
- Los datos que vienen de los equipos (salida de `show`, nombres, descripciones) y los scripts del usuario.

## Playbooks con datos (fase 34)
- `PlaybookInfo.params` (`PlaybookParam{name, kind}`; kind = `mac`, `ap`, `interface` o `ip`): lo que el playbook pide al armar el trabajo. Sus `commands` traen la plantilla con `{nombre}`; no se ejecutan tal cual.
- `JobSpec.params` (`map<string,string>`): un valor por dato de los playbooks elegidos. El núcleo valida (la MAC se normaliza a `aaaa.bbbb.cccc`) y rechaza datos faltantes, desconocidos o inválidos en `CreateJob` con `field = params` y códigos `playbook.err.param_*` (`name`, `kind` en la metadata). Sin datos, un trabajo se comporta como antes. Mientras la UI no pida los datos, un playbook con `params` no se puede usar desde la app: `CreateJob` falla por el dato que falta.
- Los datos quedan en el manifest (`params`) y en la auditoría de `job.create`; no son secretos. Los playbooks con datos no generan script `lib-<id>` en la biblioteca.

## Paquete personal: exportar e importar (fase 32c)
Dos RPC al final de `PackService` y sus métodos de puente (`ui/bridge/pack.go`; tipos y Wails en `modules/packs/api.ts`, con su `fake.ts`). La vista (Ajustes → Paquetes → Exportar / Importar) es de front. Nada de esto escribe en equipos. Texto, nombres y README del paquete siguen siendo texto plano.

| Puente | Entrada | Salida |
|---|---|---|
| `PackExport(req)` | `{editorName "<editor>/<nombre>", scriptIds[], includePlaybooks, license, path, overwrite, name, nameEn, description, descriptionEn, author}`; `path` absoluto; lo opcional vacío toma su valor por omisión | `{id, version, sha256, scripts, playbooks, omittedPlaybooks[]}` |
| `PackImportPreview(path)` | ruta absoluta del `.mpack`; no escribe nada | `{pack, items[], warnings[], applied:false, …}` |
| `PackImport(path, decisions[])` | `decisions` = `{itemId, action}` con `action` `renombrar` u `omitir` | `{pack, items[], applied:true, scriptsCreated/Renamed/Skipped, playbooksCreated/Renamed/Skipped, playbookIds[]}` |

- **Exportar.** Solo scripts del usuario (uno de biblioteca da `scripts.svc.not_found`); `includePlaybooks` suma todos los de `<config>/playbooks`. El archivo no lleva firma y pasa las mismas validaciones del instalador como paquete de terceros: se instala con `allowUnsigned`. Versión `AAAA.MMDD.HHMM` de la hora local, `min_core` = versión del núcleo (`0.0.0` si es `dev`), licencia `NOASSERTION` si va vacía, `nameEn`/`descriptionEn` copian el español. Los scripts salen como `lib-<editor>-<12 hex>`; los playbooks con el editor como prefijo (`ios-xe/<editor>-<id>`). Solo `ios`, `ios-xe` y `wlc-9800`: lo demás, o un ID que un paquete no aceptaría, llega en `omittedPlaybooks` (mostrar el aviso). Los favoritos no viajan. La ruta debe ser nueva salvo `overwrite`.
- **Importar.** Dos pasos sin token: la vista previa y luego `PackImport` con las decisiones (se vuelve a validar todo). Un paquete con firma oficial no se importa (`pack.err.import.official`; se instala). Cada elemento de `items`: `kind` `script` o `playbook`, `id` (el del archivo), `name`, `state` (`nuevo`, `igual`, `conflicto_id`, `conflicto_nombre`) y `conflictsWith` (script: ID guardado; playbook: `base`, `reserved`, `user`, `file` o el id del paquete instalado). Los `nuevo` entran solos; `igual` se omite solo; cada conflicto necesita `renombrar` u `omitir` (un playbook renombrado queda `<id>-2`, `-3`…). **Nunca se reemplaza** (`reemplazar` da `pack.err.import.decision`). Los scripts quedan editables con ID de usuario; los playbooks van a `<config>/playbooks` con su ID con prefijo y el catálogo se recarga sin reiniciar (`ListPlaybooks` los trae al instante). Todo o nada: si algo falla no queda nada escrito.
- **Auditoría (inglés):** `pack.export` (`id= version= sha256= scripts= playbooks= omitted= path=`), `pack.import` (`id= version= sha256= origin= scripts_created= … playbooks_skipped= path=`), `pack.rejected` si el `.mpack` no pasa, y `pack.import.reload_failed` si los archivos quedaron escritos pero la recarga falló (el catálogo los toma al reiniciar).

| Reason | Args | gRPC |
|---|---|---|
| `pack.err.export.empty` | | InvalidArgument (nada que exportar) |
| `pack.err.export.name_dup` | `name` | InvalidArgument (dos elementos con el mismo nombre) |
| `pack.err.import.official` | | InvalidArgument |
| `pack.err.import.missing` | `id` | InvalidArgument (conflicto sin decisión) |
| `pack.err.import.decision` | `id` | InvalidArgument (acción no permitida, ID que no es del paquete o repetido) |
| `pack.err.import.exists` | `file` | FailedPrecondition (carrera: el archivo apareció antes de escribir; nada se sobrescribe) |
| `pack.err.editor.reserved`, `pack.err.manifest.invalid` (`field=id`, `license`…) | | el editor no cumple las reglas del export |

Además salen los de siempre de `Install` (`pack.err.zip.*`, `pack.err.id.prefix`, `pack.err.playbook.denied`…) al importar un `.mpack` hostil, y `scripts.imp.*` por las decisiones de scripts. `mctl pack export` y `mctl pack import` son la misma API.
