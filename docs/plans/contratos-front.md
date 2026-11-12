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
- **Campo `platforms` por comando de un playbook.** Opcional: `platforms: [ios-xe]` hace que el comando solo corra si la plataforma detectada está en la lista; vacío = en todas las compatibles. Una plataforma desconocida hace fallar la carga con el nombre del archivo. El comando omitido no corre y queda en el `manifest.json`, en `devices[].Skipped` (texto de cada comando omitido por plataforma). `dir bootflash:` lo lleva en `upgrade-check`, `plat-flash-fs`, `flota` y `plat-reloads-crashinfo`. `listPlaybooks` con `platform: ios` devuelve los de `ios-xe` (misma regla que al ejecutar) y sin los comandos que ahí no corren.
- **FTP: ruta remota con `/` inicial = absoluta** (decisión del 2026-11-12), igual que SCP y SFTP; sin `/` es relativa a la carpeta de inicio. En la URL la absoluta lleva `//` (`ftp://host//x/y`); la vista la arma así (`buildURL`) y `getMany` conserva el `//` de la carpeta del lote. El campo de listado `path` ya iba tal cual (`CWD /x/y` absoluta, `CWD x/y` relativa).
- **Tipo de trabajo (`kind`).** `JobSpec.kind` (15) y `JobSummary.kind` (14), y `kind` en el DTO de `listJobs` del puente. Valores cerrados: `patrol` (vacío en la spec = patrol), `adhoc`, `backup`, `change`; cada servicio pone el suyo y `createJob` rechaza otro valor con `InvalidArgument`. Se persiste con el trabajo; uno guardado antes de la fase sale como `patrol`. El resumen siempre trae un valor (nunca vacío).

## Idioma del núcleo: errores con código estable, fases y nombres de playbooks (fase 30a)

Paso 1 de 3 del inventario `docs/plans/2026-11-07-idioma-nucleo.md`: la infraestructura y los primeros códigos. El núcleo ya no obliga a leer su texto en español para saber qué pasó: cada error migrado lleva un **reason** estable y su **metadata**, y con el idioma pedido el texto sale en inglés.

### Regla de compatibilidad
Sin el metadato `accept-language`, o con `es` (o con cualquier idioma que no sea `en`), cada respuesta del núcleo es **idéntica byte por byte** a la de antes de la fase: mismos mensajes de error, mismos detalles de fase, mismos nombres. Lo único que cambia son campos nuevos (`reason`, `args`, la metadata del error). Lo fijan pruebas de regresión con el texto en español literal. El front puede seguir parseando texto mientras no encienda la bandera.

### Cómo se activa: `core.localize`
- La bandera vive en el puente: `Bridge.Localize` (Go), apagada por omisión. En `ui/main.go` es la constante `coreLocalize` (`false`); la sesión de front la pasa a `true` cuando termine de migrar. Para probar sin recompilar: `MACUAHUITL_CORE_LOCALIZE=1` al lanzar la app.
- Encendida, **toda** llamada y todo stream del puente lleva `accept-language` con el valor de la preferencia `ui.language` (`es` o `en`; sin valor guardado o desconocido = `es`). El puente la lee una vez y la mantiene al día cuando `setPreference("ui.language", v)` pasa por él; si la interfaz no guarda esa preferencia, no hay idioma que mandar y todo sale en español.
- `ui.language` es una clave nueva de `getPreference`/`setPreference` (la lista cerrada la acepta; el valor es `es` o `en`).
- El núcleo acepta `es`, `en`, `es-MX`, `en-US`… y listas con `q` (`fr, en;q=0.8` da `en`); ausente o desconocido es `es`.
- **La auditoría no depende del idioma** (decisión del 2026-11-12, rama 30a-2): su detalle irá fijo en inglés; esta fase no toca sus textos y la infraestructura no los pasa por el catálogo.
- CLI: `mctl --lang es|en` (en cualquier posición); si no, `LC_ALL`, `LC_MESSAGES` y `LANG` por ese orden; si no, `es`. Los textos propios de mctl no se traducen.

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

**Eventos de cierre de los streams.** Los RPC de servidor (syslog, traps, flujos, diag, consola, serve, transferencias, terminal y asistente) devuelven su error de validación en el primer `Recv()`, y el puente lo emite en el evento `*:done` (`syslog:done`, `traps:done`, `flows:done`, `diag:done`, `console:done`, `serve:done`, `transfer:done`, `terminal:done`, `assist:done`) como `{runId, error, errorInfo, ...}`. `error` sigue siendo el texto de siempre; `errorInfo` es `{code: string, reason: string, metadata: Record<string,string>}` (la misma forma que `CoreError` sin `message`; `metadata` nunca es `null`) y solo está cuando hay `error`.

### Reasons y metadata de esta fase
| reason | code gRPC | metadata |
|---|---|---|
| `ingest.invalid` | `InvalidArgument` (al validar; `Unavailable` si lo detecta la escucha ya abierta) | `field` y, según el campo, `min`, `max`, `value`, `template_problem` |
| `file.exists` | `AlreadyExists` | `path` |
| `assist.invalid_value` | `InvalidArgument` | `template`, `field` y `why` del **primer** problema |
| `assist.refused` | `FailedPrecondition` | `template` (nombre de la función del snippet) y `device` |

- **`ingest.invalid`** (syslog, traps SNMP, flujos y los defaults de `setCorePrefs`). `field` ∈ `rate_per_source`, `burst_per_source`, `rate_global`, `burst_global`, `queue_size` (con `min`, `max` y `value`), `rotate_mb` (`min` 1, `max` 1024), `rotate_minutes` (1, 10080), `max_files` (1, 1000), `format` (con `value`), `protocol` (con `value`; solo syslog), `addr` (dirección de escucha: formato, puerto, privilegiado, host, todas las interfaces) y `name_template`; además `dir` si falta la carpeta de salida (no lo manda la interfaz). Para `name_template` viene `template_problem` ∈ `len` (con `min` 1 y `max` 64), `need` (falta `{fecha}` o `{hora}`), `tokens`, `chars` (con `ch`, el carácter) y `dots`. Reemplaza el `grep` de «tasa por origen», «plantilla», «dirección inválida»… de `ingestOpts.ts`.
- **Sinónimos de la plantilla del nombre:** `{date}`, `{time}` y `{source}` valen igual que `{fecha}`, `{hora}` y `{origen}`, en la validación, en el nombre del archivo y en la retención (que reconoce los archivos de la misma plantilla escrita de cualquiera de las dos formas, y también mezclada). Siguen siendo sintaxis del usuario; el núcleo no las traduce en lo que escribe.
- **`file.exists`**: los export de scripts, colecciones, hosts y respaldo de bóveda con `overwrite: false`, y `writeFile` del puente. Reemplaza `/ya existe/` de `lib/core.ts`: usa `reason === "file.exists"`. Los textos de hoy se conservan (`el archivo ya existe`, `vault: el archivo de respaldo ya existe`, `guardar: el archivo ya existe`).
- **`assist.invalid_value`**: `why` ∈ `required`, `range`, `pattern`, `choice`, `type`, `unknown_field`. El texto junta todos los problemas con «; » y lleva el prefijo `assist: valores del snippet inválidos: ` (en inglés, `assist: invalid snippet values: `); la metadata describe solo el primero. Los secretos nunca van en la metadata ni en el texto. **`assist.refused`**: el texto es `assist: el equipo no admite este snippet: <motivo>`; el motivo concreto sigue en español hasta su fase de traducción (pasos 2 y 3).

### Detalle de las fases del Job
- `JobPhase` gana `reason` y `args` (campos 5 y 6, sin renumerar); el puente los expone en `PhaseDTO` como `reason` y `args` (ausentes si la fase no lleva detalle) y en los eventos `phaseAdded` (protojson).
- `detail` sigue siendo el texto de hoy en `es` y sale traducido con `en`. Las fases guardadas antes de esta fase no traen `reason` y salen siempre en español.
- Reasons y args: `phase.devices {n}`, `phase.devices_excluded {n, excluded}`, `phase.ok_failed {ok, failed}`, `phase.rounds {n}`, `phase.packaged {path}`, `phase.round_zip_failed {error}`, `phase.close_failed {error}`, `phase.before_arming {}`, `phase.core_stopped {}`. (`error` y `path` vienen tal cual del sistema; no se traducen.)
- Quedan fuera de esta fase, y siguen en español: `DeviceStateChanged.detail`, los `detail` de los equipos de `GetRun` y los motivos de los demás servicios del inventario.

### Nombres de playbooks
Los YAML de `playbooks/` llevan `name_en` (obligatorio en los incrustados; una prueba falla si falta). `listPlaybooks` devuelve `name` en el idioma del contexto: `es` es el nombre de siempre y `en` es `name_en`, con la misma separación « · » entre el área y el nombre, así la agrupación del selector no cambia. Un playbook del usuario sin `name_en` sale con su nombre en los dos idiomas.
