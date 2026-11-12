# MACUAHUITL — Diseño de arquitectura base

**M.A.C.U.A.H.U.I.T.L.** = Multi-vendor Automated Command & Unitary Audit Hub Unified for Interface Telemetry & Logging

| Campo | Valor |
|---|---|
| Fecha | 2026-11-02 |
| Estado | Aprobado 2026-11-03 |
| Repo | https://github.com/oom-netsec/MACUAHUITL |
| Alcance de este documento | Arquitectura, contratos, estructura de carpetas, modelo de seguridad y fases. No incluye código. |

Convención: lo marcado **[Decidido]** lo eligió el dueño del proyecto. Lo marcado **[Propuesta]** es decisión del arquitecto y puede corregirse. Lo marcado **[Builder]** queda a criterio de quien implemente.

---

## 1. Intención

Una herramienta de escritorio para ingenieros de red de nivel TAC. Desde la laptop del ingeniero, sin nube, permite:

1. Recolectar evidencia de equipos Cisco por SSH o API con playbooks por plataforma, de forma programada y empaquetada (módulo **Patrol**).
2. Guardar credenciales cifradas de modo que un auditor externo pueda comprobar que nunca se escriben en claro, nunca se registran y nunca salen hacia destinos que el ingeniero no eligió.
3. Diagnosticar red activamente: ping, traceroute, nmap, iperf y captura PCAP.
4. Diseñar ACLs de forma visual y generar los scripts para varios fabricantes.

Por qué: hoy esto se hace con scripts sueltos, terminales abiertas a mano y credenciales en archivos de texto. Un caso TAC exige evidencia completa, con hora exacta y repetible, y el cliente exige que sus secretos no se filtren.

## 2. Metas, no-metas y anti-metas

**Metas**
- Una herramienta individual: un ingeniero, su laptop, su bóveda. **[Decidido]**
- Linux como único sistema operativo soportado. **[Decidido]**
- Backend en Go, UI de escritorio desacoplada, almacenamiento 100 % local con SQLite y sistema de archivos. **[Decidido]**
- Proceso núcleo separado de la UI, comunicados por un socket local. **[Decidido: camino 2]**
- Cobertura por playbooks de IOS/IOS-XE, NX-OS, Catalyst 9000, WLC, ISE, FTD/Firepower y SD-Access. **[Decidido]**
- Patrol con Login Test obligatorio, estado en vivo, programador, estrategia de archivos y empaquetado .zip. **[Decidido]**
- Enmascarado de secretos en los outputs, decidido en cada recolección. **[Decidido]** Encendido por defecto. **[Propuesta]**

**No-metas (por ahora)**
- Windows y macOS.
- Modo multiusuario o servidor compartido.
- Sincronización, respaldo en la nube, telemetría, verificación automática de actualizaciones.
- Fabricantes distintos de Cisco en Patrol. La arquitectura los admite por diseño, pero no se entregan playbooks. El generador de ACLs sí es multi-vendor desde su fase.
- Aplicar cambios de configuración en los equipos. Patrol solo lee. Los scripts de ACL se generan como texto que el ingeniero aplica a mano. **[Propuesta]**

**Anti-metas: el proyecto fracasa si...**
- Una credencial aparece en claro en disco, en un log, en un volcado de memoria o en un output por culpa del código del proyecto. La copia que el sistema operativo pueda mandar a swap o hibernación es un límite declarado con mitigaciones (§10.3), no un fallo. **[Propuesta]**
- La aplicación abre una conexión hacia un destino que el ingeniero no escribió.
- Cualquier proceso propio del proyecto necesita correr como root.
- Una recolección "tiene éxito" sin evidencia de qué se ejecutó, cuándo y contra qué equipo.

## 3. Restricciones

- Distribuciones objetivo: Ubuntu 24.04+, Debian 12+, Fedora 40+, RHEL/Rocky 9+. **[Propuesta]**
- La UI usa el motor web del sistema (WebKitGTK), así que exige que esté instalado.
- nmap y la captura de paquetes requieren capacidades de red de Linux. Se obtienen de las herramientas del sistema, no de código propio con privilegios (ver §9).
- Equipos Cisco antiguos negocian algoritmos SSH débiles. Se permiten solo por perfil de equipo, de forma explícita, y quedan registrados en auditoría.

## 4. Enfoques considerados

| Enfoque | Qué es | A favor | En contra |
|---|---|---|---|
| 1. App Wails única | UI y backend en un binario, llamadas directas | Lo más simple de construir y distribuir | Patrol se detiene al cerrar la ventana. La separación frontend/backend depende de disciplina, no de una frontera real |
| **2. Servicio de fondo + clientes** | Núcleo Go como servicio de usuario de systemd. UI Wails y CLI se conectan por socket Unix | Frontera real y auditable. Patrol corre sin UI. Permite CLI y pruebas sin UI | Más piezas que instalar. Para tareas nocturnas la bóveda queda abierta en memoria del servicio durante una ventana acotada |
| 3. Núcleo + plugins en procesos | Cada módulo como ejecutable cargado por el núcleo | Máxima extensibilidad | Maquinaria excesiva para una herramienta individual. Los playbooks se resuelven mejor como datos |

**Elegido: enfoque 2.** **[Decidido]** Es el único que cumple la separación estricta, el requisito de "no monolítico" y un programador que no dependa de la ventana abierta.

## 5. Arquitectura general

```
┌──────────────────────── Laptop del ingeniero (Linux, un usuario) ────────────────────────┐
│                                                                                           │
│  ┌─────────────────────────┐        ┌──────────────┐                                      │
│  │ macuahuitl (UI, Wails)  │        │ mctl (CLI)   │      Clientes: sin estado propio,    │
│  │ React + TypeScript      │        │              │      sin acceso a bóveda ni red      │
│  │ capa Go = cliente gRPC  │        │              │                                      │
│  └───────────┬─────────────┘        └──────┬───────┘                                      │
│              │  gRPC sobre socket Unix  (0600, verificación SO_PEERCRED = mismo UID)      │
│              ▼                             ▼                                              │
│  ┌──────────────────────────────── macuahuitld (núcleo) ───────────────────────────────┐  │
│  │  ipc ─► servicios: Vault · Patrol · Diag · ACL · Audit · Inventory · Settings      │  │
│  │                                                                                     │  │
│  │  engine: Scheduler ─► JobRunner ─► pool de workers (semáforo global +               │  │
│  │          un worker por equipo) ─► EventBus ─► streams hacia clientes                │  │
│  │                                                                                     │  │
│  │  transport: SSH · HTTPS-API  ─── todo pasa por EgressGuard (lista de destinos) ──┐  │  │
│  │  vault (Argon2id + AES-256-GCM, llaves en memoria bloqueada)                     │  │  │
│  │  audit (cadena de hashes) · store (SQLite) · outputs (FS) · mask · zip           │  │  │
│  │  diag: invoca ping/traceroute/nmap/iperf3/dumpcap del sistema (sin shell)        │  │  │
│  └──────────────────────────────────────────────────────────────────────────────────┼──┘  │
│                                                                                      │     │
└──────────────────────────────────────────────────────────────────────────────────────┼─────┘
                                                                                       ▼
                                  Solo destinos escritos por el ingeniero: equipos Cisco
                                  (SSH/22 o puerto definido), ISE / Catalyst Center (HTTPS)
```

### 5.1 Procesos

| Proceso | Rol | Corre como |
|---|---|---|
| `macuahuitld` | Núcleo: bóveda, motor, red, almacenamiento, auditoría | Servicio de usuario de systemd (`systemctl --user`). Nunca root |
| `macuahuitl` | UI de escritorio | Usuario. Arranca el servicio si no está activo |
| `mctl` | CLI para scripting, pruebas y uso sin UI | Usuario |

No hay proceso propio con privilegios. Ver §9.

### 5.2 Comunicación UI ↔ núcleo

- **Protocolo:** gRPC sobre socket Unix en `$XDG_RUNTIME_DIR/macuahuitl/core.sock`. **[Propuesta]** Contratos en Protocol Buffers versionados (`api/proto/macuahuitl/v1`), generados con `buf`.
- **Autenticación local:** permisos 0600 en el socket y en su directorio, más verificación `SO_PEERCRED`: el UID del cliente debe ser igual al del servicio. Sin esto, se rechaza la conexión.
- **Tiempo real:** streams de servidor de gRPC. La capa Go de Wails recibe el stream y lo reenvía al frontend como eventos de Wails.
- **Por qué gRPC y no REST/WebSocket:** contrato tipado y versionado que el auditor puede leer, streaming nativo, y no abre ningún puerto TCP.

### 5.3 Stack de UI **[Propuesta]**

- **Wails** (fijar la versión estable vigente al iniciar; v3 si ya es estable, si no v2). **[Builder]** confirma.
- **React + TypeScript + Vite.** Elegido sobre Svelte por el ecosistema: React Flow para el editor visual de ACLs y TanStack Table para grillas grandes de estado.
- Sin llamadas de red desde el frontend. La política de contenido (CSP) del webview prohíbe `connect-src` externos.

## 6. Motor de concurrencia

Objetivo: cientos de sesiones SSH simultáneas sin agotar las líneas VTY de los equipos ni bloquear la UI.

- **Scheduler:** lee los trabajos programados de SQLite y dispara rondas. Soporta intervalo fijo, número de rondas o fecha de fin, y expresiones cron. **[Propuesta]**
- **JobRunner:** una gorrutina por trabajo. Cada ronda reparte los equipos entre workers con `errgroup` y un `context` cancelable.
- **Límite global:** semáforo de sesiones simultáneas, por defecto 50, configurable. **[Propuesta]**
- **Un worker por equipo:** nunca dos sesiones al mismo equipo del mismo trabajo. Evita agotar VTY y mezclar salidas.
- **Por equipo:** una máquina de estados: `en cola → conectando → autenticando → detectando plataforma → ejecutando (k/N) → completado | falló | cancelado`.
- **Timeouts:** de conexión, de autenticación, por comando (definido en el playbook) y de ronda.
- **Reintentos:** solo en fallos de conexión, con espera creciente. Nunca se reintenta un fallo de autenticación, para no bloquear cuentas en TACACS.
- **Keepalive:** `keepalive@openssh.com` cada 15 s en la sesión SSH. Además el EventBus emite un latido por trabajo cada 5 s para que la UI distinga "lento" de "colgado". **[Propuesta]**
- **EventBus:** publica eventos tipados. Cada suscriptor tiene un búfer acotado. Si un cliente lento se atrasa, se combinan los eventos de progreso y nunca se descartan los de cambio de estado ni los de error.

## 6.1 Qué es "un destino que escribió el ingeniero" **[Propuesta]**

- **Nombres DNS:** permitidos. La resolución usa el resolvedor del sistema. EgressGuard autoriza las IPs que resuelve ese nombre para ese trabajo, y registra nombre e IPs.
- **Rangos:** un trabajo o un escaneo puede recibir rangos CIDR escritos por el ingeniero. Cada IP del rango cuenta como escrita.
- **Equipos descubiertos (SD-Access):** las direcciones que devuelve Catalyst Center se muestran como lista para confirmar. Solo tras la confirmación entran al trabajo. Hasta entonces EgressGuard las rechaza.
- **Herramientas de diagnóstico externas:** ping, traceroute, nmap, iperf3 y dumpcap abren sus propias conexiones fuera de EgressGuard. El núcleo valida sus argumentos: el destino debe ser una IP, nombre o rango escrito en esa misma petición, y no se permiten opciones que lean destinos de archivos o scripts (por ejemplo `-iL` o `--script` de nmap). Cada ejecución queda en auditoría con su línea de argumentos completa. La promesa ante el auditor se formula así: el código propio solo conecta vía EgressGuard, y las herramientas externas solo se lanzan con destinos validados y registrados.

## 7. Transporte y plataformas

- **SSH:** `golang.org/x/crypto/ssh`. Para manejo de prompts, paginación y modos de privilegio se evalúa **scrapligo**, que ya resuelve plataformas Cisco. **[Builder]** decide si se usa o se escribe un driver propio delgado.
- **Llaves de host:** confianza en el primer uso con confirmación explícita del ingeniero. Un cambio de llave bloquea la conexión y se registra. Se guardan en `known_hosts` propio de la app.
- **Perfiles de equipo:** puerto, algoritmos heredados permitidos, si usa `enable`, tipo de credencial.
- **APIs HTTPS:** ISE (ERS / OpenAPI) y Catalyst Center (para SD-Access) usan HTTPS hacia el host que el ingeniero escribe. Verificación TLS estricta, con opción de fijar un certificado autofirmado por host de forma explícita.

### 7.1 Matriz de plataformas

| Plataforma | Acceso | Notas |
|---|---|---|
| IOS / IOS-XE | SSH CLI | Referencia para el primer driver |
| Catalyst 9000 | SSH CLI | Mismo driver que IOS-XE. Playbooks propios (plataforma, stack, PoE, etc.) |
| NX-OS | SSH CLI | Driver propio: prompts y paginación distintos |
| WLC 9800 | SSH CLI | IOS-XE |
| WLC AireOS | SSH CLI | Login interactivo propio (pide usuario dentro de la sesión) |
| FTD / Firepower | SSH CLI | Modos `>` (CLISH), `expert`, y diagnóstico LINA. El driver cambia de modo |
| ISE | SSH CLI + API | La CLI de ISE es limitada. La evidencia útil viene por API |
| SD-Access | API Catalyst Center + SSH a nodos de fabric | Los nodos de fabric usan el driver IOS-XE |

## 8. Playbooks

- **Formato:** YAML declarativo, uno o más por plataforma, versionados en `playbooks/cisco/<plataforma>/`. Se incrustan en el binario con `go:embed`. El ingeniero puede añadir los suyos en `~/.config/macuahuitl/playbooks/`. **[Propuesta]**
- **Contenido:** plataforma, reglas de detección (expresión sobre `show version`), comandos previos (`terminal length 0`, etc.), conjuntos de comandos con nombre (por ejemplo `tac-baseline`, `cpu-alta`, `errores-interfaz`), timeout por comando, y si el comando puede contener secretos (pista para el enmascarado).
- **Validación:** esquema JSON verificado al cargar. Un playbook inválido no carga y se reporta.
- **Comandos pegados por el usuario:** se tratan como un playbook efímero. Se registra su hash en auditoría.
- **Seguridad:** Patrol solo lee. Un validador rechaza comandos de modo configuración (`conf t`, `write`, `reload`, `copy ... running`, `delete`, etc.) por lista de denegación por plataforma. **[Propuesta]**

## 9. Diagnóstico activo y privilegios

Principio: el proyecto no incluye código propio con privilegios. Se reutilizan herramientas del sistema que ya resuelven sus permisos.

| Herramienta | Cómo | Privilegio |
|---|---|---|
| Ping | ICMP sin privilegios de Linux (`net.ipv4.ping_group_range`) desde Go | Ninguno |
| Traceroute | `traceroute` / `tracepath` del sistema | Ninguno (tracepath) |
| nmap | Binario `nmap` del sistema | Escaneos SYN requieren capacidades. El instalador documenta la opción, no la impone |
| iperf | Binario `iperf3` del sistema, cliente y servidor | Ninguno |
| PCAP | `dumpcap` de Wireshark | Grupo `wireshark` del sistema |

- Se invocan con `exec` y argumentos construidos desde un objeto validado. Nunca a través de un shell.
- Los resultados se guardan como outputs normales y se registran en auditoría.
- Esto reemplaza la idea inicial de un ayudante propio con capacidades: menos código privilegiado que auditar. **[Propuesta]**
- `DiagService.ListInterfaces` lista las interfaces locales (nombre, estado, loopback, direcciones CIDR, MAC) leyendo el sistema; no genera tráfico (`mctl diag interfaces`).

## 10. Bóveda de credenciales (Zero-Knowledge local)

### 10.1 Promesas verificables

1. Ninguna credencial se escribe en claro a disco.
2. Ninguna credencial aparece en logs, auditoría, outputs, mensajes de error ni volcados.
3. La aplicación solo conecta a destinos escritos por el ingeniero.
4. La contraseña maestra nunca se guarda. Si se pierde, la bóveda es irrecuperable, y eso es intencional.

### 10.2 Formato y criptografía **[Propuesta]**

- **Archivo:** `~/.local/share/macuahuitl/vault.mcv`, permisos 0600.
- **Encabezado:** identificador mágico, versión de formato, ID de bóveda, parámetros de Argon2id y sal de 16 bytes.
- **Derivación:** Argon2id con 256 MiB de memoria, 3 iteraciones y 4 hilos como base. Se calibran en el primer uso para tardar cerca de 1 s en la máquina. Los parámetros quedan en el encabezado.
- **Jerarquía de llaves:**
  - KEK = Argon2id(contraseña maestra, sal).
  - DEK = 32 bytes aleatorios, guardada cifrada con la KEK (AES-256-GCM).
  - Cambiar la contraseña maestra solo vuelve a cifrar la DEK.
- **Entradas:** cada credencial (usuario, contraseña, enable, llave SSH opcional, etiqueta) se cifra por separado con la DEK. AES-256-GCM, nonce aleatorio de 96 bits por escritura. Datos asociados = ID de bóveda + ID de entrada + versión, para que una entrada no pueda moverse a otra posición sin detectarse.
- **Credenciales por equipo [Decidido 2026-11-03]:** cada trabajo tiene una credencial por defecto, y cada equipo puede tener la suya propia y una de respaldo local para cuando TACACS no responde. Desde el cliente no se distingue "AAA caído" de "contraseña rechazada", así que la regla es: el respaldo se intenta una sola vez tras un rechazo de la principal, solo si esa principal pasó el Login Test de ese equipo al armar el trabajo, y nunca durante el Login Test. Cada uso queda en auditoría como `auth.fallback`.
- **Todo cifrado:** incluso las etiquetas. En SQLite solo existe el ID opaco de la credencial.
- **Escritura atómica:** archivo temporal, `fsync`, renombrar. Un respaldo previo `vault.mcv.bak`.
- **Solo primitivas estándar:** `crypto/aes`, `crypto/cipher`, `golang.org/x/crypto/argon2`, `crypto/rand`. Nada de criptografía propia.

### 10.3 Vida en memoria **[Propuesta]**

- La DEK vive en memoria bloqueada (`mlock`, páginas guardia) con `memguard`, mientras la bóveda está abierta.
- Una credencial se descifra justo antes de autenticar y se borra al terminar la autenticación.
- **Límite conocido y declarado:** `x/crypto/ssh` recibe la contraseña como `string` de Go, que no se puede borrar. Esa copia vive hasta que el recolector de basura la libere. Se documenta en el modelo de amenazas. Se mitiga con la vida mínima y lo siguiente.
- Al arrancar: `prctl(PR_SET_DUMPABLE, 0)` y `RLIMIT_CORE = 0` para evitar volcados de memoria.
- Tipo `Secret` cuyos métodos `String`, `Format`, `MarshalJSON` y `LogValue` devuelven `[REDACTED]`. Imposible imprimirlo por accidente.
- **Cierre automático:** por inactividad (15 min por defecto), al bloquear la pantalla (señal de logind) y al apagar. Estos cierres no afectan a una ventana programada ya autorizada (§10.4).
- **Swap e hibernación:** el servicio intenta `mlockall` para que su memoria no vaya a swap. Al arrancar revisa si hay swap sin cifrar o hibernación activa y, si la hay, muestra un aviso persistente y lo registra en auditoría. No se niega a correr. **[Propuesta]**

### 10.4 Ventana de bóveda para tareas programadas **[Propuesta]**

- Un trabajo programado requiere que el ingeniero lo **arme**: al armarlo autoriza una ventana y la DEK queda en memoria del servicio hasta la hora de fin del trabajo. Duración configurable por trabajo, máximo 4 días. **[Decidido]** Una recolección más larga se arma como un trabajo nuevo con su propia ventana.
- La ventana se abre al armar, no a la hora de la primera ronda. Si el trabajo empieza a las 03:00, la llave está en memoria desde que se armó. La UI lo dice antes de confirmar.
- Bloquear la pantalla o la inactividad no cierran una ventana armada. Cerrar sesión de Linux sí, salvo que el ingeniero active "seguir tras cerrar sesión" (systemd linger), que el instalador ofrece pero no activa.
- **Mantener la laptop despierta [Decidido]:** mientras haya una ventana armada, el sistema no debe suspenderse, hibernar ni apagarse. Solo se permite atenuar la pantalla. **[Propuesta]** de cómo: el servicio toma bloqueos de inhibición de logind (`sleep`, `idle`, `handle-lid-switch`, `shutdown`) en vez de cambiar la configuración del sistema. Se liberan solos al cerrar la ventana o si el servicio muere, así nunca queda la laptop alterada. Tomarlos y soltarlos queda en auditoría. Si el sistema no permite tomar alguno, la UI lo avisa antes de armar.
- Suspensión, reinicio del servicio o de la laptop borran la DEK. El trabajo queda **en pausa** y espera a que el ingeniero vuelva a abrir la bóveda. Las rondas perdidas se registran como omitidas, no se recuperan.
- Solo las credenciales referenciadas por ese trabajo pueden descifrarse durante la ventana.
- Abrir y cerrar la ventana queda en auditoría. Al terminar la última ronda la DEK se borra.

### 10.5 Cómo se demuestra ante un auditor

| Promesa | Evidencia |
|---|---|
| Sin claro en disco | Formato documentado en `docs/security/CRYPTO.md`. Prueba automática que crea una bóveda con una contraseña marcador y busca ese marcador en todos los archivos de la app |
| Sin secretos en logs | Tipo `Secret` + redacción en `slog`. Prueba que corre un Patrol completo contra el simulador y busca el marcador en logs, auditoría, outputs y SQLite |
| Sin conexiones ajenas | (a) Analizador estático en CI que prohíbe importar `net`, `net/http` y similares fuera de `internal/transport` y `internal/diag`. (b) `EgressGuard`: todo `Dial` pasa por un marcador que solo permite destinos del trabajo en curso, y registra los rechazos. (c) Sin telemetría ni actualizaciones automáticas. (d) Unidad systemd con `RestrictAddressFamilies` |
| Binario = código | Compilación reproducible (`-trimpath`, toolchain fijo), SBOM en cada release, `govulncheck` en CI, sumas SHA-256 firmadas |
| Diseño revisable | `docs/security/THREAT_MODEL.md` con amenazas, mitigaciones y límites declarados |

## 11. Auditoría

- Tabla `audit_log` en SQLite, solo inserción. Cada registro guarda el hash SHA-256 del registro anterior más el suyo: cualquier borrado o edición rompe la cadena.
- `mctl audit verify` recorre la cadena y reporta la primera rotura.
- **Qué se registra:** quién (usuario de Linux), qué (acción, trabajo, equipo, hash de comandos), cuándo (UTC), resultado, si el output salió con secretos o enmascarado, apertura y cierre de bóveda y de ventanas.
- **Qué nunca se registra:** contraseñas, llaves, el contenido de los outputs.
- Exportable a JSON Lines para entregar a un auditor.
- **Ancla externa:** cada `manifest.json` incluye el hash del último registro de auditoría al cerrar el trabajo. Quien recibe el .zip guarda así un punto de la cadena que el ingeniero ya no puede reescribir sin que se note.
- **Contra quién protege:** daños accidentales en la laptop, más el ancla del manifest para quien recibe el .zip. Basta con eso. **[Decidido]** Sin firma externa.

## 12. Patrol

### 12.1 Definición de un trabajo

- **Objetivos:** IPs o nombres pegados en bloque, o equipos del inventario local.
- **Credencial:** una por defecto para el trabajo, con excepciones por equipo y respaldo local (§10.2).
- **Comandos:** playbook por plataforma detectada, comandos pegados, o ambos.
- **Ruta de output:** carpeta local elegida por el ingeniero.
- **Separación de archivos:**
  - `por-ronda`: un archivo por equipo por ronda.
  - `consolidado`: un archivo por equipo con todas las rondas, separadas por encabezados con hora.
- **Programador:** una vez, cada N minutos durante X rondas o hasta una hora, o cron.
- **Empaquetado .zip:** ninguno, al final de cada ronda, o al terminar el trabajo. Opción de borrar los archivos sueltos tras empaquetar.
- **Enmascarado:** interruptor por trabajo, encendido por defecto.

### 12.2 Login Test obligatorio

Antes de la primera ronda, por cada equipo: TCP alcanzable → llave de host aceptada → autenticación → nivel de privilegio o `enable` → detección de prompt → detección de plataforma y coincidencia con el playbook.

El trabajo no arranca hasta que todos pasan. Alternativa: el ingeniero excluye de forma explícita a los que fallaron, y la exclusión queda en auditoría.

**Rondas sin nadie presente:** el Login Test completo con confirmaciones se hace al armar el trabajo. Antes de cada ronda programada se repite en silencio. Si un equipo falla, se omite en esa ronda, se marca en el manifest y en auditoría, y la ronda sigue con los demás.

Si un equipo presenta una llave de host distinta, la decide una casilla por trabajo. **[Decidido]**
- **Desmarcada (por defecto):** se omite el equipo en esa ronda y se registra. Nunca se manda la credencial a un equipo no reconocido.
- **Marcada:** se acepta la llave nueva y se continúa. Al marcarla, la UI advierte que esto expone la credencial ante un posible intermediario. Cada llave aceptada así queda en auditoría y en el manifest con la huella anterior y la nueva.

### 12.3 Estado en vivo

La UI muestra una grilla por equipo con su estado, el comando en curso, bytes recibidos, duración y último latido. Un clic abre la salida en tiempo real del equipo.

### 12.4 Estructura de outputs

```
<ruta-elegida>/
└── <trabajo>_<AAAAMMDD-HHMMSS>/
    ├── manifest.json          # trabajo, versión app, playbook+hash, equipos, rondas, enmascarado sí/no
    ├── <hostname>_<ip>/
    │   ├── r001_20261102-230000.txt     # por-ronda
    │   └── ...
    └── <trabajo>_<AAAAMMDD-HHMMSS>.zip
```

`manifest.json` incluye el SHA-256 de cada archivo, para que TAC o el cliente verifiquen integridad.

### 12.5 Enmascarado

- Reglas por plataforma en `internal/mask` (contraseñas tipo 0/5/7/8/9, `key`, `secret`, comunidades SNMP, llaves TACACS/RADIUS, PSK, certificados privados).
- Reemplazo por `<MASKED:tipo>` conservando la línea, para que el config siga siendo legible.
- Se aplica al escribir el output, no después. Si el enmascarado está apagado, la UI muestra un aviso persistente en ese trabajo.

## 13. Generador de ACLs

- **Modelo interno neutral:** lista ordenada de reglas con acción, protocolo, origen, destino, puertos, log y comentario. Objetos de red y de servicio reutilizables.
- **Editor visual:** tabla ordenable más vista de flujo (React Flow) para ver qué tráfico pasa entre zonas.
- **Análisis:** reglas sombreadas, redundantes y sin coincidencias posibles.
- **Generadores:** Cisco IOS/IOS-XE, NX-OS y ASA en la primera entrega. Junos y Arista EOS después. **[Propuesta]**
- **Importación:** parser de ACLs Cisco existentes, para analizar lo que ya hay.
- Salida como texto. Nunca se empuja a un equipo.

## 14. Almacenamiento

| Qué | Dónde |
|---|---|
| Configuración | `~/.config/macuahuitl/config.toml` |
| Playbooks del usuario | `~/.config/macuahuitl/playbooks/` |
| Bóveda | `~/.local/share/macuahuitl/vault.mcv` |
| Base de datos | `~/.local/share/macuahuitl/macuahuitl.db` |
| known_hosts | `~/.local/share/macuahuitl/known_hosts` |
| Logs técnicos | `~/.local/state/macuahuitl/logs/` (rotación) |
| Outputs | Ruta elegida por trabajo. Por defecto `~/MACUAHUITL/outputs` |

- **SQLite:** `modernc.org/sqlite` (Go puro, sin cgo), modo WAL, migraciones versionadas. **[Propuesta]**
- **Tablas iniciales:** `devices`, `device_profiles`, `jobs`, `job_runs`, `run_devices`, `credentials_ref`, `playbooks_index`, `audit_log`, `settings`, `schema_migrations`.
- **Historial del trabajo:** `jobs.history_json` (migración 0002) guarda hora de armado, fin de ventana, carpeta, ronda y conteos, y las últimas 200 fases (`JobPhaseKind`: creado, Login Test, armado, ronda iniciada/terminada/omitida, empaquetado, completado, cancelado, fallido). `ListJobs` las devuelve en `JobSummary` y `Subscribe` emite cada fase nueva como `phase_added`. Al arrancar, el núcleo recarga los trabajos; uno que quedó armado se marca `failed`.

## 15. Estructura de carpetas

```
MACUAHUITL/
├── api/proto/macuahuitl/v1/      # Contratos gRPC: vault, patrol, diag, acl, audit, inventory, events
├── gen/                          # Código generado por buf (no se edita a mano)
├── cmd/
│   ├── macuahuitld/              # Núcleo (servicio)
│   └── mctl/                     # CLI
├── internal/
│   ├── core/                     # Arranque, ciclo de vida, cableado de servicios
│   ├── ipc/                      # Servidor gRPC, socket Unix, SO_PEERCRED
│   ├── secret/                   # Tipo Secret, borrado, redacción
│   ├── vault/                    # Formato, KDF, cifrado, ventanas
│   ├── audit/                    # Cadena de hashes, verificación, exportación
│   ├── store/                    # SQLite, migraciones, repositorios
│   ├── engine/                   # Scheduler, JobRunner, workers, EventBus
│   ├── transport/                # SSH, HTTPS, EgressGuard, known_hosts
│   ├── platform/                 # Drivers Cisco: iosxe, nxos, aireos, ftd, ise, catcenter
│   ├── playbook/                 # Carga, esquema, validación, lista de denegación
│   ├── patrol/                   # Trabajos, Login Test, escritura de outputs, manifest, zip
│   ├── mask/                     # Reglas de enmascarado por plataforma
│   ├── diag/                     # Ping, traceroute, nmap, iperf3, dumpcap
│   └── acl/                      # Modelo, parser, análisis, generadores por fabricante
├── playbooks/cisco/
│   ├── ios-xe/  ├── cat9k/  ├── nx-os/  ├── wlc-9800/  ├── wlc-aireos/
│   ├── ftd/     ├── ise/    └── sda/
├── ui/                           # Proyecto Wails
│   ├── main.go  app.go           # Capa Go: cliente gRPC → eventos Wails
│   └── frontend/src/
│       ├── app/                  # Shell, rutas, tema
│       ├── modules/              # vault/ patrol/ diag/ acl/ audit/ inventory/ settings/
│       ├── components/           # Componentes compartidos
│       └── lib/                  # Cliente de eventos, tipos generados
├── tools/
│   └── noegress/                 # Analizador estático: prohíbe red fuera de transport/diag
├── test/
│   ├── simulator/                # Servidor SSH falso que imita prompts Cisco desde transcripciones
│   ├── transcripts/              # Salidas reales anonimizadas por plataforma
│   └── e2e/                      # Pruebas de punta a punta con el simulador
├── deploy/
│   ├── systemd/macuahuitld.service
│   └── packaging/                # nfpm: .deb y .rpm
├── docs/
│   ├── architecture/             # Este diseño, diagramas
│   ├── adr/                      # Registros de decisiones (una por archivo)
│   ├── security/                 # THREAT_MODEL.md, CRYPTO.md, AUDIT_GUIDE.md
│   └── plans/                    # Planes de implementación por fase
├── .github/workflows/            # CI: lint, test, noegress, govulncheck, build reproducible
├── go.mod                        # Un solo módulo Go
├── buf.yaml  buf.gen.yaml
├── Taskfile.yml
├── README.md  SECURITY.md  CONTRIBUTING.md  LICENSE
```

## 16. Pruebas

- **Unitarias** por paquete. La criptografía con vectores conocidos y pruebas de alteración (un byte cambiado debe fallar).
- **Simulador SSH** (`test/simulator`): reproduce prompts, paginación, `enable` y errores por plataforma a partir de transcripciones. Permite probar Patrol sin laboratorio.
- **Pruebas de no-filtración:** las de §10.5.
- **Laboratorio real:** el dueño tiene dos APs, un equipo IOS-XE y un switch IOS. **[Decidido]** Cubre la fase 1. Para NX-OS, WLC, FTD, ISE y Catalyst Center no hay equipos: las fases 2 y 3 incluyen un paso previo para conseguir transcripciones reales anonimizadas o imágenes virtuales. Sin ellas, el simulador solo prueba el driver contra sí mismo.
- **CI:** `go vet`, `staticcheck`, `noegress`, `govulncheck`, pruebas con `-race`, lint del frontend.

## 17. Fases y alcances

| Fase | Entrega | Criterio de terminado |
|---|---|---|
| 0. Raíces | Este documento, ADRs iniciales, estructura de carpetas, CI vacío en verde, contratos `.proto` v1 | Repo compila sin funcionalidad. CI corre `noegress` |
| 1. Núcleo + Patrol IOS-XE | Servicio, IPC, bóveda, auditoría, SQLite, motor, driver IOS-XE, Login Test, outputs, zip, enmascarado, UI de bóveda y Patrol, CLI | Patrol programado contra el simulador y contra un IOS-XE real, con todas las pruebas de no-filtración en verde |
| 2. Plataformas CLI | NX-OS, Cat9k, WLC 9800, AireOS, FTD | Playbooks y driver por plataforma, probados en simulador |
| 3. Plataformas API | ISE, Catalyst Center / SD-Access | Recolección API con el mismo modelo de outputs y auditoría |
| 4. Diagnóstico | Ping, traceroute, nmap, iperf3, PCAP | Cada herramienta desde UI y CLI, con resultados en outputs |
| 5. ACLs | Modelo, editor visual, análisis, generadores Cisco | Importar, analizar y generar IOS-XE/NX-OS/ASA |
| 6. Release | Paquetes .deb/.rpm, build reproducible, SBOM, guía de auditoría | Un tercero reproduce el binario y verifica las promesas de §10.1 |

## 18. Lo que queda al builder

- Versión exacta de Wails y de Go.
- Usar scrapligo o un driver propio.
- Librería de cron y de zip (la estándar `archive/zip` basta).
- Diseño visual detallado de la UI.
- Calibración final de Argon2id y del límite de sesiones.
- Licencia del proyecto: Apache-2.0. **[Decidido 2026-11-03]** El proyecto es para todo el mundo.
