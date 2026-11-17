# ADR 0013: Llaves SSH generadas en el núcleo y hosts que no son Cisco

Fecha: 2026-11-16 · Estado: propuesto · Plan: `docs/plans/2026-11-16-fase-44-llaves-ssh-y-carpetas.md`

## Contexto

El dueño quiere guardar equipos de su LAN que no son Cisco (una Raspberry Pi y un Windows con OpenSSH) y entrar con un toque desde el terminal SSH, siempre con llave y nunca con contraseña. Su regla: «cada aparato genera su propia llave; nunca copiar una privada».

Hoy pasan dos cosas que chocan con esa regla:

- `PutCredentialRequest.ssh_private_key` acepta una llave privada por gRPC y la guarda en la bóveda. Ni mctl ni la UI lo usan, pero cualquier cliente del socket puede importar una privada.
- El respaldo cifrado de la bóveda (`.mcvault`, fase 29d) copia todos los campos de cada credencial, la llave incluida, y su import los trae de vuelta. Un respaldo restaurado en otra máquina es una privada copiada.

Además, la libreta de hosts solo admite plataformas Cisco (`devices.HostPlatforms`), y todo lo que conecta asume un equipo Cisco.

## Decisión

### 1. La privada nace en el núcleo y nunca sale

- **Generación.** `vault.GenerateKey` crea un par ed25519 con `crypto/rand` dentro del paquete `internal/vault`. La privada no pasa por el servicio ni por gRPC: el servicio recibe solo el id y la pública.
- **Almacenamiento.** La privada va en el campo «llave SSH» de la entrada, que ya existe y va cifrado con la DEK (AES-256-GCM). Se guarda en formato OpenSSH sin frase (`-----BEGIN OPENSSH PRIVATE KEY-----`, `ssh.MarshalPrivateKey`). Es el formato que `transport.OpenSSH` ya lee con `ssh.ParsePrivateKey`, así que no hay un segundo formato. El formato del archivo de la bóveda no cambia: ni versión nueva ni migración.
- **Tipo de credencial.** Una credencial es `key` si tiene llave y no tiene contraseña ni enable. Se calcula al listar, no se guarda. Una credencial `key` solo autentica por publickey: `transport.OpenSSH` ofrece password y keyboard-interactive solo si hay contraseña, y eso ya es así hoy.
- **Nada la saca.**
  - Ninguna RPC devuelve la privada. `GetCredentialPublicKey` devuelve solo la pública, en formato authorized_keys con el comentario `macuahuitl@<hostname local>`.
  - El respaldo `.mcvault` no escribe llaves privadas: las credenciales de solo llave no viajan y las que tienen contraseña y llave viajan sin la llave. La respuesta lo cuenta (`ssh_keys_omitted`).
  - El export de hosts nunca llevó secretos (solo la etiqueta de la credencial) y sigue igual.
- **Nada la mete.**
  - `PutCredential` rechaza `ssh_private_key` con InvalidArgument. El campo queda en el proto por compatibilidad de cable, marcado obsoleto en su comentario.
  - El import de un respaldo descarta toda llave privada que traiga, aunque el archivo se haya armado a mano: la de solo llave se omite (estado `llave_privada`) y la que trae contraseña entra sin la llave (`ssh_key_dropped`).
  - `PutCredential` tampoco reemplaza una credencial `key`, porque la convertiría en otra cosa sin generar nada. Para cambiarla se borra y se genera otra.
- **Restaurar es regenerar.** Si se pierde la bóveda, o en una máquina nueva, la llave se genera de nuevo y se autoriza otra vez en cada equipo. Es la consecuencia directa de la regla del dueño.

### 2. Plataformas `linux` y `windows`, solo para el terminal

- `devices.HostPlatforms` suma `linux` y `windows`. Sirven para guardar el host y abrir el terminal SSH, nada más.
- Patrol (todos los tipos de trabajo: patrol, adhoc, backup y change) y el cambio asistido rechazan un objetivo que coincide con un host guardado `linux` o `windows`, con un mensaje que nombra el host. Un equipo que no está en la libreta sigue fallando como hoy, en la detección de la plataforma (`platform.err.unknown`).
- Los playbooks ya no pueden nombrar esas plataformas: `playbook.knownPlatforms` es una lista cerrada de Cisco y no cambia.
- El ADR 0007 sigue intacto: la app no aplica nada en equipos Cisco fuera del modo asistido. Por eso la orden de inicio (punto 3) solo se permite en hosts `linux` y `windows`.

### 3. Orden de inicio por host

- Es una línea de 1 a 256 puntos de código, sin espacios en los extremos y sin caracteres de control (`\p{Cc}`, el tab incluido) ni de formato (`\p{Cf}`: bidi U+202A–202E y U+2066–2069, U+200B–200F, U+FEFF). Los de formato se rechazan porque harían que la orden mostrada no sea la que corre («Trojan Source»). El núcleo es la barrera; la UI solo repite la regla.
- El terminal la manda como **exec con PTY**: `RequestPty` y luego `Start(orden)`, que es lo que hacen `RemoteCommand` + `RequestTTY` de OpenSSH. No se teclea en el shell, porque competiría con el banner y el prompt, y quedaría en el historial del shell remoto. El servidor la interpreta con el shell de la cuenta (en Windows, el `DefaultShell` de OpenSSH, `cmd.exe` por omisión). La sesión termina cuando la orden termina.
- Solo el núcleo decide qué se ejecuta. Con `host_id`, el terminal toma dirección, puerto, credencial y orden del host guardado. `host_id` es exclusivo: si el pedido trae también dirección, puerto o credencial, se rechaza sin conectar, así un cliente alterado no combina un host guardado con otra credencial u otra dirección. La UI manda la orden que mostró (`expected_startup_command`) y, si no es igual a la guardada, no se conecta.
- CheckDenied no aplica, porque es el terminal manual, como hoy. La UI lo dice junto a la orden.
- La orden viaja en el export/import de hosts. Un archivo ajeno puede traer una orden, pero no corre sin que se vea dos veces: la vista previa del import marca cada host que la trae (`has_startup_command`) y la muestra antes de aceptar, y el terminal no conecta si la orden guardada no es la que la UI mostró al conectar.

## Consecuencias

- Un respaldo de la bóveda ya no basta para recuperar el acceso por llave. Hay que regenerar y autorizar de nuevo. La UI y `mctl cred backup export` lo avisan con la cuenta.
- Las credenciales con llave importada por gRPC antes de la fase 44, si existen, siguen autenticando. `cred pubkey` funciona con ellas, pero ya no viajan en respaldos.
- La app deja de ser solo Cisco en un punto acotado: el terminal. Cualquier otra herramienta que se quiera abrir a `linux` o `windows` necesita su propia decisión.
- `docs/security/CRYPTO.md` y `THREAT_MODEL.md` describen la llave generada y su límite: la privada pasa por memoria de Go sin bloquear al generarla y al firmar, igual que la contraseña (límite declarado 1).
