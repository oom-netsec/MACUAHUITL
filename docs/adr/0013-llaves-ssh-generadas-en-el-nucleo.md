# ADR 0013: Llaves SSH generadas en el núcleo y hosts que no son Cisco

Fecha: 2026-11-16 · Estado: propuesto · Plan: `docs/plans/2026-11-16-fase-44-llaves-ssh-y-carpetas.md`

## Contexto

El dueño quiere guardar equipos de su LAN que no son Cisco (una Raspberry Pi y un Windows con OpenSSH) y entrar con un toque desde el terminal SSH, siempre con llave y nunca con contraseña. Su regla: «cada aparato genera su propia llave; nunca copiar una privada».

Hoy pasan dos cosas que tienen que ver con esa regla:

- `PutCredentialRequest.ssh_private_key` acepta una llave privada por gRPC y la guarda en la bóveda. Ni mctl ni la UI lo usan, pero cualquier cliente del socket puede importar una privada de fuera.
- El respaldo cifrado de la bóveda (`.mcvault`, fase 29d) copia todos los campos de cada credencial, con la llave, y su import los trae de vuelta.

Además, la libreta de hosts solo admite plataformas Cisco (`devices.HostPlatforms`), y todo lo que conecta asume un equipo Cisco.

## Decisión

### 1. La privada nace en el núcleo y solo sale cifrada en el respaldo

- **Generación.** `vault.GenerateKey` crea un par ed25519 con `crypto/rand` dentro del paquete `internal/vault`. La privada no pasa por el servicio ni por gRPC: el servicio recibe solo el id y la pública.
- **Almacenamiento.**
  - La privada va en el campo «llave SSH» de la entrada, que ya existe y va cifrado con la DEK (AES-256-GCM).
  - Se guarda en formato OpenSSH sin frase (`-----BEGIN OPENSSH PRIVATE KEY-----`, armado a mano en `internal/vault/keygen.go` (`noegress` prohíbe `x/crypto/ssh` en `vault` y `core`); la interoperabilidad se prueba con `x/crypto/ssh` en `internal/transport`). Es el formato que `transport.OpenSSH` ya lee con `ssh.ParsePrivateKey`, así que no hay un segundo formato.
  - El formato del archivo de la bóveda no cambia: ni versión nueva ni migración.
- **Tipo de credencial.** Una credencial es `key` si tiene llave y no tiene contraseña ni enable. Se calcula al listar, no se guarda. Una credencial `key` solo autentica por publickey: `transport.OpenSSH` ofrece password y keyboard-interactive solo si hay contraseña, y eso ya es así hoy.
- **Regenerar.** `vault.RegenerateKey(id)` reemplaza la privada de una credencial `key` por una nueva y conserva el id, la etiqueta y el usuario. La vieja se destruye. Los hosts que apuntan a esa credencial no cambian; solo hay que autorizar la pública nueva en cada equipo.
- **Por dónde sale.**
  - Ninguna RPC ni el CLI devuelven la privada. `GetCredentialPublicKey` devuelve solo la pública, en formato authorized_keys con el comentario `macuahuitl@<hostname local>`.
  - **El respaldo `.mcvault` sí la lleva**, cifrada como el resto del respaldo: un archivo de bóveda nuevo, con su propia sal y su propia DEK, sellado con una frase de al menos 12 caracteres distinta de la maestra. Su import la restaura. **Fue decisión del dueño (2026-11-16)**: a cambio de comodidad al cambiar de laptop, se acepta que la privada viaje en un archivo que él guarda. Es una excepción acotada a su regla de no copiar privadas: solo viaja dentro de ese archivo cifrado, nunca suelta. La respuesta del export cuenta cuántas llaves lleva (`ssh_keys_included`), y la UI y mctl lo avisan antes y después de exportar.
  - El export de hosts nunca llevó secretos (solo la etiqueta de la credencial) y sigue igual.
- **Nada mete una privada de fuera** (hasta la fase 47; ver §1b).
  - `PutCredential` rechaza `ssh_private_key` con InvalidArgument. El campo queda en el proto por compatibilidad de cable, marcado obsoleto en su comentario.
  - `PutCredential` tampoco reemplaza una credencial `key`, porque la convertiría en otra cosa sin generar nada. Para cambiar la llave está `RegenerateKeyCredential`.
  - **Límite aceptado.** El import de respaldo trae lo que haya en el `.mcvault`. Alguien que arme a mano un archivo con el formato de la bóveda podría meter una privada generada fuera. No se distingue, porque el respaldo es el camino de restauración que pidió el dueño. Armarlo exige reproducir el formato (Argon2id + AES-GCM) y conocer la frase.

### 1b. Enmienda (fase 47, 2026-11-17): importar una llave existente

**Decisión explícita del dueño**, que cambia su regla de «nunca copiar una privada»: puede importar a la bóveda una llave que ya tiene (por ejemplo `~/.ssh/id_ed25519`) con `ImportKeyCredential`. Plan: `docs/plans/2026-11-17-fase-47-importar-llave-ssh.md`.

- **Qué recibe.** El núcleo recibe el **contenido** de la llave, nunca una ruta. mctl y el puente leen el archivo del lado del cliente.
- **Formatos y tipos.**
  - Formatos: OpenSSH, PKCS#1, PKCS#8 y SEC1, con o sin frase.
  - Tipos aceptados: ed25519, ecdsa P-256/384/521 y RSA de al menos 1024 bits (aviso si es de menos de 3072).
  - Rechazadas: DSA y `sk-*`.
- **Cómo se guarda.** La frase se usa una vez. La privada se guarda en OpenSSH **sin frase**, en el mismo campo que las generadas, así que `transport.OpenSSH` y la validación de lo guardado no cambian. El formato del archivo de la bóveda tampoco cambia: el origen (`generated` o `imported`) se deriva de la llave guardada.
- **Lo que sigue igual.** La privada importada tiene las mismas salidas que una generada: ninguna RPC la devuelve y solo viaja dentro del `.mcvault` cifrado.
- **Regenerar.** Sobre una importada, la reemplaza por una ed25519 generada.
- **`PutCredential.ssh_private_key`** sigue rechazado: el único camino de entrada es `ImportKeyCredential`, que valida, normaliza y audita (`credential.keyimport`, sin material de llave).

### 2. Plataformas `linux` y `windows`, solo para el terminal

- `devices.HostPlatforms` suma `linux` y `windows`. Sirven para guardar el host y abrir el terminal SSH, nada más.
- Patrol (todos los tipos de trabajo: patrol, adhoc, backup y change) y el cambio asistido rechazan un objetivo que coincide con un host guardado `linux` o `windows`, con un mensaje que nombra el host. Un equipo que no está en la libreta sigue fallando como hoy, en la detección de la plataforma (`platform.err.unknown`).
- Los playbooks no pueden nombrar esas plataformas: `playbook.knownPlatforms` es una lista cerrada de Cisco y no cambia.
- El ADR 0007 sigue intacto: la app no aplica nada en equipos Cisco fuera del modo asistido.

### 3. Alcance: lo nuevo vale solo para `linux` y `windows`

Decisión del dueño (2026-11-16): la orden de inicio y las credenciales `key` valen **únicamente** para hosts `linux` y `windows`. Cisco queda como hoy, sin enable por llave. Una credencial `key` usada con Cisco se **rechaza con un mensaje claro**, en tres capas:

- **Al guardar el host.** `PutDevice` (y el import de hosts) rechaza una credencial `key` en un host que no sea `linux` ni `windows`, plataforma vacía incluida, con `metadata.field = "credential_id"`. Si la bóveda está cerrada no se puede saber el tipo: queda el aviso de hoy y la capa siguiente lo detiene.
- **Al abrir el terminal.** Una credencial `key` solo se usa por `host_id` de un host `linux` o `windows`. Con dirección escrita a mano o con un host Cisco: FailedPrecondition `terminal.err.key_credential`.
- **En todo lo demás que conecta.** `transport.OpenSSH` rechaza una credencial `key` salvo que el llamador declare un host genérico (`SSHOptions.GenericHost`, que solo pone el terminal). Así Patrol, el cambio asistido, ports, snippet, backup, restore, metrics, visibility y transfer quedan cubiertos en un solo lugar, sin repetir la regla en cada servicio, con `transport.err.key_credential`. Además, `patrolSvc.validate` y el cambio asistido lo revisan antes de empezar, para que el error salga al crear el trabajo y no a mitad de la corrida.
- Una credencial vieja con contraseña y llave importada es `password`, y sigue como hoy.

### 4. Orden de inicio por host

- Es una línea de 1 a 256 puntos de código, sin espacios en los extremos y sin caracteres de control (`\p{Cc}`, el tab incluido) ni de formato (`\p{Cf}`: bidi U+202A–202E y U+2066–2069, U+200B–200F, U+FEFF). Los de formato se rechazan porque harían que la orden mostrada no sea la que corre («Trojan Source»). El núcleo es la barrera; la UI solo repite la regla.
- El terminal la manda como **exec con PTY**: `RequestPty` y luego `Start(orden)`, que es lo que hacen `RemoteCommand` + `RequestTTY` de OpenSSH.
  - No se teclea en el shell: competiría con el banner y el prompt, y quedaría en el historial del shell remoto.
  - El servidor la interpreta con el shell de la cuenta. En Windows es el `DefaultShell` de OpenSSH, `cmd.exe` por omisión.
  - La sesión termina cuando la orden termina.
- Solo el núcleo decide qué se ejecuta.
  - Con `host_id`, el terminal toma dirección, puerto, credencial y orden del host guardado.
  - `host_id` es exclusivo: si el pedido trae también dirección, puerto o credencial, se rechaza sin conectar. Así un cliente alterado no combina un host guardado con otra credencial u otra dirección.
  - La UI manda la orden que mostró (`expected_startup_command`) y, si no es igual a la guardada, no se conecta.
- CheckDenied no aplica, porque es el terminal manual, como hoy. La UI lo dice junto a la orden.
- La orden no es un secreto: queda en la auditoría y en la grabación, y la UI avisa que no lleve secretos (decisión de Release).
- La orden viaja en el export/import de hosts. Un archivo ajeno puede traer una orden, pero no corre sin verse dos veces: la vista previa del import marca cada host que la trae (`has_startup_command`) y la muestra antes de aceptar, y el terminal no conecta si la orden guardada no es la que la UI mostró al conectar.

## Consecuencias

- **Respaldo.** Quien tenga el `.mcvault` y su frase tiene las llaves privadas. La frase propia de al menos 12 caracteres es lo que las protege, como protege las contraseñas que el respaldo ya lleva. El aviso con la cuenta de llaves lo hace explícito.
- **Llaves importadas antes de la fase 44.** Las credenciales con llave importada por gRPC, si existen, siguen como estaban. `cred pubkey` da `vault.err.key_unsupported` con todo lo que no sea una ed25519 OpenSSH sin frase (RSA, ECDSA, PKCS#8, cifradas); `cred rekey` sí las reemplaza por una ed25519 nueva conservando el id (la auditoría anota `old=unsupported`). Si son de solo llave, ahora solo sirven para el terminal de hosts `linux` o `windows`.
- **Alcance.** La app deja de ser solo Cisco en un punto acotado: el terminal. Cualquier otra herramienta que se quiera abrir a `linux` o `windows` necesita su propia decisión.
- **Documentos de seguridad.** `docs/security/CRYPTO.md` y `THREAT_MODEL.md` describen la llave generada y su límite: la privada pasa por memoria de Go sin bloquear al generarla, al regenerarla y al firmar, igual que la contraseña (límite declarado 1). También dicen que el respaldo lleva las llaves.
