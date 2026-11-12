# Modelo de amenazas

Referencia: [diseño de arquitectura](../architecture/2026-11-02-macuahuitl-architecture-design.md), §10–§12.

## Activos

| Activo | Dónde vive | Impacto si se filtra |
|---|---|---|
| Credenciales de equipos | `vault.mcv` cifrado; en claro solo en memoria durante la autenticación | Acceso administrativo a la red del cliente |
| DEK (llave de datos) | Memoria bloqueada del núcleo mientras la bóveda está abierta o armada | Descifra todas las credenciales |
| Contraseña maestra | Solo en memoria durante `Unlock`, `Create` y `ChangeMasterPassword` | Igual que la DEK |
| Outputs | Carpeta elegida por el ingeniero, con o sin enmascarado | Configuración y secretos del cliente si el enmascarado está apagado |
| Log de auditoría | SQLite local | Pérdida de trazabilidad |

## Actores

| Actor | Capacidad supuesta |
|---|---|
| Ladrón de la laptop | Acceso al disco apagado |
| Malware con el UID de otro usuario | Puede intentar conectarse al socket o leer archivos |
| Malware con el UID del ingeniero | Lo mismo que el ingeniero mientras está activo |
| Intermediario en la red | Intercepta o suplanta SSH/HTTPS hacia los equipos |
| Dependencia comprometida | Código malicioso en una librería |
| Auditor externo | Lee el código, compila y observa la ejecución |

## Amenazas y mitigaciones

| Amenaza | Mitigación |
|---|---|
| Robo de disco | Bóveda cifrada con Argon2id + AES-256-GCM; la DEK nunca toca disco en claro |
| Fuerza bruta de la contraseña maestra | Argon2id calibrado a ~1 s, 256 MiB de memoria |
| Alteración del archivo de bóveda | AES-GCM con datos asociados (ID de bóveda, ID de entrada, versión) |
| Otro usuario local usa el socket | Permisos 0600 y verificación `SO_PEERCRED` del UID |
| Volcado de memoria del núcleo | `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` |
| Secreto en un log por accidente | Tipo `Secret` con redacción en todos los formateadores; prueba de no-filtración con contraseña marcador |
| Conexión a destino no autorizado | `noegress` en CI, `EgressGuard` en tiempo de ejecución, sin telemetría ni actualizaciones |
| Suplantación SSH | Confianza en el primer uso con confirmación; llave cambiada bloquea por defecto |
| Herramienta externa usada para exfiltrar | Argumentos validados, sin shell, sin opciones que lean destinos de archivos o scripts; todo en auditoría |
| Dependencia comprometida | `govulncheck` en CI, SBOM, versiones fijadas en `go.sum`, compilación reproducible |
| Comando de configuración en una recolección | Lista de denegación por plataforma en `internal/playbook` |

## Límites declarados

Estas son las cosas que MACUAHUITL **no** garantiza. Se declaran para que nadie las suponga.

1. **Copia de la contraseña en `x/crypto/ssh`.** La librería SSH recibe la contraseña como `string` de Go, que no se puede borrar. Se crea en el momento de enviarla, una sola vez por conexión, y vive hasta que el recolector de basura la libera. Una llave SSH privada, si se usa, queda parseada en memoria normal mientras dure la sesión.
2. **Swap e hibernación.** El núcleo intenta `mlockall`, pero si falla, el sistema operativo podría escribir memoria con secretos a swap o a la imagen de hibernación. El núcleo avisa si hay swap sin cifrar o hibernación activa.
3. **Malware con el UID del ingeniero.** Mientras la bóveda está abierta o armada, un proceso con el mismo usuario puede depurar el núcleo o usar el socket. Ninguna aplicación de usuario puede defenderse de su propio usuario.
4. **Reescritura local del log de auditoría.** La cadena de hashes detecta daños accidentales. Quien controle el usuario puede reescribirla entera. El ancla en cada `manifest.json` protege lo que ya se entregó a terceros.
5. **Casilla "aceptar llaves de host cambiadas".** Si el ingeniero la marca en un trabajo, un intermediario podría recibir la credencial. Cada aceptación queda en auditoría y en el manifest.
6. **Enmascarado apagado.** Si el ingeniero apaga el enmascarado, los outputs contienen los secretos de los equipos.
7. **DEK en memoria durante ventanas armadas.** Hasta 96 h con la DEK en memoria del núcleo.
8. **Análisis estático de red.** `noegress` revisa los imports del código propio, no el de las dependencias ni llamadas como `os.StartProcess`. Una dependencia maliciosa podría abrir conexiones. Mitigación: dependencias mínimas, `govulncheck`, SBOM y la observación en ejecución de la guía de auditoría.
9. **Borrado o reversión de entradas de la bóveda.** Quien tenga acceso al disco puede borrar una entrada o devolverla a su versión de `vault.mcv.bak` sin que se detecte. No puede leerla ni moverla de posición.
10. **Llave AES expandida en memoria normal.** `crypto/aes` copia la llave a su propia estructura (rondas expandidas y tabla GHASH) en memoria del recolector de basura, que no se bloquea ni se puede borrar. Aplica a la KEK durante cada derivación y a la DEK mientras la bóveda está abierta o armada. Mitigación: una sola expansión de la DEK por vida de la DEK (no una por operación), `PR_SET_DUMPABLE=0` y los límites 2 y 3.
