# Fase 48: Telnet en la Terminal (plan)

Pedido del dueño (2026-11-18): Telnet «lo metemos después», solo en la terminal interactiva y con aviso de texto
claro. Leído en origin/main 7dfcb238. No hay nada de Telnet hoy (ni transporte, ni simulador, ni proto).

## Decisiones del dueño (2026-11-19, vía Release)

1. **Credencial: las dos.** Tecleada (el equipo pregunta y se contesta en la terminal) y también con una credencial
   guardada de la bóveda, que el núcleo contesta solo (ver «Login con credencial guardada»).
2. **Libreta: las dos.** Por dirección a mano y desde un host guardado, con protocolo (ssh/telnet) y puerto elegible en
   los dos casos; sin puerto, el del protocolo (22 SSH, 23 Telnet).
3. **Aviso:** una línea del núcleo al conectar.
4. **Siempre disponible** (sin ajuste para apagarlo) y auditado.

## Lo que cambia respecto de SSH

Telnet no tiene autenticación en el protocolo: el equipo pide «Username:»/«Password:» como texto. Sin credencial, la
persona contesta tecleando, igual que en una consola serie; no hace falta el AuthPrompt/AuthAnswer de 47t: lo que el
equipo pregunta llega como `data`. Además:

- **Lo tecleado en «Password:» no se graba.** El grabador ya detecta el prompt de secreto (`secretPrompt`,
  internal/terminal/recorder.go:30-34) y no graba lo tecleado ahí; se fija con una prueba de Telnet.
- **Todo viaja en texto claro**, contraseña incluida, y **no hay identidad del equipo** (sin huella de llave). La línea
  de aviso lo dice en cada conexión; con credencial guardada agrega que esa credencial también viaja en claro.

## Login con credencial guardada

El núcleo contesta el login solo cuando el pedido trae `credential_id` (o un host con credencial). Reglas:

- **Detección acotada, sin adivinar.** Se compara solo la última línea de la salida, sin espacios al final y cuando el
  equipo lleva 300 ms sin mandar nada (prompt estable; un banner que diga «Password: …» a media línea no cuenta):
  usuario `(?i)^(username|user name|login)\s*:$`; contraseña `(?i)^password\s*:$`. Nada más.
- **Secuencia.** Pregunta de usuario → manda el usuario de la credencial y CR; luego espera la de contraseña. Pregunta de
  contraseña primero (equipos con `password` de línea, sin usuario) → manda la contraseña.
- **Topes de tiempo:** 15 s para la primera pregunta y 10 s entre usuario y contraseña.
- **La contraseña se manda una sola vez y nunca se reintenta** (bloqueo de cuentas en TACACS, igual que en SSH). Si el
  equipo vuelve a preguntar usuario o contraseña, el núcleo no contesta más.
- **Paso a modo tecleado.** Sin pregunta reconocida a tiempo, o con la credencial rechazada, el núcleo deja de
  contestar, avisa con una línea (`terminal.telnet.manual_login` / `terminal.telnet.login_rejected`) y la persona sigue
  a mano. La sesión no se corta.
- **Lo que teclea la persona durante el login automático** se descarta (como `data` durante la autenticación en 47t),
  hasta que el login termina o pasa a modo tecleado.
- **Enable:** igual que la Terminal SSH, el núcleo no escribe `enable`. La persona lo teclea; el secreto de enable de la
  credencial se destruye sin usarse.
- **Nada de lo enviado se graba ni se audita.** Las respuestas del núcleo no pasan por el grabador (solo la salida del
  equipo, que no hace eco de la contraseña). La auditoría dice `credential=<id> user=%q protocol=telnet login=auto|manual`,
  nunca la contraseña. Los buffers se borran al enviarse.
- **Credencial de llave SSH:** no sirve para Telnet: `FailedPrecondition` `terminal.err.telnet_key_credential`.

## Bloques (cada uno con su prueba roja primero; PRs de a uno)

**48-0 Simulador.** `test/simulator`: `StartTelnet(t, Config)` que reusa la sesión IOS del simulador sobre un códec
Telnet (IAC, WILL/WONT/DO/DONT, eco del servidor). Login por texto con variantes por `Config`: «Username:» y
«Password:», solo «Password:» (password de línea), contraseña mala que vuelve a preguntar, prompt lento y banner con
«Password:» a media línea. `Config.Conns` y `Config.Attempts` cuentan conexiones y contraseñas recibidas.

**48-1 Transporte.** `internal/transport/telnet.go`:
`OpenTelnet(ctx, g *Guard, jobID, host string, port uint16, o TelnetOptions) (*TelnetSession, error)`, con la conexión
por `g.Dial` (EgressGuard, igual que SSH; noegress no cambia). Negociación mínima (RFC 854/855/857/858/1073/1091):
acepta WILL ECHO y WILL SGA del equipo, ofrece DO SGA, responde TTYPE con el tipo de terminal y NAWS con el tamaño;
rechaza lo demás (WONT/DONT). Quita las secuencias IAC de la salida y duplica 0xFF en la entrada; CR del teclado como
CR NUL. `ShellSize(term, rows, cols)` y `Resize(rows, cols)` con la misma forma que `transport.Session`, para que la
terminal no distinga. Cancelación por ctx como 47t-0. Pruebas contra el simulador y de bytes (IAC partida entre
lecturas, 0xFF en datos, opción desconocida, cierre del equipo).

**48-2 Proto y terminal, modo tecleado.** `TerminalOpen.protocol` (campo 12, enum `TERMINAL_PROTOCOL_SSH = 0`,
`TERMINAL_PROTOCOL_TELNET = 1`; aditivo, SSH por omisión). Con Telnet: puerto 23 si viene 0; `username` y las huellas
se rechazan con `InvalidArgument` (`terminal.err.telnet_field`); la línea de aviso al conectar; auditoría
`terminal.open … protocol=telnet cleartext=true`. Pruebas: abre y teclea contra el simulador, el aviso llega antes que
nada, lo tecleado en «Password:» no queda en la grabación, la auditoría ni los logs, resize llega por NAWS, cierre del
equipo y de la pestaña, puerto elegido y puerto por omisión.

**48-3 Login con credencial guardada.** Lo de la sección de arriba, en internal/service/terminal. Pruebas con el
simulador: usuario y contraseña; solo contraseña; contraseña mala (se manda una sola vez: `Attempts == 1`, y pasa a
modo tecleado con su aviso); sin pregunta en 15 s (pasa a modo tecleado); banner con «Password:» a media línea (no
contesta); lo tecleado durante el login se descarta; la contraseña no aparece en la grabación, la auditoría ni los logs
(marca única, como `TestTecleadaNoFiltra`); credencial de llave rechazada; aviso de credencial en claro.

**48-4 Libreta.** `Device.protocol` (campo 15, `ssh` por omisión) en inventory.proto, con validación (telnet sin orden de
inicio y sin credencial de llave); el puerto del host sigue en `Device.target.port`, y si es 0 vale el del protocolo.
Migración: los hosts existentes quedan en ssh. Export/import con la columna `protocol`. La terminal por `host_id` usa el
protocolo del host. Pruebas de host, de import/export y de terminal por `host_id`.

**48-5 UI** (Front). Selector SSH/Telnet y puerto en la Terminal y en el host de la libreta, puerto por omisión según el
protocolo, el texto de aviso. Contrato en docs/plans/contratos-front.md al cerrar 48-2, 48-3 y 48-4.

## Fuera de esta fase

Telnet en Patrol, respaldos, ad hoc, cambios o cualquier tarea automática; Telnet sobre TLS; reverse Telnet a servidores
de consola con puerto por línea (se puede abrir ya con dirección y puerto a mano, sin nada especial).

## Riesgos

- Equipos que negocian opciones raras o mandan IAC antes del banner: se cubren con las pruebas de bytes de 48-1.
- Un prompt de contraseña con otra palabra (fuera de `secretPrompt`) grabaría lo tecleado: es el mismo límite que hoy
  con SSH y consola serie, documentado en el grabador.
- Login automático: un equipo con un prompt de login distinto a los patrones no se contesta; pasa a modo tecleado con
  aviso (decisión del dueño: no adivinar). Si aparecen variantes reales, se agregan con su prueba.
- La contraseña de la credencial viaja en claro por la red: está en la línea de aviso y en el modelo de amenazas
  (docs/security/THREAT_MODEL.md, en 48-3).
