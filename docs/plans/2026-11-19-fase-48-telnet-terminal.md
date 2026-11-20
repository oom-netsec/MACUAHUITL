# Fase 48: Telnet en la Terminal (plan, pendiente de aprobación del dueño)

Pedido del dueño (2026-11-18): Telnet «lo metemos después», solo en la terminal interactiva y con aviso de texto
claro. Leído en origin/main 7dfcb238. No hay nada de Telnet hoy (ni transporte, ni simulador, ni proto).

## Lo que cambia respecto de SSH

Telnet no tiene autenticación en el protocolo: el equipo pide «Username:»/«Password:» como texto y la persona contesta
tecleando, igual que en una consola serie. Por eso no hace falta el AuthPrompt/AuthAnswer de 47t: la conexión abre y lo
que el equipo pregunta llega como `data`. Lo que sí hay que cuidar:

- **Lo tecleado en «Password:» no se graba.** El grabador ya detecta el prompt de secreto (`secretPrompt`,
  internal/terminal/recorder.go:30-34) y no graba lo tecleado ahí; se fija con una prueba de Telnet.
- **Todo viaja en texto claro**, también la contraseña: aviso visible en cada conexión y en la auditoría.
- **Sin huella de llave:** no hay identidad del equipo; el aviso lo dice.

## Decisiones que necesito del dueño

1. **Credencial.** Recomiendo **solo tecleada**: la bóveda no se usa con Telnet (una credencial guardada no debería
   viajar en claro sin que la persona la teclee a sabiendas). Alternativa: permitir una credencial de la bóveda y que el
   núcleo conteste Username:/Password: solo.
2. **Libreta de hosts.** Recomiendo **sí**: campo `protocol` (ssh por omisión, telnet) en el host guardado, puerto 23 por
   omisión con telnet, y la orden de inicio deshabilitada con telnet. Alternativa: Telnet solo por dirección a mano en
   esta fase.
3. **Aviso.** Recomiendo **una línea del núcleo al conectar** (localizada: «Telnet: todo viaja en texto claro,
   contraseña incluida, y no se verifica la identidad del equipo»), que también ve cualquier cliente, más el texto fijo
   en la UI junto al selector de protocolo. Alternativa: además una confirmación modal en cada conexión.
4. **Apagado por omisión.** Recomiendo **no**: es una conexión saliente que la persona pide a mano y queda auditada;
   un ajuste extra solo estorba. Alternativa: «Permitir Telnet» en Ajustes, apagado por omisión.

## Bloques (cada uno con su prueba roja primero; PRs de a uno)

**48-0 Simulador.** `test/simulator`: `StartTelnet(t, Config)` que reusa la sesión IOS del simulador sobre un códec
Telnet (IAC, WILL/WONT/DO/DONT, eco del servidor), con «Username:»/«Password:» como texto al conectar y
`Config.Conns` contando conexiones. Pruebas del simulador.

**48-1 Transporte.** `internal/transport/telnet.go`:
`OpenTelnet(ctx, g *Guard, jobID, host string, port uint16, o TelnetOptions) (*TelnetSession, error)`, con la conexión
por `g.Dial` (EgressGuard, igual que SSH; noegress no cambia). Negociación mínima (RFC 854/855/857/858/1073/1091):
acepta WILL ECHO y WILL SGA del equipo, ofrece DO SGA, responde TTYPE con el tipo de terminal y NAWS con el tamaño;
rechaza lo demás (WONT/DONT). Quita las secuencias IAC de la salida y duplica 0xFF en la entrada; CR del teclado como
CR NUL. `ShellSize(term, rows, cols)` y `Resize(rows, cols)` con la misma forma que `transport.Session`, para que la
terminal no distinga. Cancelación por ctx como 47t-0. Pruebas contra el simulador y de bytes (IAC partida entre
lecturas, 0xFF en datos, opción desconocida, cierre del equipo).

**48-2 Proto y terminal.** `TerminalOpen.protocol` (campo 12, enum `TERMINAL_PROTOCOL_SSH = 0`,
`TERMINAL_PROTOCOL_TELNET = 1`; aditivo, el valor por omisión es SSH). Con Telnet: puerto 23 por omisión;
`credential_id`, `username` y las huellas se rechazan con `InvalidArgument` (motivos `terminal.err.telnet_*`, según la
decisión 1); la línea de aviso al conectar (decisión 3); auditoría `terminal.open … protocol=telnet cleartext=true`.
Pruebas: abre y teclea contra el simulador, el aviso llega antes que nada, lo tecleado en «Password:» no queda en la
grabación ni en la auditoría ni en los logs, resize llega por NAWS, cierre del equipo y de la pestaña.

**48-3 Libreta** (si la decisión 2 es sí). Campo `protocol` en el host guardado, validación (telnet sin credencial y sin
orden de inicio), migración: los hosts existentes quedan en ssh. Pruebas de host y de terminal por `host_id`.

**48-4 UI** (Front). Selector SSH/Telnet en la Terminal y en el host de la libreta, el texto de aviso, puerto 23 por
omisión. Contrato en docs/plans/contratos-front.md al cerrar 48-2.

## Fuera de esta fase

Telnet en Patrol, respaldos, ad hoc, cambios o cualquier tarea automática; Telnet sobre TLS; reverse Telnet a servidores
de consola con puerto por línea (se puede abrir ya con dirección y puerto a mano, sin nada especial).

## Riesgos

- Equipos que negocian opciones raras o mandan IAC antes del banner: se cubren con las pruebas de bytes de 48-1.
- Un prompt de contraseña con otra palabra (fuera de `secretPrompt`) grabaría lo tecleado: es el mismo límite que hoy
  con SSH y consola serie, documentado en el grabador.
