# 47t: SSH con credencial tecleada en la Terminal (plan)

Pedido del dueño (vía Release): SSH sin credencial guardada, al estilo PuTTY/SecureCRT: «login as:» y las preguntas del
equipo (password y keyboard-interactive, MFA/OTP con varias preguntas) en la propia terminal. Seis PRs chicos de núcleo
y uno de Front; cada uno con su prueba roja primero. Leído en origin/main 6072fedc y x/crypto v0.59.0. Telnet, fuera.

## Decisiones (confirmadas por Release, 2026-11-18)

- **Modo tecleado implícito:** una pestaña con `address` y sin `credential_id`, o con `host_id` de un host sin
  credencial. Sin flag nuevo (el único cliente es el puente, que sale junto con el núcleo).
- **Usuario en el open:** `TerminalOpen.username` opcional; vacío → el núcleo pregunta «login as:» antes de marcar
  (`ClientConfig.User` no cambia a mitad del handshake, x/crypto client.go:281-282). En «Confiar y reintentar» la UI
  reenvía el usuario.
- **Sin bóveda:** el modo tecleado no necesita la bóveda abierta, pero la auditoría `terminal.open` se escribe igual con
  la bóveda cerrada (prueba propia). La credencial guardada no cambia.
- En «Confiar y reintentar» la UI reenvía solo el usuario, nunca respuestas: el equipo vuelve a preguntar.
- **Banner SSH** (`BannerCallback`): no se muestra hoy y no entra.

## Lo que hay hoy

- `OpenTerminal` es un stream bidi (terminal.proto:11-16); `TerminalOpen` lleva `credential_id = 4`, `host_id = 8`
  (:18-37); petición oneof `open|data|resize` (:44-50), respuesta `opened|recording|data` (:52-56).
- terminal.go: host sin credencial → `terminal.err.host_no_credential` (:159-161); dirección sin credencial →
  `no_address` (:167-169); bóveda cerrada (:181-189); `Guard.Allow` (:218-221); defer de cierre y auditoría (:234-251);
  `OpenSSH` (:264); la grabación se crea después del shell (:285-290); auditoría `user=%s` sin comillas (:293, :303).
  Durante el handshake nadie lee el stream (Recv al principio :126 y en la goroutine del teclado :330-351).
- ssh.go: destruye `Password`/`SSHKey` al volver (:55-57); deadline fijo de 15 s (:64-67, :116); `PasswordCallback` y
  `KeyboardInteractive` que responde **la misma contraseña a todas las preguntas**, una vez (:80-103); el ctx no corta el
  handshake.
- Secreto: `vault.Credential{Password, Enable, SSHKey *secret.Secret}` (memguard). THREAT_MODEL.md:46, límite 1: «x/crypto/ssh
  receives the password as a Go `string`, which cannot be erased».
- x/crypto v0.59: un error de callback ya no aborta, cuenta como fallo (client_auth.go:81-89); `RetryableAuthMethod`
  cuenta por método (3 password + 3 KI = 6); `ClientConfig.AuthCallback` (client.go:255-279) se llama antes de cada
  intento con `AllowedMethods`, `TriedMethods` y `PartialSuccessMethods`; `(nil, err)` aborta en el acto.
- Llamadores de `OpenSSH`: Patrol (backup, adhoc, change) logintest.go:111; assist exec.go:74 y rotate.go:45; metrics
  ports.go:127; transfer client.go:143; terminal terminal.go:264.
- Simulador: keyboard-interactive con «Password:» hasta 3 veces dentro de un intento (simulator.go:42, :203-219); sin
  ronda de dos preguntas.

## 47t-0 Cancelación del handshake (antes de 47t-2, toca a todos los llamadores)

`stop := context.AfterFunc(ctx, func(){ conn.Close() })` durante el handshake de `OpenSSH`, y `stop()` en cuanto el
handshake termina (con éxito o error): cancelar el ctx después no cierra una sesión ya abierta, salvo que ese sea el
contrato de hoy en algún llamador (revisarlo en Patrol, assist, metrics, transfer y terminal y decirlo). Pruebas rojas:
un ctx cancelado con el handshake colgado (servidor que no contesta) hace volver `OpenSSH` en <1 s; cancelar el ctx
después del handshake no cierra la sesión. Suite completa de transport, core y service en Linux y Windows.

## 47t-1 Simulador con MFA

`Config.OTP`: una ronda `name="MFA"`, `instruction="Enter password and code"`, preguntas «Password: » (echo false) y
«Verification code: » (echo true); respuesta mala = un `USERAUTH_FAILURE`; `Attempts` cuenta rondas. Flag `-otp` en
test/simulator/cmd/simserver para probar la UI a mano.
Prueba roja: `TestOTPDosPreguntas` (cliente x/crypto crudo): par bueno entra; código malo = 1 fallo; name, instruction y
echo exactos. Linux y Windows (test/simulator ya está en windows-pkgs).

## 47t-2 transport: `SSHOptions.Ask`, tope de 3 y cancelación

- API: `Prompt{Name, Instruction string; Questions []Question; Attempt int}`, `Question{Text string; Echo bool}`,
  `SSHOptions.Ask func(Prompt) ([][]byte, error)`.
- Guardas antes de marcar: `Ask` con `Password`/`SSHKey` → `ErrTypedMixed`; sin `Ask` y credencial vacía →
  `ErrNoCredential` (hoy marca y gasta un intento «none»).
- Con `Ask`: `cfg.AuthCallback` que (1) aborta con el error de `Ask` o `ctx.Err()`; (2) cuenta los fallos de
  `TriedMethods` sin «none» y con 3 devuelve `ErrAuthAttempts` (un éxito parcial no cuenta); (3) elige
  keyboard-interactive si está permitido, si no password; sin ninguno, `ErrTypedNoMethod`.
- Cada ronda de keyboard-interactive se relaya tal cual (también sin preguntas, por la instrucción). Password: una
  pregunta `{user}@{host}'s password: ` con echo false.
- Saneo del texto del equipo en name, instruction y el texto de cada pregunta: fuera C0/C1 (salvo `\n` en la
  instrucción) y Unicode de formato; tope por campo (name 128 bytes, instruction 1 KiB, cada texto 256 bytes) y 16
  preguntas por ronda; si pasa, `ErrTypedPrompt` (un equipo hostil no inunda la terminal).
- Respuestas: tantas como preguntas, 1 KiB máximo; se pasan a `string` para x/crypto y el `[]byte` se pone en ceros al
  instante.
- Deadline: se quita mientras se espera a `Ask` y se repone después (la espera la acota el servicio).
- Cancelación: la de 47t-0.
- No se usa `RetryableAuthMethod`: cuenta por método y no ve los fallos entre métodos.

Pruebas rojas (Linux y Windows): `TestAskRelayaMFA`, `TestAskTopeTresIntentos` (`Attempts==3`, `Conns==1`),
`TestAskPassword`, `TestAskEsperaMasQueElHandshake`, `TestAskCanceladoNoDejaNada` (vuelve en <1 s, goroutines en la
base), `TestCredencialVaciaNoMarca` (`Conns==0`), `TestAskConSecretoRechaza`, `TestAskSanea`, `TestAskSoloEnTerminal`
(AST: ningún `Ask` fuera de internal/service/terminal).

## 47t-3 Los RPC con credencial rechazan el modo tecleado

`TestSinCredencialSoloTerminal` (internal/core, ipc y simulador): `credential_id` vacío en CreateJob, LoginTest,
StartBackup, StartAdhoc, CreateChange, assist StartRun, transfer Get scp:// y métricas de puertos → error del catálogo,
`Conns==0` y ningún `AuthPrompt`. Si alguno acepta la credencial vacía, se le agrega la validación.

## 47t-4 Terminal tecleada por dirección (proto y servicio)

Proto, aditivo:
```
TerminalOpen        string username = 10;   // solo en modo tecleado; vacío = el núcleo pregunta «login as:»
OpenTerminalRequest oneof: AuthAnswer auth_answer = 4;
OpenTerminalResponse      AuthPrompt auth_prompt = 4;
message AuthPrompt  { uint32 seq = 1; string name = 2; string instruction = 3; repeated AuthQuestion prompts = 4; }
message AuthQuestion{ string text = 1; bool echo = 2; }
message AuthAnswer  { uint32 seq = 1; repeated bytes answers = 2; }
```

Servicio:
- Dirección sin `credential_id` = modo tecleado (sin bóveda). `username` con `credential_id` →
  `terminal.err.username_with_credential`. Usuario UTF-8 imprimible, ≤128 bytes, sin controles (`terminal.err.username`).
- Una sola goroutine de Recv desde `Guard.Allow`: cada mensaje va a un canal; durante la autenticación `data` se
  descarta y `resize` se guarda; después del open el bucle del teclado lee del canal.
- `ask(p)`: un solo emisor (el manejador). Manda `AuthPrompt{seq++}`; si subió `Attempt`, antes «Access denied».
  Espera `AuthAnswer` con el mismo `seq` y número de respuestas, o ctx, canal cerrado o `authWait` (2 min por
  pregunta). Otro `seq` o número → `terminal.err.auth_answer` y cierre. «login as:» usa el mismo `ask` (echo true).
- Motivos: `ErrAuthAttempts` → `terminal.err.auth_attempts` (PermissionDenied), timeout → `terminal.err.auth_timeout`,
  sin método → `terminal.err.auth_no_method`, cliente ido → `terminal.err.client_gone`.
- Huella: sin cambios (`HostKeyError` antes de autenticar, sin preguntas).
- Auditoría: `terminal.open credential=typed user=%q`; `terminal.failed` igual más el motivo. Nunca respuestas ni textos
  de preguntas. Grabación: nada de la autenticación. Errores: solo centinelas del catálogo.

Pruebas rojas (Linux y Windows): `TestTecleadaLoginYMFA`, `TestTecleadaTresIntentos`,
`TestTecleadaCierraPestanaEnPregunta` (CloseSend, ctx del stream y cierre del núcleo: <2 s, guard revocado, goroutines
en la base, conexión del simulador cerrada), `TestTecleadaTimeout`, `TestTecleadaRespuestaMala`,
`TestTecleadaBovedaCerrada`, `TestTecleadaNoFiltra` (marcador ausente en outputs, auditoría, log y errores),
`TestUsernameConCredencialRechaza`, `TestTecleadaHuellaNueva`.

## 47t-5 Host de la libreta sin credencial

`h.CredentialID == ""` pasa a modo tecleado (se quita el rechazo de :159-161); `username` solo con un host sin
credencial. Orden de inicio y `expected_startup_command` igual. Pruebas: `TestHostSinCredencialPregunta` (Cisco y
linux con orden de inicio), `TestHostConCredencialYUsernameRechaza`; la prueba que esperaba `host_no_credential` se
invierte.

## 47t-6 Punta a punta y documentos

`TestE2ETecleada` (ipc real, Linux y Windows) con el simulador OTP y el caso de huella. THREAT_MODEL: asset «typed
answers: only in memory, for the handshake of that connection»; límite 1: las respuestas cruzan el socket local y los
búferes de gRPC; el núcleo pone en ceros su copia, pero x/crypto/ssh necesita un `string` por respuesta, que vive hasta
el GC; la UI las tiene como strings de JavaScript; nunca se guardan, graban ni auditan. Comentario de terminal.proto.

## Contrato para Front

| Núcleo | Puente | Nota |
|---|---|---|
| `TerminalOpen` sin `credential_id` | `TerminalDTO.credentialId` vacío | modo tecleado; con `hostId` sin credencial, también |
| `TerminalOpen.username` | `TerminalDTO.username` | opcional; se reenvía en «Confiar y reintentar» |
| `auth_prompt` | evento `terminal:auth {runId, seq, name, instruction, prompts:[{text, echo}]}` | `echo:false` no pinta lo tecleado |
| `auth_answer` | `TerminalAnswer(id, seq, answers)` | todas las respuestas de la ronda en una llamada |
| fin por tope, timeout o método | `terminal:done` con `errorInfo.reason` | `auth_attempts`, `auth_timeout`, `auth_no_method`, `auth_answer` |

Durante una pregunta el teclado va al búfer de la respuesta, no a `TerminalSend`; Enter cierra cada pregunta; al mandar,
la UI borra sus variables; cerrar la pestaña cancela y el núcleo aborta.

## Orden

47t-0 → 47t-1 → 47t-2 → 47t-3 (en paralelo con 47t-4) → 47t-4 → 47t-5 → 47t-6 → Front (con el proto de 47t-4 en main).

## Riesgos

- Modo implícito: un cliente viejo con credencial vacía recibiría preguntas que no entiende (hoy el único es el puente).
- IOS repregunta dentro de un intento: hasta 3×3 preguntas; solo `USERAUTH_FAILURE` cuenta como fallo, como OpenSSH.
- `AuthCallback` es de x/crypto v0.59: una subida que lo cambie la detectan las pruebas de 47t-2.
- `AfterFunc` en todos los llamadores: un ctx cancelado ahora corta el handshake también en Patrol, assist y transfer.
- Sin deadline durante `Ask`: el límite es `authWait` y el LoginGraceTime del equipo.
- Texto del equipo en el xterm: se sanea como la salida.

## Review Focus

- Ninguna respuesta en la grabación, la auditoría, el log del núcleo ni los errores (prueba del marcador).
- Conteo con `TriedMethods` sin «none», el éxito parcial no cuenta, sin reconexión.
- Los tres caminos de cancelación sin goroutines y con el guard revocado.
- `Ask` solo en la terminal (AST) y `OpenSSH` rechaza la credencial vacía sin `Ask` antes de marcar.
- Un solo emisor por el stream; el camino con credencial guardada queda igual byte a byte.
