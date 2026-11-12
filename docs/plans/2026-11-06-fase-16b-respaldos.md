# Fase 16b, frente D: respaldos de configuración y terminal SSH

Fecha: 2026-11-06 · Rama: `fase-16b-respaldos` · Spec: ADR 0008 y `docs/roadmap.md` (fase 16, puntos 8 y 9).

Fuera de esta fase: restaurar configuraciones (`configure replace`); se diseña aparte con el dueño.

## Respaldos (`internal/backup`, `internal/service/backup`)
- `mctl backup run -d EQUIPO[:PUERTO]... --cred ID [--startup] [--keep N] [--every 24h --rounds N] [--secrets] [--accept HUELLA] [--exclude EQUIPO] [--timeout 10m] [--json]`
  guarda `show running-config` (y `show startup-config` con `--startup`) en `outputs/respaldos/<equipo>/<AAAAMMDDTHHMMSSZ>-<running|startup>.cfg`, con su ficha `.json` al lado.
  Una sola vez espera el resultado; con `--every` y `--rounds` queda programado.
- `mctl backup collect TRABAJO`, `backup list [EQUIPO]`, `backup diff A B | A --now -d EQUIPO --cred ID`, `backup export ID [-o ARCHIVO]`.
- UI: pestaña Respaldos (`modules/backup`): formulario de respaldo o programación, lista con marca «enmascarado», comparación de dos respaldos, ver y exportar.
- Es solo lectura. La recolección es un trabajo de Patrol: bóveda, Login Test, guard, planificador (intervalo y rondas), llave de host estricta y auditoría son los de Patrol. Los comandos son fijos, no los escribe el usuario.
- El diff reutiliza `drift.Compare` (misma lista de líneas volátiles) desde el servicio, porque un dominio no importa a otro (ADR 0008); el dominio `backup` solo guarda y lista.

### Puntos delicados (cada uno con prueba vista fallar antes)
- **Permisos 0600** (archivo y ficha; carpeta 0700). Mutación: 0644 hace fallar `TestGuardaConPermisos0600`.
- **La retención nunca borra fuera de su carpeta.** `Name` rechaza `..`, separadores, punto inicial y vacío; `Sanitize` convierte el nombre del equipo que viene de Patrol; la carpeta del equipo se comprueba con `Lstat` (si es un enlace simbólico, ni guarda, ni lista ni borra); solo se cuentan y borran archivos regulares con nombre `sello-tipo.cfg` (`DirEntry.Type().IsRegular`, un enlace con ese nombre se ignora). `keep` menor que 1 se rechaza. Mutaciones hechas: `Stat` en vez de `Lstat`, regex de nombre permisiva y quitar el filtro de regulares hacen fallar `TestRetencionNoBorraPorUnEnlaceSimbolicoDeCarpeta`, `TestNombreDeEquipoNoSaleDeLaCarpeta` y `TestRetencionIgnoraEnlacesDentroDeLaCarpeta`.
- **Aviso de secretos enmascarados.** La ficha guarda `masked`; `list`, `diff` y la UI avisan. Sin ficha se supone enmascarado (aviso conservador). Por defecto el trabajo enmascara; `--secrets` lo apaga y la UI avisa que el archivo tendrá secretos en claro.
- **Cabeceras falsificadas.** Un `banner motd` con líneas `===== <fecha> · show running-config =====` fabricaba secciones (fecha 2099) y hacía que la retención borrara los respaldos reales; afectaba también al análisis. De raíz: `patrol.Writer` antepone `\` a toda línea de la salida que empiece con `===== ` (o `\…=====`), y `analyze` quita una barra al leer; los paquetes viejos se leen igual (`fleet`, `topo` y `capture` tampoco ven ya esas líneas como cabecera). Defensa en el servicio: se descartan las secciones con `At` fuera de la ventana del trabajo y, si hay más de una por equipo, ronda y tipo, se descartan todas. Mutaciones hechas: quitar el escape, quitar la restauración, quitar la ventana y quitar la unicidad hacen fallar las pruebas.
- **Trabajos grandes.** Un aviso del lector (tope de 512 MiB, recorte de 8 MiB por salida, archivo ilegible) cuenta como fallo y la carpeta de Patrol no se borra. El vigilante guarda por trabajo los archivos de ronda ya importados completos (nombre y tamaño) y no los vuelve a abrir (`analyze.LoadSkipping`); una ronda en curso crece y se relee. Los avisos del vigilante se auditan una vez (`backup.warning`) y, si la carpeta se conserva, `backup.kept`. Topes inyectables en pruebas con `analyze.SetLimits`.
- La carpeta de Patrol del trabajo (`respaldos/.trabajos/lote-*`) se borra al terminar si todo se guardó bien y sin avisos. `GetBackup` (exportar) queda auditado; guardar y retención también (`backup.save`, `backup.prune`).

### Decisiones
- Un vigilante por trabajo (cada 2 s) guarda cada ronda según termina; el núcleo lo detiene al cerrarse (`OnClose`). `Collect` es idempotente y sirve si el vigilante se perdió (reinicio del núcleo: el trabajo de Patrol tampoco sobrevive).
- La retención por defecto es 30 por equipo y tipo, máximo 1000, aplicada tras cada importación. No hay comando `prune` suelto.
- `diff --now` toma un respaldo nuevo (queda guardado) y compara contra él; es la forma de comparar «contra el running actual» sin una vía de lectura aparte.
- El nombre del equipo en disco es la carpeta de Patrol (`hostname_ip`).

## Terminal SSH (`internal/terminal`, `internal/service/terminal`)
- Servicio `TerminalService.OpenTerminal` (stream bidireccional, molde de la consola serie). La sesión sale por el EgressGuard con un id propio (`term-…`), usa la credencial de la bóveda y la verificación estricta de la llave de host (una llave nueva se rechaza con su huella; se acepta con `accepted_host_key_fingerprints`). Máximo 8 sesiones.
- Grabación en `outputs/terminal/<etiqueta>_<hora>_<id>.log` (0600, `O_EXCL`): lo que devuelve el equipo y lo tecleado por línea (`>>> comando`). Los comandos tecleados pasan por `mask.Apply` (un `username X secret 0 …` no queda en claro).
- **Contraseñas:** el grabador reconoce un prompt `Password:`, `Secret:`, `passphrase`, `passcode` en la última línea de la salida y, hasta el Enter (o Ctrl-C), no graba lo tecleado; deja `>>> [oculto]`. Funciona con el prompt partido en trozos, con la contraseña pegada junto con el siguiente comando y tecla por tecla. La UI además oculta el campo (`type=password`). Mutación: desactivar el reconocimiento hace fallar cuatro pruebas del grabador.
- **Salida del equipo enmascarada.** `Output` acumula hasta el salto de línea, quita el prompt (`^\S+[#>]`, que se conserva) y pasa cada línea por `mask` con estado entre líneas (`mask.Stream`: bloques `line`/`tacacs`/`radius`, llaves privadas). Cubre el eco de `username bob … secret 0 X` y un `show running-config` dentro de la terminal. Un prompt a medias queda retenido hasta el salto o el cierre. Tope por línea (64 KiB, se recorta) y de 256 MiB por grabación (`### grabación recortada`, la sesión sigue).
- **Contraseña tecleada antes del prompt.** Un Enter sin salida nueva desde el Enter anterior retiene la línea (máximo 32): si la salida siguiente termina en un prompt de secreto, esa línea se graba `[oculto]`; si termina en el prompt normal del equipo (`SW1#`), era un comando; al cerrar se graba lo pendiente. Prueba con el envío pegado (`enable\rEnSecret9\r`) y con el eco y el prompt en trozos distintos.
- **Cierre en todos los caminos:** un solo `defer` cierra SSH y grabación, hace `Revoke` del guard y audita (`terminal.close`, o `terminal.failed` si no llegó a abrir, con la razón y `guard=revocado`). Pruebas: el cliente cierra la pestaña, el núcleo se cierra (`OnClose`), el equipo corta (`exit` y exec-timeout), el cliente cae, bóveda cerrada y llave de host nueva. Las pruebas comprueban con `Guard.Dial` que la autorización ya no existe. Mutaciones: quitar el `Revoke` y quitar la cancelación por cierre del núcleo hacen fallar las pruebas.
- Los rechazos anteriores a la apertura (bóveda cerrada, límite de sesiones, el guard no autoriza, núcleo cerrándose) quedan auditados como `terminal.failed` con la razón.
- Cambio en `internal/transport/ssh.go`: `ShellSize(rows, cols)` y `Resize`; `Shell()` conserva 24×200.
- UI: pestaña Terminal (`modules/terminal`) con varias sesiones, salida en `components/Terminal`, campo de comando, botones Ctrl-C, Ctrl-Z, ?, Espacio y Tab, aviso permanente de que lo tecleado va directo al equipo, sin modo asistido. Cerrar la pestaña o salir del módulo cierra la sesión en el núcleo.
- **Sin librería nueva.** No se agregó xterm.js: la terminal reutiliza `components/Terminal.tsx` y `cleanTerminal` como la consola serie. No hay dependencias nuevas ni licencias que leer.

## Pendiente
- Abreviaturas de IOS (`usern bob sec 0 X`): `mask` no las reconoce y quedan en claro en la grabación (nota `shortcut:` en `internal/terminal/recorder.go`); ampliar las reglas de `mask` si hace falta.
- Emulador de terminal (xterm.js, MIT): pantallas completas, Tab que completa, redimensionar con la ventana. El puente ya expone `TerminalResize` y el núcleo ya aplica `Resize`; falta la vista.
- `show startup-config` y el comportamiento real de IOS (paginación, otros prompts de contraseña como `Token:`) están en `laboratorio-bateria-de-pruebas.md`, sección K. El simulador no responde `show startup-config`.
- Comparar «contra el running actual» desde la UI (hoy solo en la CLI con `--now`).
- Retención sin tomar un respaldo (`backup prune`) y restaurar.
- Recomendación para la integración: `help.golden`, `modules.go`, `domains.go`, `App.tsx`, `main.tsx`, `core.ts` y `fake.ts` reciben una línea al final; si el frente C también agrega ahí, el choque se resuelve conservando ambas.
