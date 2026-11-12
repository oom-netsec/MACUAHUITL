# Fase 15b: colores de terminal

## Alcance
Resaltado de palabras clave en toda salida tipo terminal de la UI y de `mctl`, con paletas elegibles y preferencia guardada en el núcleo.

## Diseño
- `internal/termcolor/`: fuente única de verdad en JSON embebido. `rules.json` (tabla ordenada de patrones por categoría), `palettes.json` (5 paletas: P1 verde, P3 ámbar, azul IBM, solarizado oscuro, claro alto contraste) y `cases.json` (casos compartidos). Go y TS compilan las mismas expresiones (subconjunto común de RE2 y JS, sin lookaround) en una sola alternancia; gana la coincidencia más a la izquierda y, en empate, la regla anterior.
- Categorías: ok, bad, warn, info, addr, iface, prompt, num, dim. Los mnemónicos `%FAC-N-NOMBRE` se colorean por severidad: 0-3 bad, 4 warn, 5 info, 6-7 dim.
- UI: `lib/termHighlight.ts` (clasificación), `lib/termPrefs.ts` (almacén con `useSyncExternalStore`), `components/Terminal.tsx` (`Terminal` y `Hl`). Solo se construyen nodos React (texto y `<span>`), nunca `dangerouslySetInnerHTML`; el texto no cambia. Líneas de más de 2000 caracteres no se analizan; en salidas largas solo se resaltan las últimas 2000 líneas; `Hl` va memoizado por línea.
- Estilos: variables `--t-*` en línea sobre `.term`; CSS agregado al final de `styles.css` y acotado a `.term`. No anima nada, así que `prefers-reduced-motion` se cumple por construcción. (El efecto opcional de resplandor y líneas de barrido se retiró después.)
- Preferencia: RPC `PrefsService.Get/SetPreference` (clave `^[a-z][a-z0-9_.]{0,63}$`, valor hasta 4 KiB) sobre la tabla `preferences` (migración 0002). Puente `GetPreference/SetPreference`; `setTermBackend(wailsCore)` en `main.tsx` carga el valor al arrancar. localStorage solo es caché de arranque. El selector de paleta está en la barra de cada terminal.
- `mctl`: si stdout es TTY, colorea con la paleta guardada (24 bits si `COLORTERM=truecolor|24bit`, si no el ANSI de 16 colores más cercano). Sin color con `NO_COLOR`, `TERM=dumb`, `--no-color`, `--json` o sin TTY.

## Pruebas
Go: `termcolor` (casos compartidos, ANSI, NO_COLOR), RPC de preferencias, puente y `mctl`. Vitest: casos compartidos, contraste AA de cada paleta, texto intacto, `<img onerror>`, salida de 20 000 líneas, selector y persistencia con el doble.
