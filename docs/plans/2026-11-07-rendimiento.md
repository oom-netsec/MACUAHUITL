# Rendimiento: arranque y navegación entre módulos

Fecha: 2026-11-07 · Rama: `fase-19u-rendimiento` · Punto de partida: `docs/plans/2026-11-06-ui-rework-cierre.md` (§1, presupuestos).

## Método

- Compilación de producción (`vite build`) y vista previa de producción con los dobles (`vite build -c vite.preview.config.ts`), servidas desde un directorio aparte; no se tocó `ui/frontend/dist`.
- Chromium headless con Playwright. El cambio de módulo recorre los 33 destinos de la barra: una primera vuelta (primera visita de cada uno) y cuatro vueltas más entre vistas ya visitadas. Se mide desde el clic hasta dos cuadros pintados y sin esqueleto. Se cuentan las tareas largas (`longtask`, más de 50 ms).
- La máquina estuvo con promedio de carga de 25 a 40 durante todas las medidas, así que se compara antes y después **alternando** las dos compilaciones, con CPU a 4x (`Emulation.setCPUThrottlingRate`) y mediana de 5 corridas. Los números absolutos no son los de una máquina en reposo; la diferencia entre ambos sí es estable.
- Además hay una prueba que cuenta renders (no depende de la carga de la máquina).

## Hallazgos y cambios

| Medida (4x CPU, mediana de 5 corridas) | Antes | Después |
|---|---|---|
| Cambio entre módulos ya visitados, mediana | 207 ms | **45 ms** |
| Cambio entre módulos ya visitados, p95 | 426 ms | **82 ms** |
| Primera visita de un módulo (mediana de los 33) | 395 ms | **63 ms** |
| Tareas largas durante la vuelta de 132 cambios | 177 (28.5 s en total) | **15 (1.1 s)** |
| Sin freno de CPU, máquina cargada: cambio p50 / p95 | 66 / 136 ms (1.ª medida) | 33 / 36 ms (piso de 2 cuadros) |

1. **Todas las vistas montadas se re-renderizaban en cada cambio de módulo.** `App.tsx` conserva montadas (ocultas) las vistas visitadas, pero `m.view(core)` creaba un elemento nuevo en cada render del shell y el valor de `NavContext` (`{ go, inbox }`) también era nuevo. Con 33 vistas visitadas, cada clic en la barra, cada cambio de `busy` y cada sondeo del estado (cada 15 s) volvía a renderizar las 33. Cambio: `lazyView` guarda un elemento por núcleo (`WeakMap`) y `App` memoiza `go` y el valor del contexto. Pruebas: `lazy.test.tsx` (mismo elemento por núcleo) y `App.test.tsx` (una vista oculta no se renderiza al cambiar de módulo); ambas fallan al revertir cada parte.
2. **Cada primera visita costaba unos 300 ms de más.** React frena 300 ms la revelación del contenido que sustituye a un fallback de `Suspense`, así que el esqueleto se quedaba ese tiempo aunque el código ya estuviera descargado. Cambio: `lazyView` expone `preload()` y `App` descarga el código de todas las vistas después de la primera pintura, una a la vez, cada una al terminar la anterior, en ratos libres (`requestIdleCallback`, o un temporizador de 50 ms en WebKitGTK, que no lo tiene). Con el código ya cargado, la vista se monta directo, sin fallback. Prueba: `lazy.test.tsx` (tras `preload` la vista aparece de forma síncrona).
3. **Vistas ocultas que trabajan:** revisado, casi nada. Los temporizadores de 30 s (`RelativeTime`, `JobsPanel`) son baratos; Terminal ya suelta WebGL y deja de medir al ocultarse; el refresco "en vivo" de Forense es una opción que la persona enciende. Con el arreglo 1 un cambio del shell ya no las toca.

## Medido y sin cambio

- **Núcleo (`macuahuitld`)**: de lanzar el proceso a que `mctl vault status` conteste, 43 a 65 ms en arranques normales y 109 ms en el primero con la base nueva (migraciones), con la máquina cargada y contando el arranque de `mctl`. No hay escaneo de `outputs/` ni carga pesada en el camino de arranque (`core.New`: base, hosts conocidos, playbooks embebidos, bóveda si existe, trabajos). No se cambió nada.
- **JS inicial**: 98 KB (`index`) + 71 KB (`i18n`, los dos idiomas) = **168 KB gzip**, contra los 145 KB del cierre del rework. El crecimiento está en los diccionarios (220 KB sin comprimir). Compilar y evaluar ese bloque tarda 22 a 36 ms sin freno (54 a 118 ms a 4x), con la máquina cargada. Cargar solo el idioma activo recortaría la mitad (unos 15 ms) a costa de que el proveedor espere la descarga, de que la paleta (que busca en los dos idiomas) cargue el otro, y de precargar ambos en las pruebas. No se hizo: queda como siguiente paso si la primera pintura sigue por encima de 400 ms en la app real.
- **Primera pintura**: el camino de arranque no cambió; entre las dos compilaciones la diferencia queda dentro del ruido (mediana de 12 cargas entre 300 y 650 ms con carga de 30). Hay que medirla en la app real con la máquina en reposo.
- **Terminal (xterm + WebGL, 123 KB gzip)**: ya es un bloque aparte que solo carga la vista Terminal; no entra al arranque. La descarga anticipada no incluye `XTermPane` (se importa dentro de `TerminalView` al abrir una sesión).
- Con la descarga anticipada la app transfiere ~870 KB de JS sin comprimir en lugar de ~600 KB, todo local (activos embebidos), repartido en turnos de ocio.
