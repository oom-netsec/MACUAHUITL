# Auditoría de la interfaz antes del rework (fase 19)

Fecha: 2026-11-06 · Base: `fase-18-ui-idioma-acceso` (124c389) · Alcance: shell, componentes compartidos y los 30 destinos del manifiesto.

Cómo se midió:
- Capturas de los 30 destinos en claro y oscuro, español e inglés, a 1280×800 y 1920×1080 (240 imágenes), con la vista previa nueva (`npm run preview:ui`, datos de los dobles de prueba).
- Tiempos en **WebKitGTK 2.52**, el motor de Wails, con una ventana fuera de pantalla y sin composición GL. Son números conservadores: la app real compone con GPU.
- Tamaños con `vite build` y gzip -9.

## 1. Presupuestos: punto de partida

| Medida | Hoy | Presupuesto | Estado |
|---|---|---|---|
| JS inicial (gzip) | 162 KB, en **un solo bloque** con los 30 destinos (562 KB sin comprimir) | ≤ 250 KB, módulos bajo demanda | Cabe, pero todo se evalúa al arrancar |
| CSS (gzip) | 4.3 KB (16 KB) | ≤ 60 KB | Cabe |
| Fuente | Inter variable completa, 352 KB, `font-display: block` | — | Bloquea el texto hasta cargar |
| Primera pintura (mediana de 5) | **769 ms** (696 a 911) | < 400 ms | **No cumple** |
| Cambio de módulo | mediana 64 ms · p95 **141 ms** · máximo 147 ms | < 100 ms | **No cumple en p95** |
| Listas largas | Solo la grilla de Patrol está virtualizada | Virtualizar > 50 filas | Parcial |

Causas probables de la primera pintura: los 538 KB de JS se analizan y ejecutan antes del primer render, y la fuente completa bloquea el texto. El p95 del cambio de módulo es el primer montaje de los módulos grandes (forense, visibilidad, Patrol).

## 2. Hallazgos transversales (prioridad)

### P1: rompen la sensación de producto o la seguridad
1. **No hay sistema de patrones.**
   - Solo 4 de 23 vistas usan tarjetas (`.card`).
   - Solo 5 usan el aviso común (`Notice`).
   - Las demás mezclan `<p className="warn">` (47 usos), `role="alert"` suelto y texto sin contenedor.
   - Cada módulo inventa su forma: formularios de una columna a todo lo ancho, botones sueltos y resultados pegados al formulario.
2. **El modo de cambio asistido no se lee como un checklist de cambio.** En `components/AssistRun.tsx`:
   - El plan, la reversa y los pasos son `<pre>` seguidos.
   - "Confirmar paso" se ve igual que "Abortar" y "Revertir" (l. 184-188), así que se puede pulsar por inercia.
   - El aviso rojo (`.assist-banner`) es un recuadro con borde, y no hay un estado global que diga que hay un cambio vivo fuera del módulo.
3. **El estado no tiene un lugar fijo.** Las piezas están repartidas:
   - la conexión del núcleo, al pie de la barra;
   - la bóveda, en ningún lado;
   - lo que está en curso, como un punto en la barra;
   - el modo asistido, solo dentro de su módulo;
   - los trabajos de Patrol, solo dentro de Patrol.
4. **Sin teclado de primer nivel.** No hay paleta de comandos ni atajos globales. Para llegar a "Rotar credenciales" hay que abrir el grupo correcto: hay que saber dónde vive.
5. **Primera pintura y cambio de módulo fuera de presupuesto.** Ver la sección 1.

### P2: inconsistencia visual
6. **Títulos:** 6 vistas no tienen `<h2>` (adhoc, backup, cleaner, drift, forensic, terminal). La jerarquía va de 1.6 rem directo a 1 rem, sin escala definida.
7. **Consolas:** las consolas negras aparecen dentro del tema claro (captura, ping, consola serie, syslog). Se ven como otro producto.
8. **Formularios:**
   - Campos de hasta 760 px para un número de puerto.
   - No hay agrupación por intención ni barra de acciones fija.
   - Los botones primarios no siempre están marcados como primarios.
9. **Pestañas internas:** se dibujan como segmentos, botones o pestañas según el módulo. Ejemplos: Calculadoras, Forense, Visibilidad, Seguridad, Campo.
10. **Color sin semántica:**
    - El jade (acento) se usa a la vez como "primario", "ok" y "seleccionado".
    - Los tonos de aviso o error no siempre llevan ícono o texto.
11. **Tablas:**
    - No usan números tabulares ni monoespaciada en IP, MAC o puertos.
    - Sin encabezado fijo.
    - Solo la grilla de Patrol está virtualizada (Forense, Flota y Corridas pueden traer cientos de filas).
12. **12 copias** de un helper `useReport` en los módulos (analysis, calc, change, fleet, patrol, security ×3, tools, visibility ×3), cada una con su propio estado de carga y error.

### P3: estados incompletos
13. **Estado vacío:** casi ninguna vista lo tiene. Al abrir Corridas, Deriva, Limpiador o Flota se ve un formulario sin decir qué hacer primero.
14. **Carga:** el botón deshabilitado es la única señal; no hay esqueletos.
15. **Errores:**
    - Se dicen, pero no qué hacer.
    - Los del núcleo llegan crudos (en español aun con la app en inglés; es una decisión vigente).

## 3. Guías de interfaz (Web Interface Guidelines)

- `src/styles.css:5`: `font-display: block` sobre 352 KB. Hace falta un subconjunto y `swap` (o `optional`).
- `src/styles.css:47`: la escala tipográfica es una sola línea para `h2`; falta definir h3, h4, label y caption.
- `src/styles.css:65`: el foco de los campos cambia el contorno por una sombra. Es válido, pero su contraste en oscuro es bajo (`--accent-soft` sobre `--surface`).
- `src/components/AssistRun.tsx:184-188`: la acción destructiva y la confirmación tienen el mismo peso visual.
- `src/components/AssistRun.tsx:193, 194, 201`: avisos `<p className="warn">` sin `role`; un paso detenido no se anuncia.
- `src/app/Sidebar.tsx:47`: el estado del núcleo se comunica solo con un punto de color más un texto pequeño al pie; no se anuncia al cambiar.
- `src/modules/*`: números de equipos, puertos y conteos sin `font-variant-numeric: tabular-nums`.
- `src/modules/*`: falta un estado vacío en 19 de 23 vistas.
- `index.html`: falta la `theme-color` que acompañe a `color-scheme`. Es menor: la ventana no tiene marco.

Lo que ya cumple: etiquetas reales en los campos (`Field`), `aria-current` y `aria-expanded` en la barra, foco visible global, `color-scheme`, `prefers-reduced-motion`, la grilla virtualizada de Patrol, y todo el texto pasa por i18n con su prueba de cobertura.

## 4. Módulo por módulo

Leyenda: T = tiene título · C = usa tarjetas · A = usa el aviso común · V = tiene estado vacío.

| Módulo | Líneas | T | C | A | V | Lo más importante |
|---|---|---|---|---|---|---|
| Patrol | 470 | ✓ | ✓ | ✓ | ✓ | El más cercano al sistema nuevo; pasar a los tokens nuevos |
| SSH (terminal) | 129 | — | — | — | — | Sin título; las pestañas de sesión deben ser las del sistema; consola dentro del tema |
| Consola serie | 88 | ✓ | — | — | — | Formulario largo; los parámetros de puerto deberían estar en una línea |
| Ping / Traceroute / nmap / iperf3 / Captura | 139 | ✓ | ✓ | ✓ | — | Formulario + consola; falta el vacío "Escriba un destino" |
| PCAP, DNS, TLS, Syslog | 207 | ✓ | ✓ | ✓ | parcial | Base buena; Syslog debería ser una tabla virtualizada con filtro de severidad |
| ACL | 91 | ✓ | ✓ | ✓ | — | Dos columnas (entrada y resultado) |
| Corridas | 187 | ✓ | — | — | — | Tres herramientas apiladas sin pestañas claras |
| Deriva | 52 | — | — | — | — | Sin título ni vacío |
| Limpiador | 50 | — | — | — | — | Sin título |
| Flota | 289 | ✓ | — | — | — | 8 barras de acción; tablas largas sin virtualizar |
| Forense | 447 | — | — | — | ✓ | Seis herramientas sin título de página; tablas largas |
| Cambios | 210 | ✓ | — | — | — | Pre/post y cumplimiento en un solo formulario largo |
| Lotes ad-hoc | 101 | — | — | — | ✓ | Sin título; el aviso de "solo lectura" debe ser un aviso del sistema |
| Puertos | 71 | ✓ | — | — | — | Modo asistido (ver P1 #2) |
| Snippets | 96 | ✓ | — | — | — | Modo asistido |
| Rotar credenciales | 62 | ✓ | — | — | — | Modo asistido; el texto largo de advertencia debe ser un aviso |
| Respaldos | 241 | — | — | — | — | Sin título; respaldar, comparar y restaurar mezclados |
| Seguridad | 340 | ✓ | — | — | — | 4 pestañas; 3 copias de `useReport` |
| Campo | 124 | ✓ | — | — | — | Servidor TFTP/HTTP: el estado "escuchando" debe ir a la barra de estado |
| Calculadoras | 357 | ✓ | — | — | — | 14 barras de acción; resultados como texto plano en vez de tabla |
| Visibilidad | 380 | ✓ | — | — | — | 5 pestañas; 3 copias de `useReport`; imagen de topología con fondo blanco fijo en oscuro |
| Bóveda | 189 | ✓ | ✓ | ✓ | ✓ | Bien; llevar su estado (abierta o cerrada) a la barra de estado |
| Auditoría | 31 | ✓ | ✓ | ✓ | — | Bien |

## 5. Qué se propone (detalle en el ADR 0009)

1. **Tokens nuevos:**
   - escalera de superficies con bordes finos y casi sin sombras;
   - acento único para lo primario y el foco;
   - cuatro tonos semánticos (crítico, aviso, ok, info) con ícono;
   - escala tipográfica de seis pasos, retícula de 4 px.
2. **Shell:**
   - barra lateral con grupos;
   - **barra de estado** inferior fija: núcleo, bóveda, ejecuciones vivas, modo asistido y trabajos de Patrol;
   - **paleta de comandos** (Ctrl+K) y atajos visibles.
3. **Componentes base:**
   - página con encabezado y acciones;
   - sección, campo y fila de campos;
   - botón (primario, secundario, discreto, destructivo);
   - pestañas, tabla densa, panel de resultado, aviso, toast, estado vacío y esqueleto.
4. **Patrón del modo asistido:** checklist de cambio con plan, reversa y pasos. "Confirmar paso" lleva la acción escrita y un retardo de armado; el aviso rojo fijo es global.
5. **Rendimiento:**
   - `React.lazy` desde el manifiesto;
   - subconjunto latino de Inter con `font-display: swap`;
   - JetBrains Mono en subconjunto para salidas;
   - virtualización en tablas largas.
