# ADR 0009: Sistema de diseño de la interfaz

Fecha: 2026-11-06 · Estado: aceptado (visto bueno del dueño el 2026-11-06)

## Contexto

La auditoría (`docs/plans/2026-11-06-ui-rework-auditoria.md`) encontró 30 destinos con patrones distintos.
- Solo 4 de 23 vistas usan tarjetas.
- Hay 47 avisos sueltos y 12 copias del mismo helper de resultados.
- No hay paleta de comandos ni barra de estado.
- El modo de cambio asistido se lee como texto plano.
- La primera pintura (769 ms) y el p95 del cambio de módulo (141 ms) superan el presupuesto.

La app la usan ingenieros de redes en guardia: necesitan densidad, estado siempre visible y teclado. Debe verse premium y ser ligera en WebKitGTK.

Referencias estudiadas (principios, no marca): Linear y Raycast (escalera de superficies, un solo acento, densidad, atajos como teclas) y Apple System Settings (jerarquía con tipografía y espacio).

## Decisión

### 1. Tokens (`src/styles/tokens.css`)
Todos los colores salen de custom properties con `light-dark()`. Ningún componente usa un hex directo.

**Superficies** (profundidad por escalera de superficies y bordes finos; las sombras solo en capas flotantes):

| Token | Claro | Oscuro | Uso |
|---|---|---|---|
| `--canvas` | #f6f7f9 | #0b0c0e | Fondo de la ventana |
| `--surface` | #ffffff | #121417 | Paneles, campos, tablas |
| `--surface-2` | #f0f1f4 | #191c20 | Fila en hover, encabezado de tabla, consolas |
| `--surface-3` | #ffffff | #1e2126 | Capas flotantes (paleta, menús, toasts) |
| `--sidebar` | #eef0f3 | #0f1113 | Barra lateral y barra de estado |
| `--hairline` | #e3e5ea | #24272d | Separadores (decorativos) |
| `--border-control` | #868c98 | #62686f | Borde de campos y controles (≥ 3:1, WCAG 1.4.11) |

**Texto:**

| Token | Claro | Oscuro | Contraste mínimo |
|---|---|---|---|
| `--text` | #16181d | #eceef2 | ≥ 14:1 |
| `--text-2` (secundario) | #4b5160 | #a9aeb8 | ≥ 7:1 |
| `--text-3` (ayuda, marcadores) | #636978 | #8a909b | ≥ 4.8:1 |

**Acento:**
- `--accent` es jade: claro #0a7566, oscuro #45c9ad. Texto encima con `--accent-fg`: claro #ffffff, oscuro #05231d.
- Se reserva para la acción primaria, el foco, la selección y la marca. **Nunca significa "ok".**

**Estado** (siempre con ícono o texto, nunca solo color):

| Tono | Texto claro / oscuro | Fondo suave claro / oscuro | Uso |
|---|---|---|---|
| `--critical` | #c42b2b / #ff6b63 | #fdecec / #2a1214 | Fallos y **modo de cambio asistido**. Nada más es rojo. |
| `--warning` | #8f5400 / #f0b44a | #fdf3e1 / #2a2010 | Avisos, acciones con riesgo |
| `--success` | #1c7344 / #52cc8a | #e8f5ee / #10261a | Terminado bien, en línea |
| `--info` | #2a5fc4 / #79aaff | #eaf1fd / #121e33 | Neutro informativo, en curso |

Todos los pares texto/fondo pasan AA (≥ 4.5:1) en ambos temas; la tabla calculada va en la auditoría.

`--critical-solid` (#c42b2b / #c93a32) es el rojo de fondo con texto blanco: la franja del modo asistido, su segmento en la barra de estado y el botón `danger`. El texto blanco queda en 5.6:1 en claro y 5.1:1 en oscuro. El rojo claro del oscuro (#ff6b63) es solo para texto o íconos, nunca de fondo con blanco.

**Tipografía:**
- **Inter** para la interfaz y **JetBrains Mono** para todo lo que sale de un equipo o se teclea en él: salidas, comandos, IP, MAC, interfaces, hashes y puertos.
- Ambas tienen licencia OFL-1.1, por la **excepción para fuentes** que autorizó el dueño (2026-11-06). Esa excepción aplica solo a fuentes; el resto de dependencias sigue la lista permisiva.
- Se empaquetan subconjuntos latinos (latín básico, latín-1 y signos de puntuación) en woff2, con `font-display: swap`. Cada una lleva su OFL.txt y su nota en NOTICE.

| Rol | Tamaño / interlínea | Peso | Uso |
|---|---|---|---|
| `title` | 20 / 28 | 600, tracking −0.2 px | Título de página |
| `heading` | 15 / 22 | 600 | Sección |
| `body` | 13 / 20 | 400 | Texto y controles |
| `label` | 12 / 16 | 500 | Etiquetas de campo, encabezados de tabla |
| `caption` | 12 / 16 | 400, `--text-2` | Ayuda, metadatos |
| `mono` | 12.5 / 18 | 400 | Salidas y datos técnicos, con `tabular-nums` |

**Espacio, forma y capas:**

| Aspecto | Valores |
|---|---|
| Retícula | 4 px. Escala 4, 8, 12, 16, 20, 24, 32, 40 |
| Controles | Alto 32 px (28 en barras de herramientas); campos con relleno 6 × 10 |
| Radios | 4 (insignias, teclas), 6 (botones, campos), 8 (paneles), 12 (paleta, diálogos) |
| Sombras | Solo capas flotantes; dos niveles, `--shadow-1` (menús) y `--shadow-2` (paleta, diálogo) |
| Capas (z-index) | base 0 · sticky 10 · barra lateral 20 · paneles flotantes 30 · toast 40 · paleta y diálogo 50 |

**Movimiento:**
- Duraciones: 120 ms (hover, presionar), 160 ms (abrir capas) y 100 ms (cerrar).
- Easing `cubic-bezier(0.2, 0, 0, 1)`.
- Solo `opacity` y `transform`; nada de rebotes.
- Con `prefers-reduced-motion`, sin movimiento.
- Sin animaciones infinitas salvo el indicador de "en curso" (y no con movimiento reducido).

### 2. Shell
```
┌─────────────┬──────────────────────────────────────────────────────────┐
│ ◆ MACUAHUITL│ Diagnóstico › Ping        [⌕ Buscar o ir a…   Ctrl K]  – □ ×│  barra de título (arrastrable)
│             ├──────────────────────────────────────────────────────────┤
│ Acceso    › │ ▌MODO DE CAMBIO ASISTIDO ACTIVO · Puertos · SW1 · Ver  │  solo si hay una ejecución viva
│ Patrol      │                                                          │
│ Diagnóst. › │   Título de página                       [Acción] [⋯]    │
│ Análisis  › │   Descripción breve                                      │
│ Operación › │                                                          │
│ …           │   contenido                                              │
│ Bóveda      │                                                          │
│ Auditoría   │                                                          │
├─────────────┴──────────────────────────────────────────────────────────┤
│ ● Núcleo  🔓 Bóveda abierta  ⟳ 2 en curso  ▶ Patrol: 1 armado   ES · Oscuro │  barra de estado
└────────────────────────────────────────────────────────────────────────┘
```
- **Barra lateral** (224 px, se colapsa a 56 px con Ctrl+B):
  - Grupos con panel flotante, como hoy, con hover, click y teclado.
  - El tema y el idioma salen de la barra lateral y pasan a la barra de estado y a la paleta.
- **Barra de título:** ruta "Grupo › Módulo", el disparador de la paleta y los controles de ventana.
- **Barra de estado** (26 px, siempre visible): es el único lugar del estado global. Cada segmento es un botón que lleva a su módulo y se anuncia en una región `aria-live="polite"`:
  - núcleo;
  - bóveda;
  - ejecuciones en curso (con lista al hacer click);
  - trabajos de Patrol armados;
  - servidores de Campo escuchando;
  - modo asistido;
  - idioma y tema.
- **Franja roja del modo asistido:** aparece arriba del contenido en cualquier módulo mientras haya una ejecución asistida viva. No se cierra; lleva a la ejecución.

### 3. Teclado
| Atajo | Acción |
|---|---|
| Ctrl/Cmd + K | Paleta de comandos |
| Ctrl/Cmd + B | Colapsar o expandir la barra lateral |
| Ctrl/Cmd + Enter | Acción primaria de la vista (Ejecutar, Consultar, Analizar…) **excepto** en el modo asistido |
| Ctrl/Cmd + / | Lista de atajos |
| Alt + ← / → | Módulo anterior o siguiente del historial |
| Esc | Cierra la capa abierta (paleta, panel, diálogo) |

- **Paleta de comandos** (patrón combobox + listbox de WAI-ARIA):
  - busca módulos por nombre, grupo y palabras clave en los dos idiomas, más acciones (tema, idioma, cerrar bóveda, ir a la ejecución asistida viva, nuevo trabajo de Patrol, abrir sesión SSH);
  - muestra los recientes primero;
  - ↑/↓, Enter y Esc;
  - cada fila muestra su atajo como tecla (`kbd`).
- **Regla del modo asistido:** Enter nunca confirma un paso. "Confirmar" no recibe el foco automáticamente y se habilita 1.5 s después de mostrar el paso.

### 4. Componentes base (`src/components/`)
Todos tienen sus estados (reposo, hover, foco, presionado, deshabilitado, ocupado) definidos con tokens.

| Componente | Notas |
|---|---|
| `Page` | Encabezado: título (`h2`), descripción, acciones a la derecha y pestañas opcionales. Ancho de lectura 1040 px; las tablas pueden ocupar todo el ancho |
| `Section` | Título de sección y contenido. **Sin caja por defecto**: la jerarquía es tipográfica |
| `Panel` | Caja con borde fino. Solo para resultados y grupos que deben leerse como unidad |
| `Field`, `TextArea`, `Select`, `Check`, `PathField` | Como hoy (etiqueta real, ayuda con `aria-describedby`), más `width="xs|sm|md|lg|full"` (80, 160, 240, 400 px, 100 %) y error en línea bajo el campo |
| `FieldRow` | Varios campos en una línea (p. ej. host, puerto y protocolo) |
| `Button` | `primary`, `secondary`, `quiet` y `danger`; tamaños 32 y 28; `busy` con indicador y texto que termina en "…" |
| `ActionBar` | Botones al pie del formulario, primario primero; muestra el atajo Ctrl+Enter |
| `Tabs` | Un solo patrón para subherramientas (`role="tablist"`, flechas del teclado) |
| `DataTable` | Filas de 32 px, encabezado fijo, números tabulares, columnas mono, ordenar, virtualizada a partir de 100 filas |
| `ResultPanel` | Encabezado con título, insignia de estado, duración y acciones (copiar, exportar, limpiar); cuerpo con tabla, consola o texto. **Reemplaza las 12 copias de `useReport`** (el hook vive aquí) |
| `Console` / `Terminal` | Toda salida de equipo o configuración (diagnóstico, SSH, consola serie, análisis de configs, plantillas, diffs, plan del modo asistido) va en la terminal con la paleta que elige el ingeniero y resaltado de palabras clave (ver §8) |
| `Notice` | Tonos crítico, aviso, éxito e info, con ícono, título opcional, texto y acción. `role="alert"` solo para crítico |
| `Toast` | Solo éxito o info pasajeros, abajo a la derecha; los errores se quedan en línea |
| `Dialog` | `<dialog>` nativo, solo para confirmar algo destructivo fuera del modo asistido |
| `EmptyState` | Ícono, una frase de qué hacer primero y la acción primaria |
| `Skeleton` | Bloques estáticos (sin brillo animado) mientras carga una vista diferida o una tabla |
| `Badge`, `Kbd`, `StatusDot` | Insignia de estado con ícono, tecla y punto + texto |

### 5. Patrón del modo de cambio asistido
Se lee como un checklist de cambio de TAC:
1. **Franja roja fija** en la vista y en el shell: "Modo de cambio asistido · esto cambia la configuración de N equipos". No se puede cerrar ni ocultar.
2. **Plan por equipo**, en un panel por equipo con cuatro bloques mono numerados:
   - Verificación previa;
   - **Cambio** (líneas con `+`/`−`);
   - Verificación posterior y lo esperado;
   - **Reversa**.
3. **Armado:** una casilla "Revisé el plan y la reversa de los N equipos". "Iniciar cambio" es un botón `danger` con el número de equipos en el texto.
4. **Ejecución paso a paso:** lista vertical con el estado de cada paso (pendiente, esperando confirmación, aplicado, revertido, fallido). El paso actual muestra qué se envía y a qué equipo, y tres botones de peso distinto:
   - "Aplicar N líneas en SW1" (primario, habilitado a los 1.5 s, sin foco automático);
   - "Revertir" (secundario);
   - "Abortar" (discreto).
5. **Detención o fallo:** aviso crítico fijo con los equipos que quedaron cambiados y las acciones "Proponer reversa" o "Abortar".

### 6. Rendimiento
- **Carga diferida:** el manifiesto sigue siendo una línea por módulo, pero la vista se importa con `React.lazy`. Cada módulo es su propio bloque y la primera vista visible usa `Suspense` con `Skeleton`.
- **CSS por capas:** `styles/tokens.css`, `styles/base.css` y `styles/components.css` en el bloque inicial. El CSS propio de un módulo vive en su carpeta y se carga con él.
- **Íconos:** Lucide (ISC), importando cada ícono por separado (`lucide-react`, tree-shaking). Reemplaza los trazos dibujados a mano y da un set consistente de unos 40 íconos. Se lee su LICENSE antes de agregarlo.
- **Presupuestos que se miden en cada PR:** JS inicial ≤ 250 KB gzip (objetivo ≤ 120 KB), CSS ≤ 60 KB gzip, primera pintura < 400 ms y cambio de módulo < 100 ms en WebKitGTK.
- **WebKitGTK:** se usan `light-dark()`, `color-mix()` y `:has()` (soportados en 2.44+). `backdrop-filter` solo en la paleta y los paneles flotantes; sin soporte, cae a un fondo opaco.

### 7. Vista previa y capturas
- `npm run preview:ui` abre la app con los dobles de pruebas y datos de ejemplo (sin vitest).
- Los parámetros `?m=<id>&theme=light|dark&lang=es|en` fijan módulo, tema e idioma.
- Cada cambio visual se revisa con capturas en claro y oscuro, español e inglés, a 1280×800 y 1920×1080.

## 8. Terminal: paletas y palabras clave (enmienda del 2026-11-06, a pedido del dueño)
- El ingeniero elige la paleta una vez, en Ajustes (se abre también con "Idioma, tema y terminal" de la barra de estado; la terminal SSH tiene además su menú «Cambiar tema»), y aplica a todas las salidas. Hay dieciocho paletas: Clásica (la predeterminada, fondo negro multicolor), Consola oscura, Consola clara, Fósforo verde, Ámbar, Azul IBM, Solarizado, Claro, Medianoche, Grafito, Océano, Bosque, Brasa, Ciruela, Arena (clara), Papel (clara), Niebla y Alto contraste. El menú «Cambiar tema» de la terminal SSH las lista con una muestra. Todas pasan AA en cada color.
- Las reglas de resaltado son las de `internal/termcolor/rules.json`, compartidas con `mctl`, y se prueban con `cases.json` en Go y en TypeScript. Cubren:
  - estados;
  - direcciones e interfaces;
  - códigos de ruta por protocolo;
  - métricas y temporizadores;
  - palabras de política y de configuración IOS;
  - objetos de ACL y `hitcnt`;
  - servicios, versiones y series, y credenciales;
  - acciones de riesgo (`erase`, `reload`, `[confirm]`).
- Las listas de palabras clave de SecureCRT que compartió el dueño se tomaron como referencia. Sus expresiones se adaptaron con límites de palabra y a RE2 (Go no tiene lookaround), y sus colores sobre fondo claro se oscurecieron hasta pasar AA.

## Consecuencias

- El rework se hace por capas, cada una con la suite en verde y capturas antes y después: tokens → shell → componentes base → módulos de uso diario (Acceso, Patrol, Diagnóstico, Puertos y modo asistido) → el resto.
- **Para las otras sesiones:**
  - un módulo nuevo sigue siendo una línea en el manifiesto;
  - usa `Page`, `Section`, los campos y `ResultPanel`;
  - su CSS va en su carpeta;
  - no usa colores directos.
- Las pruebas buscan por rol y etiqueta. Cambiar de `<p className="warn">` a `Notice` puede cambiar `role` (status o alert); se ajustan las pruebas sin debilitarlas.
- Se agrega una dependencia (`lucide-react`, ISC) y una fuente (JetBrains Mono, OFL por la excepción).
