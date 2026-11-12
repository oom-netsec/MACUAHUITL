# Cierre del rework de la interfaz (fase 19)

Fecha: 2026-11-06 · Rama: `fase-19-ui-rework` · Antecedentes: `2026-11-06-ui-rework-auditoria.md` (punto de partida) y `docs/adr/0009-sistema-de-diseno.md` (sistema de diseño aprobado).

## 1. Presupuestos: antes y después

Medido igual que en la auditoría: `vite build` con gzip -9, y WebKitGTK 2.52 (el motor de Wails) sobre la vista previa de producción. El cambio de módulo recorre todos los destinos de la barra.

| Medida | Antes | Después | Presupuesto | Estado |
|---|---|---|---|---|
| JS inicial (gzip) | 162 KB, un solo bloque con los 30 destinos | **145 KB**, cada módulo bajo demanda (31 destinos con Transferencias) | ≤ 250 KB | Cumple |
| CSS inicial (gzip) | 4.3 KB | **7.4 KB**, más el CSS de cada módulo al abrirlo | ≤ 60 KB | Cumple |
| Fuentes | Inter completa, 352 KB, `font-display: block` | Inter variable y JetBrains Mono en subconjunto latino, 108 KB, `swap` | — | Mejor |
| Primera pintura | 769 ms (sin GPU) | 303 a 709 ms; **mediana de 390 a 670 ms** según la carga de la máquina | < 400 ms | **No cumple de forma estable** |
| Cambio de módulo | mediana 64 ms · p95 141 ms | **mediana 31 ms · p95 48 a 50 ms** · máximo 83 ms | < 100 ms | Cumple |
| Listas largas | Solo la grilla de Patrol | `DataTable` virtualizada en Flota, Forense, Syslog, Traps, Bóveda y Corridas; grilla de Patrol | Virtualizar > 50 filas | Cumple |

Las medidas de la primera pintura se tomaron con la máquina cargada (promedio de carga de 14 a 18). React confirma el primer render hacia los 160 ms. El resto es el estilo y el diseño del motor más la cascada de efectos iniciales, que en la vista previa es peor porque los dobles responden al instante. Lo que queda por probar está en la sección 4.

## 2. Qué cambió

- **Shell:**
  - barra de estado: núcleo, bóveda, ejecuciones en curso, Patrol armado, modo asistido y preferencias;
  - paleta de comandos con Ctrl+K;
  - atajos: Ctrl+B, Ctrl+/, Alt+← y →, y Ctrl+Enter en el primario de la sección con el foco;
  - barra lateral contraíble, ruta en la barra de título y franja global del modo asistido.
- **Componentes compartidos:** Page, Section, Tabs, ResultPanel, EmptyState, ErrorState, Badge, StatusPill y SeverityBadge, CopyButton, RelativeTime y Duration, DataTable, DiffView, TimeChart (uPlot) con Sparkline y Meter, DropZone, DownloadButton, ExportMenu, TransferProgress y DeviceMenu.
- **Terminal:** ocho paletas de color con contraste AA y resaltado por palabras clave compartido con `mctl` (`internal/termcolor`). Se aplica en todas las salidas: terminal, análisis de configuraciones, plantillas y diferencias.
- **Modo asistido:**
  - el plan es un checklist por equipo;
  - "Aplicar" no recibe el foco y se habilita a los 1.5 s;
  - el inicio es un botón de peligro que dice cuántos equipos toca;
  - Ctrl+Enter nunca actúa dentro de una ejecución.
- **Vistas útiles por módulo:**
  - Patrol: métricas.
  - Ping: RTT en vivo.
  - Traceroute: RTT por salto.
  - Puertos: vista de frente del switch.
  - Respaldos: línea de tiempo y diferencias.
  - Lotes: matriz de resultados.
  - Visibilidad: gráficas SNMP.
  - Seguridad: tarjetas de RADIUS y TACACS+, y cadena de certificados.
  - Calculadoras: barras de reparto.
  - PCAP: barras.
  - DNS: árbol de resolución.
  - TLS: cadena de certificados.
  - Syslog en vivo: tabla virtualizada.
  - Flota: cadena de saltos y mapas de calor.
  - Forense: carriles de flapping y curva de memoria.
  - ACL y Corridas: copiar y exportar.
- **Transferencias** (de la fase 22a, que entró a `main` durante esta fase): pasó al sistema de diseño.
- **Datos del núcleo:** el backend implementó los contratos de `docs/plans/contratos-front.md` (fase 19, datos para la UI). Patrol grafica `core.jobMetrics` a través de `fromJob`, y Puertos dibuja el frente con `core.portStatus`. Exportar y descargar usan el diálogo nativo y `Bridge.WriteFile`.

## 3. Revisión independiente

La revisión independiente cubrió los 61 commits contra `origin/main`; una segunda revisión cubrió la adaptación a los contratos del backend y las correcciones de la GUI.

- **Sin hallazgos:** no hay datos inventados fuera de la vista previa y de los dobles. Los parsers nuevos coinciden con el texto del núcleo.
- **Corregido** (commit `e72fc8c`, cada punto con su prueba):
  - Ping: los últimos paquetes sin respuesta no contaban como perdidos.
  - DiffView: congelaba la app con configuraciones muy distintas. Ahora recorta lo común, usa arreglos tipados y tiene un tope con aviso.
  - CSV: había inyección de fórmulas. Ahora hay un solo `csvCell` compartido.
  - Ctrl+Enter desde la paleta disparaba el primario de una vista, y no respetaba la sección con el foco.
  - Modo asistido: faltaba `key` por paso pendiente.
  - El menú de equipo no precargaba la dirección en Respaldos y Flota.
  - TLS con fecha ilegible se veía vigente.
  - El conteo en pausa del syslog podía salir negativo.
  - Respaldos no ordenaba la comparación por fecha.
  - El DropZone no manejaba un diálogo que falla.
  - Había pistas de Ctrl+Enter donde el atajo está apagado.

## 4. Pendientes, por prioridad

### Alta
1. **Primera pintura < 400 ms de forma estable.**
   - Medir en la app real (`./dev.sh`, con el núcleo) con la máquina en reposo.
   - Si sigue arriba, probar:
     - posponer `useShellStatus` y las suscripciones iniciales a después de la primera pintura;
     - cargar bajo demanda el diccionario del idioma inactivo (unos 17 KB gzip; la paleta lo necesita solo al abrirse).
2. **Explorador remoto y avance de Transferencias:** el núcleo ya tiene `transferBrowse`, el avance y cancelar (§3 y §4 del contrato). Falta la vista; `TransferProgress` ya existe. Lo mismo para el selector de equipos con `listDevices` (§5).

### Media
3. **Datos estructurados del núcleo para lo que hoy se lee del texto:** RADIUS, TACACS+ y PKI en Seguridad, subred y VLSM en Calculadoras, y PCAP. Si el núcleo cambia el texto, la vista vuelve a la salida cruda, sin error.
4. **Forense:**
   - conteos por minuto en el informe de patrones, para el histograma de syslog;
   - hora de cada transición de flapping, para carriles a escala de tiempo;
   - ronda con hora en las fugas de memoria, para usar TimeChart.
5. **Deriva:** el antes y el después de cada cambio, para usar DiffView.
6. **Cambios:** `config_diff` solo trae líneas sueltas. Con el texto PRE y POST, DiffView sustituiría la terminal teñida.
7. **Ejecución asistida iniciada desde `mctl`:** la franja la ve, pero no puede llevar a ella porque el núcleo no dice qué módulo la inició.
8. **Severidad de los traps:** hoy se deduce en el cliente por el nombre del trap. Debería venir del núcleo.

### Baja
9. **DataTable:**
   - alto automático por número de filas;
   - seguir el final (syslog);
   - ranura de barra de herramientas;
   - cerrar el menú de columnas con Esc o con un clic fuera;
   - avisar si la exportación falla.
10. **Diálogo de atajos:** atrapar el foco.
11. **Componentes a compartir:** barras horizontales (`Bars`), barra segmentada (`SegmentBar`), Heatmap y Lanes. Hoy viven en Visibilidad, PCAP, Calculadoras, Flota y Forense.
12. **Pulidos:**
    - Meter con umbral bajo, para días restantes;
    - Duration con un decimal por debajo de 10 ms;
    - DiffView que acepte líneas ya calculadas;
    - eje de rondas en TimeChart.
13. **Capturas en WebKitGTK:** las 240 del después se tomaron en Chromium. Falta un recorrido visual en la app real con las paletas de terminal.
