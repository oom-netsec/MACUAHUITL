# Fase 18: idioma completo de la interfaz y sección Acceso

El dueño probó la app compilada y pidió dos cosas: que no se mezclen los idiomas y que la terminal SSH sea visible junto a la consola serie.

## 1. Todo el texto visible pasa por i18n

- Todos los módulos y componentes usan `useT()` con claves en `lib/i18n/{es,en}.ts` (prefijo por módulo: `fleet.`, `calc.`, `security.`, …). Títulos, etiquetas, botones, placeholders, avisos, encabezados de tabla, estados, mensajes vacíos, `title`/`aria-label` y opciones de selectores.
- Los términos técnicos no se traducen: SSH, VLAN, ACL, Ping, nmap, iperf3, PCAP, TLS, DNS, SNMP, NTP, Syslog, comandos `show ...` y la CLI de IOS.
- Cadenas con valores: interpolación existente (`{n}`, `{device}`); plural con la variante `<clave>.one`.
- Los estados que antes guardaban texto ya armado (`setStatus("...")`) guardan la clave y sus valores, de modo que cambian de idioma al vuelo.
- Los nombres de las paletas de terminal (`internal/termcolor/palettes.json`) tienen clave `term.palette.<id>`; el nombre del JSON queda de respaldo.
- El idioma por omisión sigue siendo el del sistema; las pruebas simulan `es-MX`.

### Prueba que falla si queda texto fijo

`ui/frontend/src/lib/i18nCoverage.test.ts`:

1. `es.ts` y `en.ts` tienen las mismas claves y las mismas variables `{x}`.
2. Recorre con el analizador (`rolldown/parseAst`, MIT; TypeScript 7 ya no trae API de JavaScript) cada `.tsx` de `src/modules`, `src/components` y `src/app` (sin pruebas) y falla si encuentra texto fijo: nodos de texto JSX, `placeholder`, `title`, `aria-label`, `label`, `legend`, `hint`…, cadenas en `{cond ? "a" : "b"}`, propiedades `label`/`title`/`text` de objetos y opciones, y cualquier literal con aspecto de prosa (acentos, `¿¡…` o dos palabras) como los avisos de estado.
3. Lista blanca explícita (`TECH`) de siglas, protocolos, herramientas y nombres de atributos que no se traducen; el contenido de `<code>` y `<kbd>` y los comandos que empiezan con `show`/`ping`/`traceroute` quedan exentos.
4. Una prueba de la propia prueba confirma que detecta los seis tipos de texto fijo y que no marca lo permitido.

Antes de la pasada la prueba reportaba unas 800 apariciones en 25 archivos.

### Pendiente: textos que llegan del núcleo (en español, se muestran tal cual)

No se tradujeron en esta pasada; hay que decidir si el núcleo los emite por clave o con el idioma de la UI:

- Errores gRPC (`errorText`) y avisos de ejecución (`failReason`, `state`, `warnings`, `note`, `detail`, `why`).
- Informes de texto: Limpiador (`res.text`, `o.why`), Lotes (`res.text`), Cambios (`findings[].facet/detail`, `config_diff`, `upgradeCheck`, `complianceCheck`), Respaldos (`diff`, `r.warnings`).
- Análisis: hallazgos (`title`, `detail`, `explanation`, `action`, `rule`), línea de tiempo y vecinos.
- Forense: significado, causa y acción de la base de conocimiento; `rep.hint`, `rep.reason`, motivos de anomalía.
- Calculadoras y Deriva: títulos, cabeceras y notas de las tablas de resultado (`ResultView`).
- Flota: `reason` de los saltos, `p.evidence` y advertencias.
- Visibilidad: texto de traps y de eventos con error. El nombre del playbook "Topología L2" es el del YAML.

## 2. Sección Acceso

- Grupo nuevo `access` («Acceso» / «Access», ícono `terminal`) como primer grupo de la barra, justo después de Patrol (que sigue siendo el módulo de arranque).
- Entradas: **SSH** (módulo `terminal`, antes en Operación; vista "Terminal SSH") y **Consola serie** (módulo nuevo `modules/console/`).
- `modules/console/` saca de Campo la consola serie con su API (`api.ts`: `fieldPorts`, `consoleOpen/Send/Break/Close`, `onConsole`; los métodos de Wails y el servicio `field` del núcleo no cambian) y su doble de pruebas (`fake.ts`). Campo conserva Servidor (TFTP/HTTP) y Hash.
- `lib/stream.ts` aloja lo que comparten consola, Campo y SSH: `cleanTerminal` y `useStream`.
- Sin cambios en el núcleo, el proto ni el puente.
- Pestaña de consola serie dentro de la vista SSH: no se hizo; las dos entradas del grupo bastan y evitan acoplar dos módulos con ciclos de vida distintos (sesiones SSH multipestaña frente a un puerto serie único). Queda como mejora posible.

## Pruebas

Manifiesto y navegación (`App.test.tsx`: Acceso es el primer grupo, en español y en inglés; Operación ya no incluye Terminal), Campo (servidor, hash, cierre al salir), Consola serie (`ConsoleView.test.tsx`, movidas de Campo), SSH, `stream.test.ts` y la prueba de cobertura de idioma.
