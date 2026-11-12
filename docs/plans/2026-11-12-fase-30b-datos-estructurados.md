# Fase 30b: datos estructurados para seguridad, calculadora y captura

Este es el paso 2 de 3 para que la app no mezcle idiomas. El paso 1 es la fase 30a (PR #10), con la infraestructura `internal/i18n`, el interceptor de `accept-language`, `reason`/`metadata` y la bandera `core.localize`. El inventario está en `docs/plans/2026-11-07-idioma-nucleo.md`, sección «Acoplamientos que hay que romper primero».

Quedan tres módulos del front que dibujan sus tarjetas leyendo texto en español del núcleo:

| Front | Qué lee | Origen |
|---|---|---|
| `ui/frontend/src/modules/security/parse.ts` | «Servidor RADIUS», «Hallazgos:», «Emisor», «Serie», «Validez … (N días)», «Llave», «Firma», «servidor pidió:», «enviado»/«recibido»… | `radiustest.Text`, `tacacstest.Text`, `pki.Text` |
| `ui/frontend/src/modules/calc/bars.ts` | Títulos «Subred …», «VLSM sobre …», filas «Red», «Primera usable», «Hosts usables», columnas «Prefijo», «Nombre», nota «Espacio libre: » | `internal/calc/*.go` (`CalcResult.tables/notes`) |
| `ui/frontend/src/modules/tools/pcapParse.ts` | Encabezados «== Conversaciones», «== Equipos con más tráfico» | `internal/pcapan/text.go` |

## Objetivo
Cada uno de esos RPC devuelve, además del texto de siempre, los mismos datos de forma estructurada, con claves estables. Así el front podrá dibujarlos sin parsear el español; la migración la hace la sesión de front. Esta fase no toca la UI salvo el puente y `api.ts`/`fake.ts`, si hace falta exponer los campos.

## Reglas
- **Compatibilidad.** El texto actual (`text`, `json` y los campos existentes) queda idéntico byte por byte, sin `accept-language` o con `es`. Solo se suman campos de proto, sin renumerar. Una prueba de regresión fija el texto de hoy de cada RPC tocado.
- **Claves estables, no texto.** Las etiquetas de fila y columna, los títulos y los encabezados de sección viajan como clave (`key`, por ejemplo `calc.row.network`, `calc.col.prefix`, `security.pki.issuer`, `pcap.section.conversations`) con sus argumentos (`args`, `map<string,string>`). Los valores (IPs, números, fechas, nombres de host) viajan como datos.
  - Agrega cada clave al catálogo `internal/i18n` con su texto es (el de hoy) y en. Así el núcleo también puede devolver el texto traducido con `accept-language: en`. La prueba de cobertura del catálogo debe seguir verde.
  - En `en`, el texto de esos RPC sale traducido. En `es`, idéntico al de hoy.
- **Antes de diseñar, lee lo que hace el front.** Por módulo, lee primero el `parse.ts`/`bars.ts`/`pcapParse.ts` correspondiente y su prueba: lo estructurado debe cubrir TODO lo que hoy el front saca del texto. Si algo no se puede cubrir, anótalo en el PR.
- **Severidades y estados** que ya se mapean en el front (`aviso/error/info`, «ausente/válido/inválido») viajan como código cerrado en inglés (`warning`, `error`, `info`, `absent`, `valid`, `invalid`). Revisa `lib/vocab.ts` para no romper lo existente.
- **Seguridad.** Ningún secreto RADIUS/TACACS+, llave privada ni contenido sensible puede ir en los campos nuevos. Mantén el mismo enmascarado que el texto.
- **No toques** lo de la fase 30a-2 (detalles de auditoría): va en otra rama en paralelo.
- Nada de dependencias nuevas. TDD, con al menos una mutación a mano por lógica nueva.

## Por módulo (forma sugerida, ajústala a lo que lea el front)
- **Calculadora.** `CalcTable` y `CalcResult` ganan `title_key`/`title_args`, `columns[].key` y `rows[].label_key`/`label_args`, y `notes` gana `notes_structured[] {key, args}`. Cubre todas las calculadoras de `internal/calc` (subred, VLSM, resumen, BGP, MTU…) y no solo las que dibuja `bars.ts`, porque el front las usará todas.
- **Seguridad.**
  - `RadiusTestResponse` y `TacacsTestResponse` ganan una lista de pasos/atributos estructurados: `{key, args, direction: sent|received, value}` y los hallazgos `{code, severity, args}`.
  - `PkiDecodeResponse` (y las que imprimen un certificado) gana `certificate {subject, issuer, serial, not_before, not_after, days_left, key {algorithm, bits}, signature {algorithm, valid}, san[], key_usage[]}` y `warnings[] {code, args}`.
- **Captura (pcap).** La respuesta de `ToolsPcap` gana sus secciones estructuradas: `summary {packets, bytes, …}`, `conversations[]`, `top_talkers[]`, `neighbors[]` y lo demás que imprima `text.go`, con sus encabezados como `key`.

## Puente y contrato
- Puente (`ui/bridge`): los DTO exponen los campos nuevos con `omitempty`, para que el JSON de hoy no cambie. Todo error sigue pasando por `wrapErr`, porque la prueba AST de 30a lo exige.
- TS: `api.ts`/`fake.ts` de security, calc y tools ganan los tipos opcionales.
- Contrato: una sección nueva al final de `docs/plans/contratos-front.md` con cada forma y la lista de claves.

## Pruebas mínimas
- Regresión byte por byte del texto actual de cada RPC tocado.
- Para cada calculadora, cada prueba de seguridad y el pcap de prueba: lo estructurado coincide con lo que dice el texto (mismos valores).
- `en` devuelve el texto traducido. La cobertura del catálogo sigue verde.
- Ningún secreto en los campos nuevos.
