# Fase 30c: el resto del texto del núcleo, traducible y estructurado

Es el paso 3 de 3 para que la app no mezcle idiomas. Los pasos anteriores ya están en main:
- **30a (PR #10):** `internal/i18n`, interceptor `accept-language`, `reason`/`metadata` y `core.localize`.
- **30a-2 (PR #11):** auditoría siempre en inglés.
- **30b (PR #13):** datos estructurados con `i18n.Text`/`Tx` en calc, seguridad y pcap.

El inventario está en `docs/plans/2026-11-07-idioma-nucleo.md` («Inventario por área»). El contrato de cada paso está al final de `docs/plans/contratos-front.md`.

## Reglas comunes (todos los bloques)
- **Compatibilidad.** Sin `accept-language`, o con `es`, todo texto queda byte por byte igual. Una prueba de regresión lo fija por RPC tocado, con golden generado desde el código de antes del cambio. La auditoría no se toca: ya está en inglés.
- **Cómo se traduce.**
  - Un texto libre que el núcleo devuelve pasa a `i18n.Text{Key, Args}`, con su texto es (el de hoy) y en, y se entrega en el idioma del contexto.
  - Si el front tiene que dibujar algo a partir de ese texto, viaja además estructurado: clave y argumentos, o códigos cerrados en inglés (`warning`, `error`…).
  - Los errores gRPC usan `service.Err`/`ErrFrom` con código del catálogo (30a).
- **Datos.** Los datos (IPs, nombres, salidas de equipos, comandos Cisco, palabras clave de IOS) no se traducen.
- **Catálogo.** Cada área tiene su archivo `internal/i18n/catalog_<área>.go`. `TestCatalogoCobertura` se mantiene verde. Traducciones con términos de Cisco TAC; no inventes.
- **Seguridad.** Ningún secreto en textos, argumentos ni metadata.
- **Puente.** Campos `omitempty`; todo error pasa por `wrapErr` (prueba AST). Los métodos que devuelven `string` y necesitan estructura ganan un método `*Report` aparte, como hizo 30b.
- **Archivos compartidos.** En `contratos-front.md` y en las listas, agrega al final.
- Sin dependencias nuevas. TDD, con al menos una mutación a mano por lógica nueva.

## Bloque A: valores que quedaron de 30b, más DNS, TLS e IKE
- **Calculadoras** (`internal/calc`): el veredicto óptico, «Lo limita» (ventana/pérdida), las capas MTU, los pasos BGP, «sí/no», `Tipo`/`Clase` de direcciones y las clases DSCP. Viajan como códigos cerrados (`verdict`, `limit`, `bgp_step`…) y su texto sale traducido.
- **RADIUS:** `RadiusExchange` gana `mschap2_verified` (bool opcional). Los `code` de hallazgo de RADIUS y TACACS+ pasan a inglés (`no_response`, `invalid_response`, `blast_radius`, `ma_invalid`, `reject`, `secret`, `authen_fail`, `author_fail`, `status`). Avisa en el contrato que el front debe cambiar los slugs.
- **DNS** (`internal/diag/dnsq`): `Finding.Detail` traducible; el `Code` ya es estable.
- **TLS** (`internal/diag/tlsinspect`): `Findings[].Detail` y `VerifyError`.
- **IKE** (`internal/ikedec`): unos 75 hallazgos con título, detalle y causa.

## Bloque B: asistente de cambios y snippets
- `internal/assist`: `plan.go`, `l2port.go`, `l3mgmt.go`, `snippets.go`, `templates.go`, `ports.go`, `credrotate.go` y `restore*.go`. Cubre las `notes`, las descripciones de pre/post, los avisos, el motivo concreto de `assist.refused` (hoy en español dentro del texto en) y los errores de `normIfaces`.
- `internal/assist/run.go` y `internal/service/assist`: `failReason`, `AssistDone` y los errores gRPC («el modo asistido no está habilitado…»).
- Las líneas de config de IOS NO se traducen.

## Bloque C: flota, análisis y cumplimiento
- `internal/fleet`: `FleetSummary.rows[].value/detail`, `PathHop.reason`, `warnings` y `Problem.evidence`.
- `internal/analyze`: `Finding.title/explanation/action/detail` y `TimelineEvent.text/note`.
- `internal/acl`: `Finding.detail` y `LineError`.
- `internal/change`, `internal/upgrade` e `internal/compliance`: hallazgos, la nota fija y las reglas de endurecimiento.
- `internal/drift` e `internal/cleaner`: texto del informe y `why` por línea.

## Bloque D: forense, métricas, Patrol, scripts y transferencias
- `internal/crashinfo`, `internal/logintel`, `internal/msgkb` e `internal/metrics`: `meaning/cause/action/verify`, `hint`, anomalías y advertencias, más la fuente fija «documentación pública de Cisco (sin validar en laboratorio)».
- `internal/patrol` y `internal/core/services.go`: `DeviceStateChanged.detail`, los pasos del Login Test y los errores gRPC de los servicios backup, terminal, visibility y forensic.
- `internal/scripts`: errores de validación y nombres y descripciones de la biblioteca de ejemplo. Es dato del usuario solo si lo escribió el usuario: los ejemplos de fábrica sí se traducen, con `name_en` como en los playbooks.
- `internal/diag/fileserve`, `internal/diag/transfer` e `internal/service/transfer`: motivos de rechazo, `TransferResult.report`, errores de validación y `TransferListing.reason`.

## Pruebas mínimas (por bloque)
- Regresión es byte por byte de cada RPC tocado.
- `en` traducido, sin español en las claves migradas.
- Lo estructurado coincide con el texto.
- Cobertura del catálogo.
- Ningún secreto en los campos nuevos.
