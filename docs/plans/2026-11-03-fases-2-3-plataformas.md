# Fases 2 y 3 — Resto del portafolio Cisco: Plan de implementación

**Goal:** Patrol contra NX-OS, Catalyst 9000, WLC 9800, WLC AireOS y FTD/Firepower por SSH (Fase 2), y contra ISE y Catalyst Center / SD-Access por API (Fase 3), con el mismo modelo de outputs, enmascarado y auditoría que IOS-XE.

**Prerrequisito que bloquea ambas fases:** transcripciones reales anonimizadas de cada plataforma en `test/transcripts/<plataforma>/` (procedimiento en `laboratorio-bateria-de-pruebas.md`). Sin ellas, un driver solo se prueba contra la idea que tenemos de la plataforma. El dueño no tiene estos equipos; las opciones son imágenes virtuales (CML, NX-OSv, Cat8000v, FTDv, ISE eval) o salidas de clientes anonimizadas.

**Architecture:** Un driver por plataforma en `internal/platform/<nombre>` que implementa `platform.Driver`. `patrol.Deps.NewDriver` pasa a elegir el driver según la detección inicial, que sigue haciendo `iosxe` con `show version` y, si no reconoce, prueba los demás. Las reglas de enmascarado y la lista permitida de comandos se vuelven tablas por plataforma en `internal/mask` e `internal/playbook`. Las plataformas API usan `internal/transport/https.go`, que pasa por `EgressGuard` y verifica TLS estricto con opción de fijar el certificado por host (spec §7).

**Spec:** `docs/architecture/2026-11-02-macuahuitl-architecture-design.md` §7.1, §8, §12.5, §17.

## Global Constraints

- Ningún driver escribe en el equipo: cada plataforma trae su lista permitida (`show`, `dir`, …) y la lista de prefijos peligrosos se amplía con los suyos (NX-OS `run bash`, `python`; FTD `expert`, `sudo`; WLC `config`).
- Toda credencial de API viaja por `EgressGuard` y TLS verificado; un certificado autofirmado se fija por host de forma explícita y queda en auditoría.
- Las transcripciones nuevas llevan los marcadores `MARKER-*` para las pruebas de enmascarado de cada plataforma.

## Fase 2 — SSH

| Tarea | Plataforma | Diferencias con IOS-XE que el driver debe cubrir | Enmascarado extra |
|---|---|---|---|
| 2.1 | Catalyst 9000 | Mismo driver IOS-XE; solo playbooks (`show switch`, `show platform`, `show stack-power`, `show environment`, PoE) y detección `C9[2-6]00` en `show version` | — |
| 2.2 | NX-OS | Prompt `host#` sin `enable`; `terminal length 0` igual; `show running-config` con `!Command:`/`!Time:`; `show tech-support` muy largo (timeout 1200 s); `feature` y `vdc` | `snmp-server user … auth md5 X priv Y`, `tacacs-server key 7`, `key-string`, `password 5` de usuarios |
| 2.3 | WLC 9800 | IOS-XE; playbooks de wireless (`show wireless summary`, `show ap summary`, `show wlan summary`, `show wireless client summary`) | `security wpa psk`, `dot1x`, RADIUS |
| 2.4 | WLC AireOS | Login interactivo (`User:` y `Password:` dentro de la sesión), prompt `(Cisco Controller) >`, `config paging disable`, comandos `show run-config` | `config radius auth add … <key>`, `wlan security wpa akm psk set-key` |
| 2.5 | FTD / Firepower | Prompt `>` (CLISH), `expert` cambia a shell Linux (prohibido en recolección), `show running-config` solo en modo `system support diagnostic-cli`; el driver entra a diagnostic-cli, hace `enable` y vuelve | `enable password`, `aaa-server … key`, `tunnel-group … pre-shared-key` |
| 2.6 | Detección | `patrol` elige driver por `show version` / banner inicial; si ninguno reconoce, `platform` falla en el Login Test | — |

Cada tarea: transcripciones en `test/transcripts/<plataforma>/`, el simulador aprende el prompt y el login de esa plataforma (`simulator.Config.Platform`), driver con las mismas pruebas que `iosxe` (`Open`, `Run`, paginación, timeout, `Detect`), playbooks YAML, reglas de enmascarado con prueba sobre la transcripción de `show running-config`.

## Fase 3 — API

| Tarea | Plataforma | Qué se recolecta | Cómo |
|---|---|---|---|
| 3.1 | `transport/https.go` | — | Cliente HTTPS que usa `Guard.Dial`, TLS 1.2+, verificación estricta, `PinnedCert` por host; pruebas con un servidor TLS local y certificado autofirmado |
| 3.2 | ISE | Nodos y servicios (`/ers/config/node`), políticas, sesiones activas (`/admin/API/mnt/Session/ActiveList`), `show` básicos por SSH (`show application status ise`, `show logging system`) | ERS/OpenAPI con usuario de API; el output se guarda como JSON indentado más un resumen de texto |
| 3.3 | Catalyst Center / SD-Access | Inventario de fabric (`/dna/intent/api/v1/business/sda/fabric-site`), dispositivos (`/dna/intent/api/v1/network-device`), salud (`/dna/intent/api/v1/network-health`) y después SSH a los nodos de fabric con el driver IOS-XE | Token por `/dna/system/api/v1/auth/token`; las direcciones que devuelve entran al trabajo solo tras confirmación del ingeniero (spec §6.1) |
| 3.4 | Enmascarado JSON | Claves `password`, `secret`, `sharedSecret`, `psk`, `token` en cualquier nivel | Regla genérica sobre JSON antes de escribir |

## Orden sugerido

1. Conseguir transcripciones (bloqueante). Primero NX-OS y Cat9k, que son lo más común en casos TAC de campus y data center.
2. 2.1 y 2.2, luego 2.3 y 2.4, al final 2.5 (la más distinta).
3. 3.1 antes que cualquier plataforma API.

## Criterio de terminado por plataforma

Un trabajo `tac-baseline` de 3 rondas contra el simulador con transcripciones reales produce outputs completos, enmascarados y con manifest; `TestNoLeakEndToEnd` sigue en verde; y, cuando haya equipo real, la batería de laboratorio secciones B, C y D pasan.
