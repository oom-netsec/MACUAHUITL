# ADR 0008: Arquitectura modular por áreas

Fecha: 2026-11-05 · Estado: aceptado

## Contexto

Tras 14 fases, cada herramienta nueva agrega líneas en los mismos archivos: `cmd/mctl/main.go` (643 líneas), `ui/bridge/bridge.go` (629), `internal/core/core.go` (importa 25 paquetes), `core.ts`, `fake.ts` y `App.tsx`. Cada merge choca ahí. Además, la lectura de salidas `show` está repartida entre `analyze`, `topo`, `change` y `fleet`; con NX-OS y ASA habría que tocar varios lugares por comando. El roadmap suma 13 fases más. Sin reglas, esto termina en un monolito.

## Decisión

### 1. Un área = un módulo vertical
Cada área (patrol, acl, diag, tools, analysis, field, change, visibility, calc, security, fleet, …) es un módulo con sus piezas en lugares fijos:

| Capa | Ubicación | Puede importar |
|---|---|---|
| Dominio | `internal/<área>/` | stdlib, `internal/parse/...`, utilidades sin estado |
| Red (si la hay) | `internal/diag/<x>/` | stdlib y librerías de red; nunca `core` |
| Servicio gRPC | `internal/service/<área>/` | los dominios de su área (p. ej. `service/change` usa `change`, `upgrade` y `compliance`), `gen`, `internal/service` (`service.Deps`), `ipc`, `transport`, `vault`, `audit`, `parse`; nunca `core` ni el servicio de otra área |
| API | `api/proto/macuahuitl/v1/<área>.proto` | — |
| CLI | `cmd/mctl/<área>/` | `gen`, `cmd/mctl/cli` |
| Puente | `ui/bridge/<área>.go` | `gen` |
| UI | `ui/frontend/src/modules/<área>/` con su `api.ts`, `fake.ts`, vista y pruebas | `lib/` compartida |

### 2. Registro en lugar de listas compartidas
- **Núcleo:** cada servicio implementa `service.Module` (`Register(*grpc.Server, Deps)`). `core` arma la lista en un único archivo (`modules.go`) y es solo la raíz de composición: bóveda, auditoría, guard, store y ciclo de vida. Sin lógica de herramientas.
- **`service.Deps`** es una interfaz pequeña (auditoría, guard, bóveda, store, rutas, actividad). Los servicios no ven el resto del núcleo.
- **mctl:** cada área registra sus comandos (nombre, uso, función) en una tabla. `main.go` despacha y genera la ayuda desde ella.
- **Puente y UI:** un manifiesto de módulos (`modules/index.ts` con id, título, vista y api). `App.tsx` lo recorre; `core.ts` y `fake.ts` se parten por área.
- **Meta:** agregar un área = archivos nuevos + **una línea** en cada lista de registro.

### 3. Una sola capa de parsers por plataforma
`internal/parse/<plataforma>/` (`iosxe` primero, luego `nxos` y `asa`) convierte cada comando `show` en un tipo de Go. Los dominios consumen tipos, no texto. Hay un solo parser por comando y plataforma, con sus fixtures en un solo lugar. Ante un formato desconocido devuelve un error tipado, que el dominio muestra como aviso.

### 4. Reglas verificadas por máquina
`tools/archcheck` (junto a noegress, en CI) falla si:
- un dominio importa `core`, `service`, `gen`, grpc o red;
- un módulo importa otro módulo de dominio (lo compartido va en `internal/parse` o en una librería común);
- `core` importa un dominio directamente (solo vía `service`).

## Consecuencias

- Hay que migrar lo existente: una fase de refactor sin cambio de comportamiento, cubierta por las pruebas actuales. Se hace en pasos (parsers, servicios, mctl, puente/UI), cada uno con la suite en verde.
- Las fases nuevas se escriben ya con este molde; los conflictos de merge se reducen a una línea por lista.
- Las plataformas nuevas (fases 2 y 3) se suman agregando `internal/parse/<plataforma>` sin tocar los dominios.

## Enmienda (2026-11-06)

`patrol` es el motor del núcleo (ejecuta los trabajos), no un dominio: queda fuera de la lista de dominios junto con `audit`. `capture`, `iosconf`, `pcapan` y `parse` son compartidos: cualquier dominio puede importarlos. `tools/archcheck` además exige que la raíz de un dominio no importe `ipc` ni `transport`, que solo los subpaquetes de `internal/diag` sean capa de red, y que un servicio no importe `core` ni el servicio de otra área.

## Enmienda (2026-11-12)

El formato de scripts de `internal/scripts` es compartido: lo usan la importación de scripts, la biblioteca y los paquetes de contenido (ADR 0010). Comprende `Script`, `Validate`, `Parse`, `NameKey`, el formato de export y `Derived(pbs []playbook.Playbook) []Script`. Esta última se extrae de `LibraryWithEN` y devuelve solo los `lib-<id>` derivados de playbooks, sin los de configuración. `internal/pack`, que es infraestructura del núcleo como `playbook`, puede importarlo. El resto de `internal/scripts` sigue siendo del área de Scripts. `archcheck` no lo hace cumplir, porque `internal/pack` no es un dominio; la regla se revisa en la revisión de código.
