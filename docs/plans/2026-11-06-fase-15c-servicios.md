# Fase 15c: servicios por módulo (ADR 0008 §1-2)

## Qué se movió
- `internal/service`: `Deps` (auditoría, exportar auditoría, actividad, reloj, guard, bóveda, parámetros de sellado, store, carpeta de salidas, `LookPath` de diag, foto de un trabajo, Patrol para la ventana de cambio) y `Module` (`Register(grpc.ServiceRegistrar, Deps)`). Ayudantes compartidos: `NewID`, `VaultErr`, `RunID`, `Report`, `MS`, `SyslogDuration`.
- `internal/service/{acl,analysis,calc,change,diag,field,fleet,prefs,security,tools,visibility}`: antes `internal/core/services_<área>.go`, sin cambio de lógica. Cada paquete expone `Module{}`.
- `internal/core/modules.go`: una línea por módulo. `internal/core/deps.go`: `coreDeps`, la vista angosta de `Core`. `Serve` solo recorre la lista.
- `internal/service/servicetest`: `Deps` real mínimo (bitácora, guard y bóveda verdaderos) para probar un servicio sin el núcleo.

## Decisiones
- Vault, patrol, event y audit se quedan en `core` (módulo `nucleo` en `modules.go`): leen y mutan jobs, bus, planificador y bóveda, o sea el ciclo de vida. `convert.go` también (solo lo usa patrol/event). Inventory sigue sin implementar, registrado ahí.
- Las pruebas de integración con `newHarness` se quedan en `core` (prueban la composición completa). Pasaron a su paquete las que tocan internos: `serveSink` (field), `SyslogDuration` (service), resolvedor del sistema de DNS (tools) y SNMP sin allow (visibility, con `servicetest`). Ninguna aserción cambió.
- Los servicios no ven `Core`: el acceso a un trabajo es `Deps.Job(id)` (estado y carpeta); la ventana de cambio crea y arma por `Deps.Patrol()` y valida con `Deps.ValidateJob`.

## Pendientes
- Ninguna prueba unitaria nueva por servicio: la cobertura sigue siendo la de integración en `core`.
- `tools/archcheck` (ADR §4) aún no existe.
