# Fase 29a — Traps y flows con el control de inundación y el archivo de syslog

Pedido del dueño (vía la sesión de front). Hoy `VisibilityService.SnmpTraps` y `Flows` solo tienen `save` (bool), con un archivo por sesión en `outputs/snmp-traps` y `outputs/flows` (`outFile` en `internal/service/visibility/visibility.go`). Tienen que dar lo mismo que el receptor syslog de la fase 28a (#54):

- tope de tasa por origen y global, con ráfaga;
- cola acotada que descarta y cuenta, sin bloquear la lectura del socket;
- archivo con rotación (MB y/o minutos), plantilla `{fecha}{hora}{origen}`, retención y formato (texto, crudo o jsonl);
- eventos `drops` y `rotated_path` iguales a los de syslog.

## Reglas globales
- **Reutilizar, no copiar.** El limitador, la cola y el `Sink`/rotación de `internal/diag/syslogd` (`limits.go`, `pipeline.go` y `rotate.go`) pasan a un paquete compartido, por ejemplo `internal/diag/ingest`, que importan syslogd, el receptor de traps y el de flows. La API de syslogd y sus pruebas no cambian de comportamiento: son la red de seguridad del movimiento.
  - Comprueba con archcheck que el paquete nuevo es legal (los dominios no se importan entre sí). Si `internal/diag/...` es un solo dominio, va ahí.
- **Mismos defaults y rangos que syslog.** La validación de rangos del servicio debe ser una sola función compartida (hoy vive en `internal/service/tools/tools.go`). Muévela a un lugar que los dos servicios puedan importar sin romper ADR 0008.
- **Rutas.** Todo queda bajo `outputs/snmp-traps` y `outputs/flows` (carpeta 0700, archivos 0600). La plantilla se valida con `ValidateTemplate` y no hay rutas arbitrarias.
- **Auditoría.** Se audita la config efectiva al iniciar, cada borrado por retención (`visibility.traps.retencion` / `visibility.flows.retencion`) y el resumen con los descartes al terminar.
- **El formato `crudo`:**
  - en traps: el PDU decodificado en una línea de texto, porque no hay texto «crudo» legible;
  - en flows: el registro de flujo en una línea.

  Documenta la elección en el contrato.
- **`{origen}`.** Es la IP del exportador o del agente, con la misma forma que en syslog.
- TDD, al menos una mutación por lógica nueva, y nada de dependencias nuevas.

## Proto, mctl, puente y contrato
- `SnmpTrapsRequest` y `FlowsRequest` ganan los mismos campos que `SyslogRequest` (tasa, ráfaga, global, cola, rotate_mb, rotate_minutes, name_template, max_files, format), sin renumerar.
- `SnmpTrapsResponse` y `FlowsResponse` ganan `drops` (reutilizan el mensaje `SyslogDrops`; si hace falta, renómbralo a uno común con un alias compatible) y `rotated_path`.
- `output_path` del primer evento pasa a ser la carpeta, como en syslog.
- mctl: las mismas banderas que `mctl syslog listen` en los comandos de traps y flows, con su `help.golden`. Valores fuera de int32 se rechazan.
- Puente y TS: amplía `TrapsStart`/`FlowsStart` (o como se llamen) con `opts` opcional, como `SyslogStart`, y los eventos nuevos en `api.ts`/`fake.ts`.
- Contrato: una sección nueva al final de `docs/plans/contratos-front.md` que remita a la de syslog y diga solo las diferencias.

## Pruebas mínimas
- Las de syslogd siguen verdes sin cambios de aserción tras el movimiento.
- Traps y flows:
  - una ráfaga de un origen no le quita lugar a otro;
  - con la cola llena, el lector no se bloquea y los descartes se cuentan;
  - la rotación y la retención borran solo los archivos de su plantilla;
  - los tres formatos;
  - un cliente atascado no cuelga el cierre (como en `TestSyslogStuckClientDoesNotHangCloseAndFileKeepsEverything`).
- Servicio: los rangos inválidos dan InvalidArgument y la auditoría registra la config y los borrados.
