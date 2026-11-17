# #200 — Ping extendido: plan de implementación

**Goal:** que Diagnóstico → Ping tenga las opciones del ping extendido de IOS y del `ping -t` de Windows: continuo con resumen al parar, origen, DF, TTL, espera por respuesta, duración total, IPv4/IPv6, barrido de tamaños y ToS. Pedido del dueño (issue #200).

**Architecture:** las opciones siguen en `RunRequest.options`, validadas por rango en `internal/diag/args.go` (`Build`, una rama por sistema, ADR 0012 f): nunca pasa texto libre al comando. El núcleo calcula el resumen a partir de las respuestas, así sale igual en los dos sistemas. Una RPC nueva, `StopRun`, detiene sin cortar el stream para que el cliente reciba el resumen.

**Licencias:** nada nuevo.

## Contrato (fijado en este PR)

```proto
rpc StopRun(StopRunRequest) returns (StopRunResponse);   // NOT_FOUND si run_id no existe o ya terminó

message RunResponse {
  ... // 1-4 como hoy
  string run_id = 5;             // solo en el primer evento
  PingSummary ping_summary = 6;  // evento final de ping
  SweepPoint sweep_point = 7;    // uno por tamaño del barrido
}
message PingSummary { int64 sent = 1; int64 received = 2; double loss_pct = 3; double min_ms = 4; double avg_ms = 5; double max_ms = 6; double mdev_ms = 7; }
message SweepPoint  { int32 size = 1; int64 sent = 2; int64 received = 3; string result = 4; } // ok | loss | frag
message StopRunRequest { string run_id = 1; }
```

El `run_id` es del núcleo y no reemplaza ningún id del cliente: el puente guarda runId → run_id y llama a `StopRun` con el segundo. Cancelar el stream sigue deteniendo la ejecución como hoy, pero sin resumen.

## Opciones de ping

| Clave | Rango | Linux (iputils) | Windows (ping.exe) |
|---|---|---|---|
| `count` | 1-100 (4 por omisión); se ignora con `continuous` | `-c` | `-n` |
| `continuous` | `true` | sin `-c` | `-t` |
| `interval` | 0.2-60 s | `-i` | no existe → `diag.err.opt_windows` |
| `size` | 0-65500 | `-s` | `-l` |
| `source` | IP literal de una interfaz local, o nombre de `ListInterfaces` | `-I` | `-S`, solo IP; nombre → `diag.err.opt_windows` |
| `df` | `true` | `-M do` | `-f`, solo IPv4; con `family=6` → `diag.err.opt_windows` |
| `ttl` | 1-255 | `-t` | `-i` |
| `timeout` | 1-60 s por respuesta | `-W` | `-w` en ms |
| `duration` | 1-3600 s en total | la aplica el núcleo (contexto) | igual |
| `family` | `4` \| `6` | `-4` / `-6` | `-4` / `-6` |
| `tos` | 0-255 | `-Q` | no aplica (`-v` deprecado) → `diag.err.opt_windows` |
| `sweep_start`, `sweep_end`, `sweep_step` | 0-65500; paso ≥ 1; como mucho 100 tamaños; los tres o ninguno | el núcleo corre un ping por tamaño | igual |

Reglas: `continuous` y barrido no van juntos; el barrido no va con `size`; con barrido, `count` por tamaño es 1-5 (1 por omisión). `source` debe ser de la misma familia que el destino (si `family` está dado). Un valor fuera de rango da InvalidArgument con `metadata.key` como hoy.

**Tope de seguridad del continuo:** 24 h o 86 400 envíos, lo que llegue antes; al llegar se detiene como con `StopRun`.

## Resumen

El núcleo lee cada respuesta del proceso (líneas de eco con tiempo y las de «sin respuesta») con un parser por sistema en `internal/diag` y cuenta enviados, recibidos y tiempos. `loss_pct = (sent-received)/sent*100`; `mdev` = desviación estándar poblacional, como iputils; en Linux se toman los valores de la línea `rtt` cuando aparece. El resumen va en el evento final (done=true) al terminar `count`, `duration`, `StopRun` o el tope. Las líneas de texto siguen saliendo como hoy.

## Barrido

Por cada tamaño, el núcleo corre ping con `count` y las demás opciones (DF incluido si se pidió) y manda un `sweep_point`:
- `ok`: volvieron todas;
- `frag`: el sistema avisó que hace falta fragmentar con DF («Message too long» / «Frag needed» en Linux, «Packet needs to be fragmented but DF set» en Windows);
- `loss`: lo demás.

Al final, un `ping_summary` con el total. `StopRun` interrumpe el tamaño en curso; ni su punto ni su cuenta entran al resumen. `duration` y el tope de envíos valen para el barrido entero.

## StopRun

`internal/service/diag` lleva un registro de ejecuciones vivas (run_id → cancelar). `StopRun` cancela el proceso de forma ordenada (en Linux SIGINT para que ping termine; en Windows el Job Object) y el manejador de `Run` manda el resumen y `done`. Auditoría: `diag.stop` con el run_id. Una ejecución ya terminada da NOT_FOUND.

## Bloques

1. **200-1 (este PR):** plan y proto, `gen/` regenerado. El servicio responde `Unimplemented` a `StopRun` hasta 200-3.
2. **200-2 args:** las opciones nuevas en `Build` por sistema, con tabla de pruebas de argv (Linux y Windows), rangos y rechazos; mutación en cada rango.
3. **200-3 continuo, resumen y StopRun:** parser de respuestas por sistema (fixtures de salida de iputils y de ping.exe, sin datos de equipos reales), registro de ejecuciones, `StopRun`, `duration`, tope de seguridad, auditoría. Prueba con un ping falso (el doble de proceso que ya usan las pruebas de diag) que se detiene con `StopRun` y manda el resumen.
4. **200-4 barrido:** bucle por tamaño, `sweep_point`, detección de `frag` con fixtures de los dos sistemas.
5. **200-5 mctl:** `mctl diag ping -o key=value` ya pasa las opciones; agregar el resumen al final, el barrido como tabla, y Ctrl+C en continuo llama a `StopRun` y espera el resumen. Ayuda es/en con golden.
6. **Puente y UI:** Front (`fase-200-ping-ui`).

## Review Focus

1. Ninguna opción deja pasar texto al comando (sobre todo `source`: IP literal o nombre de interfaz existente, nunca otra cosa).
2. El continuo siempre termina: `StopRun`, cancelación del stream, `duration` o el tope.
3. El resumen es el mismo en Linux y en Windows para la misma secuencia de respuestas.
4. `StopRun` sobre una ejecución de otro cliente: solo detiene, nunca expone su salida.
5. En Windows, las opciones que no aplican dan `diag.err.opt_windows` con la clave, nunca se ignoran en silencio.
