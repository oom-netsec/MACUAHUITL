# ADR 0011: `changeto` hecho por el ejecutor de Patrol (ASA multicontexto)

Fecha: 2026-11-16 · Estado: aceptado (decisión D1 de la fase 42)

## Contexto

En un ASA en `mode multiple` el espacio del sistema no tiene IP de gestión. Se llega por consola, o por SSH a un contexto
con IP (normalmente admin) y luego `changeto system`. Sin eso no pueden correr los playbooks del sistema (`sys-*`:
`show context`, `show resource usage`, `show running-config` del sistema, failover del sistema), y tampoco los de cada
contexto que no tenga IP propia.

Hoy `CheckDenied` niega `changeto` en todo playbook, y debe seguir así: un texto de playbook (o uno pegado a mano) no
puede mover la sesión a otro contexto.

## Decisión

El `changeto` lo manda **el ejecutor** (`internal/patrol`), nunca un texto de playbook.

- El destino del trabajo lleva equipo y contexto (`Target.Context`): vacío (la sesión se queda donde entra), `system`
  o el nombre de un contexto. Se valida como el dato de tipo `context` de los playbooks (`^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$`,
  ASCII anclado, igual que `interface`).
- Antes de los playbooks del destino el ejecutor llama a `platform.ContextSwitcher.ChangeTo`. El driver arma el comando
  solo con `system` o un nombre válido, manda `changeto system` o `changeto context X` y **verifica el prompt nuevo**
  con el parser por segmentos: mismo hostname y el contexto esperado, y nada entre el eco y el prompt salvo un syslog.
  Si no coincide, la sesión queda inservible, el destino falla y **no se guarda evidencia**.
- **Lista blanca:** un nombre de contexto solo se manda si aparece en el `show context` de **la misma ronda**. Ese
  comando solo existe en el sistema, así que el ejecutor pasa antes a `changeto system`. Un nombre ausente falla sin
  mandarse. Tras una reconexión dentro de la ronda se repite el procedimiento completo.
- **Auditoría:** cada `changeto` se registra como `patrol.changeto` (trabajo, ronda, contexto destino y origen) **antes**
  de mandarlo; si la auditoría no se puede escribir, no se manda.
- **Vuelta:** con `defer`, al terminar el bloque (con éxito, error, corte o fin de ventana) el ejecutor vuelve al contexto
  de entrada, o al sistema si se entró por ahí. Un fallo de esa vuelta cierra la sesión, que se va a cerrar de todos modos.
- **Evidencia:** la carpeta del equipo lleva el contexto (`host/ctx` en el nombre) y el resultado del equipo guarda el
  contexto en el manifest. El nombre estable (host y contexto, sin el rol pri/sec ni act/stby) evita que un failover
  parta la evidencia en carpetas distintas.
- `CheckDenied` sigue siendo una función pura y sigue negando `changeto`; hay prueba explícita.

## Qué no cambia

`changeto` solo mueve la sesión de CLI: **no escribe nada en el equipo** (no toca configuración ni estado de failover).
Dura lo que la sesión. El driver sigue sin entrar nunca a configuración (`(config…)#` da `ErrConfigPrompt`).

## Riesgos y controles

| Riesgo | Control |
|---|---|
| Guardar evidencia de un contexto equivocado (el peor caso) | Verificación del prompt tras cada `changeto`; el destino falla sin evidencia |
| Mandar `changeto` a un contexto inventado o con texto raro | Validación del nombre al armar y otra vez en el driver; lista blanca contra `show context` de la misma ronda |
| Que un playbook cambie de contexto | `CheckDenied` niega `changeto`; el nombre del contexto es un dato validado, no texto de comando |
| Sesión que queda en otro contexto | `defer` de vuelta; si la sesión ya no sirve, se cierra |
| Cambios sin rastro | Auditoría `patrol.changeto` antes de mandar; sin rastro no se manda |
| Un failover cambia el rol del prompt a mitad de corrida | El prompt se compara por segmentos estables; el rol se informa aparte |

Límite conocido: un contexto llamado `act`, `pri`, `control` o similar es ambiguo con el rol en el prompt.

## Alternativas descartadas

- **Consola por servidor de terminal.** La consola del sistema tiene el prompt del sistema, pero exige que el dueño tenga
  ese servidor y un transporte nuevo. Queda como opción si esta decisión se revierte.
- **Una corrida por IP de gestión de cada contexto.** Sirve para los playbooks por contexto, pero deja sin cubrir el
  espacio del sistema, que no tiene IP.

## Consecuencias

- Hace falta que el contexto de entrada permita `changeto system` (admin con privilegio).
- El dato `context` y `Target.Context` aún no viajan por proto, mctl ni la interfaz (bloque 42g).
- El parser de `show context` del ejecutor es mínimo; se cambia por `internal/parse/asa` cuando exista (42c).
