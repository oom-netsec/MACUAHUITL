# Fase 28d — Catálogo de snippets: lote L3 y Gestión

Esta fase sigue a 28b (#56) y reutiliza su infraestructura: `internal/assist/templates.go`, `Template`/`Field`/`ValidateValues`, el patrón de `l2port.go`, `DevicePlan.Notes` y la verificación de la reversa contra la línea base de `run.go`. No hay cambios de proto: las plantillas nuevas solo se registran en `Templates()`.

## Reglas globales
- Las mismas de 28b (ADR 0007, lista cerrada por plantilla, reversa capturada, rechazo de lo que la reversa no restauraría exactamente, fixtures de la documentación de Cisco marcadas "sin validar en laboratorio", TDD con mutación, parsers nuevos en `internal/parse/iosxe`).
- Todas son configuración global salvo `ip helper-address`. La línea base de cada una es la sección del running-config que toca, capturada en Pre:
  - `show running-config | include ^ip route `
  - `show running-config | section ^ntp`
  - `show running-config | include ^logging`
  - `show running-config | include ^snmp-server community`
  - `show running-config | section ^line vty`
  - `show running-config | section banner motd`
  - `show running-config interface X`
  
  Revisa que `run.go` (`runningCmds`) tome esos comandos como running y que el simulador los responda. Si `runningCmds` solo reconoce el prefijo `show running-config`, ya los cubre.
- Patrón «agregar»: si la línea exacta ya existe, el snippet no hace nada en ese equipo (nota «ya estaba»). Si existe una variante que la reversa no restauraría (p. ej. el mismo NTP con otras opciones), se rechaza. La reversa es el `no` exacto de lo agregado.
- Secretos (community SNMP y contraseñas SNMPv3): campos `secret`, en `DevicePlan.Secrets`, con `Scrub` en la `Function`. Ni el error, ni la auditoría, ni `Notes`, ni la salida los muestran. Compruébalo con una prueba por plantilla, como `TestResidueMasksSecrets`.

## Plantillas
| ID | Tech | Campos | Apply | Rechaza | Reversa / Expect |
|---|---|---|---|---|---|
| `ruta-estatica` | l3 | red ipv4, máscara ipv4_mask, siguiente salto ipv4 (o interfaz de salida), distancia int 1–255 opcional, nombre text opcional | `ip route R M NH [AD] [name N]` | otra ruta al mismo R/M con el mismo salto y otros atributos; ruta por defecto 0.0.0.0/0 (fuera de este lote) | `no ip route R M NH [AD]`; Expect: la línea en el running |
| `loopback` | l3 | número int 0–2147483647, IP ipv4, máscara ipv4_mask, descripción opcional | `interface LoopbackN` + `ip address` + `description` | loopback existente; IP repetida en `show ip interface brief` (igual que SVI) | `no interface LoopbackN` |
| `helper-address` | l3 | interfaz (SVI o ruteada), IP ipv4 | `interface X` + `ip helper-address IP` | interfaz inexistente o de capa 2 (switchport) | `no ip helper-address IP` |
| `ntp-server` | gestion | IP ipv4, prefer bool | `ntp server IP [prefer]` | el mismo servidor con otras opciones (key, source, version) | `no ntp server IP` |
| `logging-host` | gestion | IP ipv4, nivel choice (emergencies…debugging) opcional | `logging host IP` (y `logging trap NIVEL`) | — | `no logging host IP`; trap capturado o `no logging trap`. IOS 12.x muestra `logging IP`: el parser acepta las dos formas al capturar |
| `snmp-community` | gestion | community secret (1–32, sin espacios ni `@`), ACL text opcional | `snmp-server community C RO [ACL]` | community existente con cualquier permiso; una ACL que no existe (`show ip access-lists ACL`); RW nunca | `no snmp-server community C` |
| `snmpv3-usuario` | gestion | usuario text, grupo text, auth sha, contraseña auth secret (8–64), priv aes 128, contraseña priv secret (8–64) | `snmp-server group G v3 priv` si el grupo no existe, más `snmp-server user U G v3 auth sha A priv aes 128 P` | usuario existente (`show snmp user`); grupo existente con otro nivel de seguridad | `no snmp-server user U G v3` y `no snmp-server group G v3 priv` si se creó. IOS no muestra los usuarios en el running: Expect y verificación de la reversa con `show snmp user` (el usuario presente tras aplicar y ausente tras la reversa). Revisa que la verificación de la línea base lo cubra o agrega su Expect de reversa |
| `banner-motd` | gestion | texto text de una línea (1–200, ASCII sin el delimitador) | `banner motd ^C<texto>^C` en una línea, con el delimitador `^C` literal (dos caracteres) | banner actual de varias líneas (la reversa no lo restauraría) | banner capturado de una línea o `no banner motd` |
| `vty-acl` | seguridad | ACL text (estándar, numerada o nombrada), líneas choice `0 4` / `0 15` | `line vty A B` + `access-class ACL in` | ACL inexistente; **la ACL no permite la IP de origen de la sesión de la app** (con `internal/acl` sobre `show ip access-lists ACL`: si no hay un permit explícito para esa IP antes de un deny que la cubra, se rechaza: «te dejaría fuera»); bloques vty que ya tienen otro `access-class in` | `no access-class ACL in` en los mismos bloques; restaurar el capturado si lo había |

`vty-acl`: la IP de origen es la dirección local de la sesión SSH con el equipo. Busca cómo obtenerla en la capa de ejecución (`devExec`/transport). Si no se puede saber, se rechaza. Cuenta como un rechazo más: no inventes la IP.

## Pruebas mínimas
- Por plantilla: estado vacío (reversa = `no`); «ya estaba» (sin cambios); cada rechazo de la tabla; ida y vuelta con `roundTrip` que deja `residue == ""`.
- Secretos: no aparecen en el error de `ValidateValues`, en `Notes`, en la auditoría ni en la salida enmascarada.
- `vty-acl`: una ACL que permite la IP de origen se acepta; una que la niega o que no la menciona (deny implícito) se rechaza; una ACL inexistente se rechaza.
- Servicio: al menos tres plantillas de punta a punta contra el simulador hasta `rolled-back` (`ntp-server`, `snmp-community` y `vty-acl`).
- mctl: `snippet list` muestra las tecnologías nuevas; `help.golden` si cambia.
- Contrato: agrega a la sección 6 de `docs/plans/contratos-front.md` la lista de plantillas nuevas y la nota de que SNMPv3 se verifica con `show snmp user`.
