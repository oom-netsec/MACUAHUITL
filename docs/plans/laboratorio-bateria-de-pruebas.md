# Batería de pruebas de laboratorio

Borrador para la primera validación con equipos reales. Se ejecuta a mano con `mctl` y la UI, se registra el resultado de cada caso y se graban transcripciones para el simulador. Está pensada para una sesión de medio día con el laboratorio actual: dos access points, un equipo IOS-XE y un switch IOS.

## Objetivos

1. Confirmar que el driver IOS/IOS-XE habla con equipos reales igual que con el simulador: prompts, paginación, `enable`, comandos largos.
2. Demostrar las promesas de seguridad en condiciones reales: credenciales fuera del disco, solo los destinos escritos, llaves de host.
3. Medir tiempos reales (Login Test, `show tech-support`, rondas) para calibrar los timeouts por defecto.
4. Dejar grabadas transcripciones anonimizadas por plataforma para `test/transcripts`.

## Antes de empezar

| Paso | Cómo | Evidencia |
|---|---|---|
| Inventario | Hostname, modelo, versión, IP de gestión de cada equipo | Tabla al inicio del reporte |
| Cuenta de prueba | Usuario local en cada equipo, privilegio 15, `enable secret` propio. No usar cuentas reales de TACACS | — |
| Cuenta "mala" | Un segundo usuario con contraseña distinta a la que guardará la bóveda, para probar el rechazo | — |
| Instalación | `macuahuitld` como servicio de usuario (`deploy/systemd`), `mctl` y la UI compilados desde la rama bajo prueba | `macuahuitld --version` |
| Captura de red | `tcpdump -i <if> host <ip-equipo> -w sesion.pcap` corriendo en la laptop durante toda la sesión | Archivo pcap; sirve para la promesa de destinos |
| Reloj | NTP activo en la laptop y en los equipos | `show clock` vs `date` |

## Cómo registrar cada caso

Para cada caso: ID, fecha y hora, comando exacto, resultado (PASA / FALLA / PARCIAL), evidencia (ruta del output, línea de auditoría, captura de pantalla) y notas. Un caso FALLA abre un issue con el ID.

## A. Bóveda y credenciales

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| A1 | Crear bóveda | `mctl vault create` | Archivo `vault.mcv` con permisos 0600; `vault.create` en auditoría con parámetros Argon2id |
| A2 | Contraseña maestra incorrecta | `mctl vault unlock` con otra contraseña | Rechazo; `vault.unlock_failed` en auditoría; sin bloqueo de cuenta |
| A3 | Credencial sin rastro en disco | Guardar credencial con contraseña única (`LAB-MARKER-…`); `grep -r` del marcador, su base64 y su hex en `~/.local/share/macuahuitl`, `~/.local/state/macuahuitl`, `~/.config/macuahuitl` y la carpeta de outputs | Cero coincidencias |
| A4 | Cierre por inactividad | Dejar la bóveda abierta 16 minutos sin tocar la UI ni `mctl` | `mctl vault status` → cerrada; `vault.lock` con detalle `inactividad` |
| A5 | Bloqueo de pantalla | Abrir la bóveda y bloquear la sesión con `loginctl lock-session` | Bóveda cerrada; `vault.lock` con detalle `pantalla bloqueada` |
| A6 | Cambio de contraseña maestra | `mctl vault passwd`; intentar abrir con la vieja | Rechazo con la vieja; `vault.mcv.bak` tampoco abre con la vieja |

## B. Conexión y llaves de host

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| B1 | Primer uso | Login Test contra el switch IOS | Huella SHA256 mostrada; no conecta comandos hasta aceptarla |
| B2 | Aceptar y repetir | `job arm --accept <huella>`; repetir Login Test en otro trabajo | Conocida; sin volver a pedir confirmación |
| B3 | Llave cambiada | Regenerar la llave en el switch (`crypto key generate rsa`) y repetir Login Test | `host_key` cambiada; no se envía la contraseña (verificar en la captura de red que no hay fase de autenticación) |
| B4 | Casilla de aceptar cambiadas | Trabajo con `accept_changed_host_keys: true`, ronda nocturna con llave cambiada | Conecta; `hostkey.accepted_changed` con huella vieja y nueva en auditoría y en `manifest.json` |
| B5 | Contraseña rechazada | Credencial "mala" | `auth` falla; en la captura se ve **un solo** intento; `show aaa` o `show logging` del equipo muestra un solo fallo |
| B6 | Respaldo | Principal verificada al armar; cambiar la contraseña del equipo entre rondas; respaldo configurado con la nueva | Ronda usa el respaldo una vez; `auth.fallback` en auditoría |
| B7 | Equipo apagado | Apagar el AP a mitad de un trabajo | `tcp` falla con 3 reintentos (1, 2, 4 s) y luego `failed`; el resto de equipos sigue |
| B8 | Algoritmos heredados | Si algún equipo solo ofrece `diffie-hellman-group14-sha1`, perfil con `allow_legacy_algorithms` | Conecta; los algoritmos negociados quedan en auditoría |
| B9 | Destinos | Revisar `sesion.pcap` al final | Solo tráfico de la laptop hacia las IPs de los equipos (y DNS/NTP del sistema); nada más desde `macuahuitld` |

## C. Driver IOS/IOS-XE

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| C1 | Detección | Login Test en IOS-XE y en IOS | Plataforma `ios-xe` e `ios` respectivamente |
| C2 | Paginación | Equipo con `terminal length 0` deshabilitado por `exec-timeout`/`length 24` en la línea; correr `show running-config` | Salida completa sin `--More--` |
| C3 | Comando largo | `show tech-support` con timeout 600 s | Completo; medir duración real y anotarla |
| C4 | Comando inválido | Comando pegado con error de dedo | Marcado como inválido en el output y en `manifest.json`; la ronda sigue |
| C5 | Comando de cambio | Pegar `conf t` o `show run \| redirect flash:x` | Rechazado al crear el trabajo |
| C6 | Banner con `#` | Configurar un banner MOTD que termine en `#` | Login Test pasa (el hostname se toma del prompt, no del banner) |
| C7 | Sesiones concurrentes | Trabajo con los cuatro equipos y límite de 2 sesiones | Nunca más de 2 VTY en uso a la vez (`show users` en el equipo) |

## D. Patrol

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| D1 | Playbook base | `tac-baseline` contra el IOS-XE, 3 rondas cada 5 min, por ronda, zip al final | 3 archivos por equipo, `manifest.json` con SHA-256 correctos, zip con todo |
| D2 | Consolidado | Igual con `consolidado` y zip por ronda | Un archivo por equipo con 3 encabezados; un zip por ronda más el final |
| D3 | Enmascarado | Con y sin `disable_masking` sobre `show running-config` | Con enmascarado: ningún `enable secret`, comunidad SNMP ni llave visible; `mask_counts` en el manifest. Sin: aparecen, `masked: false` |
| D4 | Borrar sueltos | `delete_loose_files: true` | Solo quedan zips y manifest |
| D5 | Rondas omitidas | Ronda que tarde más que el intervalo (intervalo 1 min, `show tech`) | `round.skipped` en auditoría y en `skipped_rounds` del manifest |
| D6 | Cancelar | `job cancel` a mitad de una ronda | Estado `cancelled`; manifest escrito; bloqueos de suspensión soltados |
| D7 | Ventana máxima | `window_hours: 97` | Rechazado al crear |
| D8 | Reinicio del núcleo | `systemctl --user restart macuahuitld` con un trabajo armado | El trabajo se pierde (límite conocido); manifest y auditoría de lo corrido quedan intactos |

## E. Suspensión y energía

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| E1 | Bloqueos tomados | Armar un trabajo; `systemd-inhibit --list` | Cuatro bloqueos `block` de MACUAHUITL: sleep, idle, handle-lid-switch, shutdown |
| E2 | Cerrar la tapa | Con el trabajo armado, cerrar la tapa 2 minutos | La laptop no se suspende; la ronda corre; solo se atenúa la pantalla |
| E3 | Suspensión forzada | `systemctl suspend` con el trabajo armado | Antes de dormir: `power.sleep`, bóveda cerrada, trabajo en pausa. Al despertar y abrir la bóveda: `job.resume`; rondas perdidas como omitidas |
| E4 | Fin del trabajo | Esperar la última ronda | Bloqueos soltados (`systemd-inhibit --list` vacío); `power.release`; DEK fuera de memoria (`mctl vault status` sin ventanas) |
| E5 | Sin logind | Correr el núcleo en una sesión sin D-Bus de sistema | Armar avisa `missing_inhibitors` y continúa |

## F. Auditoría

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| F1 | Integridad | `mctl audit verify` al final del día | Cadena íntegra |
| F2 | Alteración | Copiar la base, editar un `detail` con `sqlite3` (tras borrar el trigger), verificar | Rota en el registro editado |
| F3 | Ancla | Comparar `audit_head` de cada manifest con la exportación | Coincide con el hash del registro `job.finish` correspondiente |
| F4 | Sin secretos | `grep` del marcador de A3 en `mctl audit export` | Cero coincidencias |

## G. Diagnóstico

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| G1 | Ping / traceroute | A cada equipo desde la UI y `mctl` | Salida en vivo; archivo en `outputs/diag`; `diag.run` con argv en auditoría |
| G2 | nmap | Escaneo `connect` de puertos 22,80,443 al switch | Resultado coherente con `show ip interface brief` y servicios activos |
| G3 | iperf3 | Servidor en otra máquina del laboratorio; cliente 10 s | Resultado; sin tráfico a otros destinos |
| G4 | PCAP | Captura de 30 s con filtro `host <ip-switch>` durante una ronda de Patrol | Archivo `.pcapng` legible en Wireshark; solo SSH hacia el switch |
| G5 | Cancelar | Cancelar un ping de 100 paquetes a los 3 s | Proceso terminado (`pgrep ping` vacío); `diag.done` con código distinto de 0 |
| G6 | Inyección | Destino `-iL /etc/passwd`; filtro `tcp; cat /etc/passwd` | Rechazado antes de ejecutar; el filtro va como un solo argumento |

## H. ACLs contra equipos reales

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| H1 | Importar | `show run \| section access-list` del IOS-XE → `mctl acl analyze --vendor ios-xe` | Importa completa o falla con número de línea claro |
| H2 | Ida y vuelta | Generar para `ios-xe` y pegarla en un equipo de prueba con otro nombre; comparar `show access-lists` | Mismas reglas; sin errores de sintaxis |
| H3 | NX-OS / ASA | Generar para `nx-os` y `asa` y validar sintaxis en un equipo virtual si hay | Sin `% Invalid` |

## I. UI

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| I1 | Núcleo caído | Abrir la UI con el servicio detenido; luego arrancarlo | Aviso "Núcleo desconectado" y recuperación sola |
| I2 | Trabajo completo | D1 desde la UI | Grilla en vivo por equipo; estado `closed` con la ruta del paquete |
| I3 | Reabrir | Cerrar la UI con un trabajo armado y reabrir | Grilla reconstruida con el estado de la ronda |
| I4 | Exclusión | Un equipo apagado en el Login Test; excluirlo | Arma con los demás |

## J. Modo asistido: snippets y rotación de credenciales (fase 16b, frente C)

Todo con un equipo de laboratorio y confirmando paso a paso. Las salidas del simulador son de la documentación de Cisco; esto es lo que nadie ha visto en un IOS real.

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| J1 | VLAN nueva | `mctl snippet vlan EQ 30 --name Prueba --cred ID --asistido` en un equipo VTP transparente | `vlan 30` / `name Prueba` y `end` crean la VLAN (sin `exit` ni `apply` previos); `show vlan brief` la muestra `active`; la reversa `no vlan 30` la borra |
| J2 | VTP | `show vtp status` en servidor, cliente, transparente, apagado y VTP v3 | `ParseVTP` lee modo y dominio de las cuatro salidas; servidor/cliente con dominio se rechaza sin `--accept-vtp` |
| J3 | Renombrar | Renombrar una VLAN existente y revertir | La reversa restaura el nombre (también si era el de omisión `VLANnnnn`); nunca borra |
| J4 | Trunk add/remove | Lista `all` (sin línea), lista corta, lista larga con `add` en varias líneas | `TrunkAllowedSet` coincide con `show interfaces trunk`; tras `remove` desde `all` el running-config muestra la lista sin la VLAN y la reversa `add` la vuelve a incluir (¿vuelve a no mostrar línea?) |
| J5 | Trunk en Port-channel | `snippet trunk EQ Port-channel1 add 30` | Se acepta la interfaz; un miembro del canal se rechaza |
| J6 | SVI nueva | `snippet svi EQ 99 10.9.9.1 255.255.255.0 --desc X` | `show running-config interface Vlan99` de una SVI inexistente da `% Invalid input...` (el plan lo exige); la SVI nace sin `shutdown`; la reversa `no interface Vlan99` la borra |
| J7 | SVI existente sin IP | Una SVI con descripción y `shutdown`, sin IP | La reversa deja descripción y estado como estaban y `no ip address` |
| J8 | Rotación | `mctl cred rotate EQ --user tech --cred ADMIN --update-cred TECH --asistido` | `username tech privilege 15 algorithm-type scrypt secret ...` se acepta; el running-config muestra `secret 9`; `privilege` se conserva; `secret 9 <hash>` restaura el acceso con la contraseña anterior |
| J9 | Algoritmos | Usuarios con tipo 5, 8 y 9 en IOS-XE 16/17 y en IOS clásico | El tipo resultante coincide con el decidido en Pre; IOS clásico sin `algorithm-type` acepta `secret S` |
| J10 | Rechazos | Usuario con `password 7`, `nopassword`, `view`, `autocommand` o dos líneas | `password`/`nopassword`/duplicado se rechazan; con `view` o `autocommand` la reversa debe dejarlos intactos (ver si `username U ... secret` los conserva) |
| J11 | Sesión nueva que no entra | Usuario que autentica por TACACS/RADIUS aunque exista el local | La verificación falla, la bóveda no cambia y la reversa por la sesión original deja el hash anterior |
| J12 | Sin secretos | `mctl audit export` y la salida de la UI/CLI tras J8 y J11 | Cero coincidencias del secreto nuevo y del hash previo (usar el marcador de A3) |
| J13 | Bloqueo de cuenta | Rotar en un equipo con `login block-for` / TACACS | Una sola contraseña por sesión nueva (el transporte no reintenta); ningún bloqueo |
| J14 | Atributos de usuario que se rechazan | Usuarios con `view`, `autocommand` y `algorithm-type` en la línea (`show running-config \| include ^username`) | La rotación se rechaza antes de tocar el equipo. Validar en IOS real qué atributos imprime el running-config y si `username U ... secret` los conserva, para poder aceptar alguno de ellos más adelante |
| J15 | VTP v3 | `show vtp status` en primario, secundario, cliente y transparente con VTP v3 | El modo de `Feature VLAN:` manda (no el de MST ni UNKNOWN); `Primary Server`, `Secondary Server` y `Client` se rechazan sin `--accept-vtp`; ¿el secundario imprime `Secondary Server`? |
| J16 | SVI con `ip unnumbered` | Una SVI con `ip unnumbered` (y otra con IP secundaria o IPv6) | `snippet svi` se rechaza: la reversa `no ip address` la dejaría sin dirección |

## K. Respaldos y terminal SSH (fase 16b)

El simulador no responde `show startup-config` (lo trata como inválido) ni reproduce el comportamiento de IOS con paginación o prompts distintos de `Password:`. Estos casos se validan con un equipo real o virtual.

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| K1 | Respaldo con startup | `mctl backup run -d EQUIPO --cred ID --startup` | Dos archivos 0600 en `outputs/respaldos/<equipo>/`; sin aviso de startup inválido |
| K2 | Respaldo grande | Un running-config de varios cientos de KB | Se guarda completo (sin `--More--`); el diff contra el anterior solo marca lo cambiado |
| K3 | Secretos enmascarados | Respaldo con y sin `--secrets` | Con máscara, `mctl backup list` marca «enmascarado»; sin ella, el archivo trae los hashes y comunidades en claro |
| K4 | Programado | `--every 5m --rounds 3` | Tres respaldos sin intervención; el núcleo sigue guardando con la UI cerrada |
| K5 | Prompts de contraseña | En la terminal: `enable`, `Old password:` (`username X password`), `Enter secret:` en `enable secret` interactivo | La grabación trae `>>> [oculto]` y nada de lo tecleado |
| K6 | Prompt con otra palabra | TACACS que pide `Token:` o `Passcode:` | `Passcode:` se oculta; `Token:` no (límite conocido: ampliar `secretPrompt` en `internal/terminal`) |
| K7 | Corte del equipo | Reiniciar el equipo con la terminal abierta | La pestaña queda «cerrada», `terminal.close` en la bitácora con `guard=revocado` |
| K8 | exec-timeout | Dejar la sesión inactiva hasta el exec-timeout | Igual que J7 |
| K9 | Paginación | `show running-config` en la terminal | Aparece `--More--`; el botón Espacio avanza; `terminal length 0` lo evita |

## L. Restaurar configuraciones (fase 16c)

Equipo de laboratorio: Catalyst 3560CX con IOS clásico 15.2(x)E, no IOS-XE; repetir lo que se pueda en IOS-XE. El simulador modela el running-config con sus propias suposiciones (`test/simulator/running.go`); esto es lo que nadie ha visto en un IOS real. `restore-diff` solo aplica una **lista cerrada** (ver la nota de la fase): globales `hostname`, `logging host|buffered|trap|facility|source-interface`, `ntp server`, `snmp-server location|contact`, `ip domain-name`, `ip name-server` (uno por línea), `clock timezone|summer-time`, `service timestamps debug|log`, `spanning-tree portfast default`, `errdisable recovery cause|interval`, nombre de VLAN; y en un puerto físico de acceso `description`, `switchport access|voice vlan`, `shutdown`, `spanning-tree portfast|bpduguard`, `storm-control broadcast|multicast|unicast|action`. `spanning-tree mode` y `extend system-id` se rechazan (reconvergen todo el árbol). Siempre con un respaldo sin enmascarar tomado con `mctl backup run --secrets` (con la bóveda abierta, para que la ficha salga firmada) y confirmando paso a paso.

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| L1 | Línea de un solo valor | Respaldo con `switchport access vlan 30` (VLAN que existe en `show vlan brief`) y `description X` distintos a los del equipo; `mctl restore diff EQ RESPALDO --cred ID --asistido` | Solo se mandan `description X` y `switchport access vlan 30` (sin `no` previo); el running los muestra y `show interfaces status` no pasa por la VLAN 1 |
| L2 | `no` de una línea con valor | Respaldo sin `description` ni `switchport access vlan` que el equipo sí tiene | `no description TEXTO` y `no switchport access vlan N` se aceptan con el argumento y devuelven el valor por omisión (VLAN 1) |
| L3 | Globales: agregar y luego quitar | Respaldo que cambia `ntp server IP1` por `ntp server IP2`, quita un `logging host` y cambia `snmp-server location` | Orden `ntp server IP2`, `no ntp server IP1`, `no logging host ...` (primero se agrega, luego se quita); `snmp-server location` se manda solo con el valor nuevo. Tras la reversa el running queda igual al capturado |
| L4 | `no X` que IOS imprime | `no service timestamps debug`, `no logging console`: respaldo que los agrega o los quita | Con `no X` agregado el running muestra `no X` y no `X` (el post-check lo exige); con `no X` quitado, la línea `no X` desaparece. Anotar cuáles `no` imprime el 15.2E y cuáles son el valor por omisión (el post-check de sección completa fallaría con uno que no se imprime) |
| L5 | `shutdown` y `no shutdown` | Respaldo que apaga un puerto y cambia su VLAN, y otro que enciende un puerto y cambia su descripción | `shutdown` va primero en su interfaz y `no shutdown` al final; el enlace no sube con la VLAN vieja |
| L6 | Rechazos | Respaldos con diferencias en rutas (`ip route`, `ipv6 route`, por omisión partida, en VRF), `router bgp ... remote-as`, ACL (nombrada y `access-list N`), `route-map`, `vrf forwarding`, `no switchport`, `switchport trunk`, `channel-group`, `ip access-group` de una SVI, `access-class` de la vty, `standby ... authentication`, `username`, `enable secret`, `aaa`, `crypto`, `banner`, `snmp-server community`, `tacacs-server key` | El plan se rechaza entero con cada línea listada y sin ningún secreto (comunidad, hash, llave) en el plan, los eventos ni la bitácora; con `--parcial` solo se aplica lo permitido y nada que nombre una VLAN, interfaz o ACL rechazada |
| L7 | Volátiles del running | Dos `show running-config` seguidos con NTP sincronizado y tras un cambio | `ntp clock-period` y los comentarios `! Last configuration change` no hacen caducar el plan, la línea base ni el post-check de sección completa (si salen otros, ampliar `normalize` en `internal/assist/run.go` y `volatile` en `restore.go`) |
| L8 | Gestión por la sesión real | Con 1 y con 2 sesiones SSH abiertas desde el mismo origen: `show users` y `show tcp brief`; conectarse a la IP de una SVI, de una Gi0/0 en VRF `Mgmt-vrf`, de una Loopback y a través de NAT | **Decisión**: el origen es el `Location` de la línea marcada con `*` de `show users`; la IP local son las conexiones `ESTAB` de `show tcp brief` cuyo extremo remoto es ese origen (formato `IP.puerto`, igual en 15.2E e IOS-XE; **sin validar**). Si hay una IP local única y la lleva una sola interfaz, esa es la de gestión; si no (NAT, VRF que `show tcp brief` no muestra: probar `show tcp brief vrf all` en IOS-XE, loopback, dos IP locales) el plan se rechaza y `--mgmt-if` la fija. Una SVI de gestión protege también su VLAN |
| L9 | Uplink con la VLAN de gestión | Puerto de acceso o trunk del uplink por donde pasa la gestión; respaldo que cambia su `description`, `shutdown` o VLAN | Todo trunk, canal y puerto que lleve la VLAN de gestión (también el que no imprime `switchport access vlan`, que está en la VLAN 1) se rechaza. Confirmar que el 15.2E imprime `switchport mode access` en los puertos de acceso (sin esa línea el puerto se rechaza) |
| L10 | Firma, serie y respaldo completo | Respaldo anterior a la firma; ficha editada; respaldo de otro equipo con el mismo hostname; respaldo cortado | Sin firma válida, con otra serie o sin `end` se rechaza antes de tocar nada (el de otro equipo, tras `show version`). Verificar que `Processor board ID` es la serie del equipo (en 3560CX) y qué imprime en pilas y en IOS-XE (¿conviene `show inventory`?). `show startup-config` trae `Using N out of M bytes`: el plan lo ignora |
| L11 | Avisos `%` en configuración | `spanning-tree portfast` en un puerto de acceso; un `no` que borra una interfaz o un neighbor | `%Warning: portfast ...` y `%Portfast has been configured...` son informativos (no detienen; quedan en la bitácora). `% Interface X removed` y `% Specify remote-as ...` detienen la ejecución. Anotar otros `%` que el 15.2E imprima al aplicar estas líneas |
| L12 | Secciones sin cuerpo | Una `interface` o `vlan` sin líneas hijas en el running (solo el encabezado) | Se trata como sección, no como línea suelta; un respaldo que le agrega hijas se rechaza si es una interfaz sin `switchport mode access` |
| L13 | Running grande | Un running-config de cientos de KB | El pre-check (running, version, users, tcp, vlan) completa en menos del tope de 60 s por comando y sin `--More--`; el diff, la línea base y el hash de sección no hacen lento el plan |
| L14 | Cambio ajeno | Alguien edita el equipo entre planear y confirmar, y entre `apply` y la reversa | El pre-check y la comprobación previa a la reversa detienen la ejecución ("cambió desde que se hizo el plan" / "pisaría un cambio ajeno") sin mandar nada |
| L15 | Respaldo de startup | Restaurar un respaldo `-startup` | Se rechaza antes de conectar («solo se restaura un respaldo de running-config»): el diff es contra el running. Con uno de running, el equipo no se guarda sin `--write-memory` y su confirmación |
| L16 | Reversa tras un fallo a medias | Hacer que una línea del plan falle en el equipo (`% Invalid input`) | La ejecución se detiene, ofrece la reversa y el running queda como el capturado en Pre |
| L17 | `configure replace` (pendiente de implementar) | En el 3560CX 15.2(x)E: `configure replace flash:x.cfg list revert trigger error timer 5`, `configure confirm`, `verify /md5 flash:x.cfg HASH`, `archive` / `path flash:`, `ip scp server enable`, `copy tftp:` con `Destination filename?` | Confirmar que la sintaxis existe en IOS clásico 15.2E (no suponerla): `list`, `revert trigger error`, `timer N`, `configure confirm`, `verify /md5`; qué pide cuando no hay `archive`; el espacio en flash; si hay un replace pendiente y cómo se ve; los avisos interactivos (`[confirm]`, `[no]:`) que el driver debe responder |
| L18 | Gestión en un switch con `ip routing` | 3560CX con `ip routing`, uplink de acceso `Gi1/0/48` en la VLAN 10 (con SVI `Vlan10`) y la sesión entrando por `Loopback0` o por la IP de `Vlan99`; **validar además con la sesión entrando por un puerto de acceso** (el 3560CX de laboratorio suele atenderse así). Leer a mano `show ip cef IP-ORIGEN` y `show ip route IP-ORIGEN`; respaldo que cambia `shutdown` y `switchport access vlan 20` en `Gi1/0/48` | **Decisión**: Pre lee `show ip cef <origen>` y, si no da interfaz, `show ip route <origen>` (siempre que se conozca el origen, aunque el running no tenga `ip routing`: un router lo trae activo y no lo imprime; con `no ip routing` no se lee); se protegen la interfaz de salida, la que lleva la IP local y, si la de salida es una SVI, su VLAN en todos los puertos de acceso. Confirmar el formato que imprime el 15.2E y el IOS-XE (`nexthop IP Vlan10`, `attached to Vlan99`, `via IP, Vlan10, 0 dependencies`, `* IP, from ..., via Vlan10`; **los parsers de `internal/parse/iosxe/egress.go` usan fixtures de la documentación, sin validar**) y qué imprimen con ECMP, con `% IPv4 CEF not enabled`, `% Network not in table`, un salto recursivo (`* IP` sin `via`) y Null0. Probar también en un router (ISR/ASR) y en un switch con el enrutamiento apagado: confirmar qué contesta `show ip route IP` (`Default gateway is X` con la tabla de caché de redirects, o `IP routing not enabled`; **fixtures de `ios152_show-ip-route-l2` y `-norouting`, sin validar**) y que `show ip cef IP` no falla ni cuelga. Una tabla de rutas = enruta; esas respuestas = sin enrutamiento (gestión por la IP local); si no se sabe, el plan se rechaza y pide `--mgmt-if`. Sin certeza de la salida con enrutamiento también; con `--mgmt-if` en un puerto físico se protegen además la VLAN 1 implícita y su VLAN de voz |
| L19 | Un solo valor frente a varias líneas | Sustituir `clock summer-time CDT recurring` por `... CST recurring`, `service timestamps log datetime msec` por `... localtime`, `errdisable recovery interval 300` por `600`, `ip domain name` (IOS-XE) por `ip domain-name`, un `name` de VLAN; agregar `storm-control action trap` con `shutdown` ya puesta; `ip name-server A B` en una línea | Cada sustitución manda solo la línea nueva y el running queda con ella (si IOS borra el valor nuevo con un `no` posterior, esta clasificación de `restore_rules.go` está mal). `storm-control action shutdown` y `trap` coexisten. `ip name-server A B` se imprime en una sola línea y se rechaza. Anotar para cada comando de la lista si `no X valor` quita el comando entero (se supone que sí) |
| L20 | Formas `no` que IOS conserva | `no logging buffered`, `logging buffered 8192` y quitarlo; `no logging trap`; `no service timestamps log datetime msec` | **Decisión**: `no logging buffered` deja la línea `no logging buffered` en el running y apaga el buffer; `no logging buffered N` no se manda. Para `logging buffered`, `logging trap` y `service timestamps debug|log`, quitar o agregar la línea sin sustituto (no hay manera de revertirla con certeza) se rechaza; solo se acepta pasar de un valor a otro. Confirmar en el 15.2E qué imprime cada `no` y si hay más comandos de la lista con ese comportamiento |
| L21 | Gestión en una VRF | Interfaz de gestión (`Vlan99` o un puerto L3) con `vrf forwarding Mgmt` (IOS-XE) y con `ip vrf forwarding Mgmt` (15.2E), la sesión entrando por su IP y un uplink de acceso en otra VLAN; leer a mano `show ip cef vrf Mgmt IP-ORIGEN` y `show ip route vrf Mgmt IP-ORIGEN`, y la misma consulta sin `vrf` | **Decisión**: si la única interfaz que lleva la IP local está en una VRF, Pre pide `show ip cef vrf X <origen>` y `show ip route vrf X <origen>` (la tabla global no se consulta: puede dar otra salida). Una respuesta de «Default gateway» o «IP routing not enabled» no vale en una VRF. Sin respuesta utilizable, o con un nombre de VRF que no sea una palabra simple, el plan se rechaza y pide `--mgmt-if`. Confirmar que ambos comandos existen en 15.2E e IOS-XE con esa sintaxis y qué imprimen (**fixtures sin validar**: se usan las mismas de `show ip cef`/`show ip route`) |
| L22 | Origen IPv6 | Sesión SSH desde una dirección IPv6 hacia una SVI con `ipv6 address`; leer `show users`, `show tcp brief`, `show ipv6 cef IP6-ORIGEN` y `show ipv6 route IP6-ORIGEN`; repetir con `no ip routing` (con `ipv6 unicast-routing`) y con una VRF | **Decisión**: con origen IPv6 Pre pide `show ipv6 cef <origen>` y `show ipv6 route <origen>` (también con `no ip routing`, que solo apaga IPv4); `ParseEgress` lee `nexthop FE80::1 Vlan10`, `attached to Vlan99` y, bajo `Routing paths:`, `FE80::1, Vlan10` y `directly connected, Vlan99`; un salto sin interfaz o `% ...` = sin certeza y se pide `--mgmt-if`. Una respuesta de switch L2 de IPv4 no vale para IPv6. Confirmar el formato real (**fixtures `ios15_show-ipv6-*`, sin validar**), cómo imprime `show tcp brief` las direcciones IPv6 (`2001:DB8::1.22`) y que `show users` imprime la dirección sin corchetes |
| L23 | Varias SVI y subred del origen | Switch L2 con dos SVI (`Vlan10` con la IP de la sesión y `Vlan99` en la subred del origen) y un puerto de acceso en la VLAN 99; lo mismo en L3. Cambiar `description` o `shutdown` en ese puerto | **Decisión**: además de la interfaz de la IP local y la de salida, se protege toda interfaz con `ip address A M` (o `ipv6 address P/L`) cuya subred contenga al origen, con su VLAN en todos los puertos de acceso. Confirmar por qué interfaz responde realmente el equipo (`show ip arp`, captura) y qué pasa con `ip address dhcp` o direcciones secundarias, que hoy no se consideran si no se conoce la máscara |
| L24 | `ntp server` con `prefer` | Equipo con `ntp server 10.0.0.1`; aplicar `ntp server 10.0.0.1 prefer`, luego `ntp server 10.0.0.1`; `no ntp server 10.0.0.1 prefer`; agregar `key`, `source` y `version` | **Decisión**: IOS guarda una sola línea por dirección de `ntp server`, así que la línea nueva con la misma dirección reemplaza a la anterior sin `no`, y un `no ntp server X` posterior borraría la asociación (el equipo se queda sin NTP). El plan manda solo la línea nueva, en los dos sentidos, y quita con `no` solo las direcciones que no están en el respaldo. Confirmar que `ntp server X prefer` sobre `ntp server X` reemplaza y no duplica, que `no ntp server X` quita la línea aunque tenga `prefer`, y qué hacen `logging host` e `ip name-server` con la misma dirección (la lista cerrada solo admite la forma simple, así que no hay variantes) |

## M. Forense de logs y fallas (fase 17)

Todo es de solo lectura. Las fixtures (`internal/crashinfo/testdata`, `internal/logintel/testdata`, `internal/parse/iosxe/testdata/sw3560cx_*`) se escribieron a partir de la documentación pública de Cisco con el estilo del Catalyst 3560CX con IOS 15.2(7)E: nadie las ha comparado con un equipo real. Los `debug` se ejecutan **a mano** en la consola del equipo (la app no los lanza); apágalos con `undebug all`.

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| M1 | Marcas de `show logging` | `service timestamps log datetime msec` y `show logging` tras un flap | Formato `*Mar  1 00:00:20.575: %LINK-3-UPDOWN: ...` (con y sin número de secuencia y año); `mctl logs patterns` lo lee sin líneas omitidas más allá de la cabecera. Anotar si el 3560CX imprime zona (`UTC`) |
| M2 | Flap real | Desconectar y conectar un cable 3 veces en menos de 60 s; `show logging` y `mctl logs flaps` | Un `%LINK-3-UPDOWN` y un `%LINEPROTO-5-UPDOWN` por transición; el detector cuenta una sola capa por interfaz y marca `[FLAPPING]` con las transiciones en milisegundos |
| M3 | Contadores de `show interfaces` | `show interfaces GigabitEthernet0/N` antes y después de M2 | `interface resets`, `lost carrier` y `no carrier` suben; **¿imprime el 3560CX la línea `carrier transitions`?** (el parser solo la lee si existe). Con un trabajo de Patrol de 2 rondas, `mctl logs flaps --job` muestra el salto |
| M4 | BPDU Guard | PortFast + BPDU Guard y conectar un switch | `%SPANTREE-2-BLOCK_BPDUGUARD` y `%PM-4-ERR_DISABLE` con el texto de la ficha de `mctl msg`; los comandos `show errdisable detect` y `show interfaces status err-disabled` existen |
| M5 | Fichas: comandos de verificación | Ejecutar, uno por uno, los `verify` de `mctl msg %SYS-2-MALLOCFAIL`, `%PM-4-*`, `%ILPOWER-*`, `%PLATFORM-*`, `%STORM_CONTROL-3-SHUTDOWN`, `%UDLD-4-UDLD_PORT_DISABLED`, `%PORT_SECURITY-2-PSECURE_VIOLATION`, `%SEC_LOGIN-4-LOGIN_FAILED`, `%AUTHMGR-5-FAIL` | Anotar los que el 15.2 del 3560CX rechaza con `% Invalid input`. Dudosos: `show platform resources`, `show memory failures alloc`, `show environment all` (¿`show env all`?), `show interfaces transceiver detail` (necesita SFP), `show archive log config all` (necesita `archive`), `show login failures` (necesita `login on-failure`), `show reload`, `show authentication sessions` |
| M6 | `show processes memory sorted` | Comando en el equipo y en 3 rondas de Patrol separadas 10 min | Columnas `PID TTY Allocated Freed Holding Getbufs Retbufs Process`; el orden por `Holding`; nombres con espacios; `ParseProcessMemory` lee las filas. Anotar si aparece `show processes memory platform` y si la salida del 3560CX trae otros pools (`I/O Pool`) antes de la tabla |
| M7 | Fuga conocida | Con el equipo en reposo: ¿algún proceso sube de forma monótona 3 rondas seguidas sin carga? | `mctl logs leaks` no marca falsos positivos con el umbral por defecto (3 rondas, 1 MiB); ajustar el umbral si el 3560CX rebasa 1 MiB por ruido |
| M8 | Crashinfo | `dir flash:` y `dir crashinfo:`; si hay archivo, `more` o copiarlo por TFTP a la app y correr `mctl crashinfo ARCHIVO` | Anotar el nombre real del archivo (`crashinfo_AAAAMMDD-HHMMSS`), la ubicación (¿`flash:/crashinfo`?) y las líneas reales de motivo (`System returned to ROM by`), `-Traceback=`, `-Process=` y uptime; sin crashinfo real, provocar uno solo si el dueño lo autoriza. Los volcados binarios (`*.core`, `system-report`) solo se identifican |
| M9 | `show version` tras una caída | `show version` después de una recarga por falla | `Last reload reason` / `System returned to ROM by` coincide con lo que lee el analizador |
| M10 | Syslog en vivo | `mctl syslog listen` con `logging host IP transport udp port 5514` en el equipo y guardando la salida; luego `mctl logs patterns --capture` y la casilla «En vivo» de la pestaña Forense | Los mensajes del equipo llegan con `<PRI>` y número de secuencia; la captura se agrupa por patrón; ráfagas e inestabilidad aparecen tras repetir M2 |
| M11 | Debugs | A mano: `debug ip ospf adj` (u otro) con `terminal monitor`, copiar la salida a un archivo y `mctl logs debugs ARCHIVO --hide ...` | Las marcas de los debug (`*Mar  1 00:05:12.345:`) se separan del texto; los hellos repetidos forman un patrón; las líneas raras se marcan; anotar el ruido típico del 3560CX |
| M12 | Línea de tiempo con fichas | `mctl timeline` de un trabajo con `show logging` | Los eventos con mnemónico conocido llevan `[%XXX: significado Acción: ...]` |

## N. Transferencias: servidores y clientes (fase 22a)

Equipo de laboratorio: Catalyst 3560CX con IOS clásico 15.2(x)E; repetir en IOS-XE lo que se pueda. Toda la sintaxis de IOS de esta sección se escribió de la documentación de Cisco y **no está validada**: cada caso confirma o corrige lo que `fileserve.ServerHint` (`internal/diag/fileserve/hints.go`) le dice al usuario. La laptop tiene la IP `L` (la que se pasa a `--listen`); los servidores escuchan en puerto alto y el equipo llega al estándar con la redirección que muestra la app (`sudo nft ... redirect to :PUERTO`, que ejecuta el usuario; la regla es estrecha, `ip daddr L`, en una tabla propia de cada servidor, p. ej. `macuahuitl_tftp_6969`; quitarla al terminar con el comando que la app muestra al cerrar, `sudo nft delete table ip macuahuitl_tftp_6969`). Capturar con `tcpdump -i IF host IP-EQUIPO -w transferencias.pcap` toda la sección. Carpetas: `~/lab/enviar` (con una imagen, `r1.cfg`, un subdirectorio, un enlace simbólico y una FIFO) y `~/lab/recibidos`.

**Servidores (el equipo copia desde y hacia la laptop)**

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| N1 | TFTP lectura | `mctl transfer serve --proto tftp --listen L --from ~/lab/enviar --allow IP-EQUIPO`; redirección del 69; en el equipo `copy tftp://L/r1.cfg flash:` y `verify /md5 flash:r1.cfg` | Copia completa; el MD5 del equipo coincide con el de `mctl transfer get`/`md5sum`. La salida de `serve` muestra la transferencia con ruta y bytes. Anotar si IOS pide `Destination filename` y qué `blksize`/`tsize` manda (pcap) |
| N2 | TFTP escritura | `mctl transfer serve --proto tftp --listen L --write --dir ~/lab/recibidos --allow IP-EQUIPO`; en el equipo `copy running-config tftp://L/r1-config.txt` | El archivo cae en `~/lab/recibidos/r1-config.txt` con 0600 y el SHA-256 de la salida de `serve` coincide con `sha256sum`. Confirmar que IOS 15.2 manda WRQ con `tsize` (y si no, que el servidor acepta igual) |
| N3 | TFTP: nunca sobrescribe y nombre con ruta | Repetir N2 con el mismo nombre; luego `copy running-config tftp://L/a/b/../../c.txt` | El segundo intento falla en el equipo (`Error code 6` / `File already exists`) y el archivo no cambia; el de la ruta cae como `c.txt` dentro de la carpeta, sin subcarpetas |
| N4 | TFTP crashinfo | `copy flash:crashinfo_... tftp://L/crashinfo` (provocar uno si hace falta) | Llega íntegro; `mctl crashinfo` puede leerlo. Si es mayor que `--max-file`, el equipo recibe el error 3 y no queda un archivo a medias |
| N5 | TFTP: solo lectura y solo escritura | Servidor con solo `--from`: `copy running-config tftp://L/x`; servidor con solo `--write`: `copy tftp://L/r1.cfg flash:` | Cada uno rechaza lo apagado con un error TFTP (`access violation`); aparece como rechazo en `serve` |
| N6 | FTP pasivo | `mctl transfer serve --proto ftp --listen L --from ~/lab/enviar --write --dir ~/lab/recibidos`; en el equipo `conf t`, `ip ftp username U`, `ip ftp password P` (los que muestra `serve`), `ip ftp passive`; `copy ftp://L/r1.cfg flash:` y `copy running-config ftp://L/r1-config.txt` | Ambas copias funcionan. Con el pcap anotar **qué órdenes manda IOS 15.2** (USER, PASS, TYPE I, PASV/EPSV, SIZE, CWD, LIST...) y si alguna cae en `502`/`550` del servidor; si IOS exige `LIST` o `CWD` a otra ruta, anotar cuál. Redirección del 21: confirmar si la URL `ftp://U:P@L:2121/` se acepta en 15.2 |
| N7 | FTP activo rechazado | Quitar `ip ftp passive` y repetir `copy ftp://...` | El servidor contesta `502` a `PORT`; la copia falla con un mensaje claro y el servidor no abre ninguna conexión hacia el equipo |
| N8 | FTP: puertos pasivos acotados | `--pasv-ports 50000-50031`; varias copias seguidas | En el pcap, todas las conexiones de datos van a puertos de ese rango; con la conexión de datos desde otra IP (otra laptop) el servidor la cierra |
| N9 | SCP lectura | `mctl transfer serve --proto scp --listen L --from ~/lab/enviar`; redirección del 22; `ip scp server enable` no hace falta (el equipo es cliente); en el equipo `copy scp://U@L/r1.cfg flash:` (contraseña de `serve`) | Pide la contraseña, copia. Anotar el **algoritmo negociado** (kex, cifrado, MAC, llave de host) en el pcap o en `show ssh`; por omisión el servidor ofrece solo algoritmos modernos y un 15.2 debe **fallar**; con `--legacy-ssh` (solo `aes128-cbc`, `3des-cbc`, `diffie-hellman-group14-sha1`, `hmac-sha1` y la llave `ssh-rsa`) debe funcionar. Anotar cuál de esos hizo falta; si basta con menos, la lista se acota. La huella que muestra `serve` debe coincidir con la que ve el equipo (`show ip ssh`/aviso de llave) |
| N10 | SCP escritura | `serve --proto scp --write --dir ~/lab/recibidos`; `copy running-config scp://U@L/r1-config.txt` | El archivo cae en la carpeta con 0600 y su hash en la bitácora. Anotar qué manda IOS: `scp -t` con qué ruta, si manda líneas `T` |
| N11 | SCP: puerto en la URL | Servidor con `--legacy-ssh` (lo antiguo está apagado por omisión) y sin redirección: `copy scp://U@L:2222/r1.cfg flash:` | **Pregunta abierta**: ¿IOS 15.2 permite indicar el puerto en la URL de scp? La documentación no lo lista; si falla, la redirección del 22 es la única vía y así se queda en la ayuda. Anotar el resultado y la versión exacta, y si negoció con `--legacy-ssh` o no hizo falta (en ese caso la compatibilidad antigua sobra para esa versión) |
| N12 | SFTP | `serve --proto sftp ...` y en el equipo `copy sftp://U@L/r1.cfg flash:` | **Pregunta abierta**: ¿existe el cliente `sftp:` en 15.2(x)E? (en IOS-XE 16+ sí). Si existe, igual que N9/N10; si no, anotarlo y dejar la ayuda diciendo que se use scp. Desde la laptop, `sftp -P PUERTO U@L` (cliente de OpenSSH): lista solo los archivos publicados, no deja borrar, renombrar ni crear carpetas |
| N13 | HTTP | `serve --proto http --listen L --from ~/lab/enviar`; `copy http://L:8080/r1.cfg flash:` (y `ip http client source-interface` si hace falta) | Funciona con el puerto en la URL. Anotar si IOS manda `Range` al reintentar |
| N14 | Lista de origen | Servidor con `--allow IP-EQUIPO`; intentar desde otra IP (laptop o segundo equipo) en cada protocolo | La otra IP no obtiene respuesta (TFTP/FTP/SSH/HTTP 403) y queda como rechazo; sin `--allow` y con `--write --any` el servidor se niega a abrir; **TFTP con `--write` sin `--allow` también se niega** (en UDP la IP de origen se falsifica: la lista es un filtro, no autentica; desde una laptop con IP falsificada en la misma red confirmar que escribe, por eso solo en red de confianza) |
| N15 | Lo que no se sirve | En `~/lab/enviar`: subcarpeta con archivo, enlace simbólico a `/etc/hostname`, FIFO; `copy tftp://L/sub/x`, `.../enlace`, `.../tuberia`, `.../../etc/passwd` | Todo se rechaza como «archivo no publicado»; nada se queda colgado por la FIFO. En `scp`/`sftp`/`ftp` igual (`LIST`/`dir` solo muestran regulares) |
| N16 | Carpetas rechazadas | `--dir /etc`, `--from /usr/share`, `--dir ~/.ssh`, `--dir $HOME`, `--dir ~/.config/autostart`, `--dir ~/.local/bin`, `--dir ~/bin`, un enlace simbólico a una carpeta normal, una carpeta inexistente | Todas se rechazan antes de abrir el puerto, con el motivo; ninguna abre un servidor |
| N17 | Leer y recibir en la misma carpeta | Una sola carpeta para `--from` y `--dir`; subir un archivo grande desde el equipo y pedirlo con otro `copy` a mitad | El archivo no se sirve hasta que termina de escribirse; después sí |
| N18 | Duración, parada y bitácora | `--duration 2m`, luego `mctl transfer stop ID` en otro; `mctl audit export` | El servidor cierra solo a los 2 min o al `stop`; la bitácora tiene `transfer.serve.open` (con carpetas y reglas), cada `transfer.serve.transfer` (ruta, bytes, SHA-256) y `transfer.serve.close`; **ninguna contraseña** ni llave privada en ella |

**Clientes (la laptop copia desde y hacia el equipo)**

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| N19 | SCP desde el equipo | En el equipo `ip scp server enable` y una cuenta de privilegio 15 (AAA local); `mctl transfer get scp://U@IP-EQUIPO/flash:/c3560cx.bin --cred ID --dir ~/lab/recibidos --legacy-ssh` | Sin `--accept-host-key` falla mostrando la huella; con ella baja el archivo; el MD5 coincide con `verify /md5` del equipo. Anotar la ruta que acepta IOS (`flash:/x`, `flash:x`) y los algoritmos antiguos que hicieron falta (`--legacy-ssh` queda en la bitácora) |
| N20 | SCP hacia el equipo | `mctl transfer put scp://U@IP-EQUIPO/flash:/x.cfg x.cfg --from ~/lab/enviar --cred ID --legacy-ssh` | El archivo aparece en `dir flash:`; si ya existe, anotar si IOS lo sobrescribe (eso es del equipo) |
| N21 | TFTP, cliente | En el equipo `tftp-server flash:r1.cfg` (si 15.2E lo permite); `mctl transfer get tftp://IP-EQUIPO/r1.cfg` y `mctl transfer put tftp://IP-EQUIPO/x ...` | Baja con `blksize`/`tsize` o sin ellos (anotar si IOS los negocia); no se queda colgado ante un servidor que calla (el tiempo máximo corta) |
| N22 | FTP y HTTP(S), cliente | Servidor FTP del equipo si existe (`ip ftp`), o la laptop; `ip http server` / `ip http secure-server` en el equipo; `mctl transfer get http://IP-EQUIPO/...` y `https://...` | `https` con el certificado autofirmado del equipo falla sin `--insecure` y funciona con él; la bitácora marca `insecure=true`. Un `404` no deja archivos |
| N23 | Hash esperado | `mctl transfer get ... --sha256 H` con el valor bueno y con uno cambiado; `--sha512` con el publicado por Cisco | Con el bueno `verificado: ok`; con el malo el comando falla y no queda archivo en la carpeta |
| N24 | Destino | Descargar dos veces al mismo destino; a un enlace simbólico; a `/etc`; con `--max-bytes` menor que el archivo | La segunda no sobrescribe; enlace y `/etc` se rechazan; el tope corta y no deja archivo parcial |
| N25 | Salida solo a lo escrito | Con el pcap abierto, `get` a un nombre de host; `get http://` con redirección a otra IP | El pcap solo muestra tráfico hacia la IP escrita (y la redirección a otra IP se niega con `egress.denied` en la bitácora); tras cada trabajo, `Revoke` (`guard=revocado`) |
| N26 | Contraseña fuera de lugar | `mctl transfer get ftp://U:P@IP/x` y revisar la bitácora, `ps` y el historial | La URL con contraseña se rechaza («usa una credencial de la bóveda»); en ninguna parte aparece una contraseña |

**Revisión de seguridad de la fase** (se repite después de cualquier cambio en `fileserve`)

| ID | Caso | Pasos | Esperado |
|---|---|---|---|
| N27 | Subida SFTP cortada | `sftp -P PUERTO U@L`, `put` de un archivo de 100 MB y cortar la conexión a la mitad (`kill -9` del cliente) | La transferencia queda como `error` en la bitácora y el archivo parcial **se borra** de la carpeta de recepción; no queda como «ok». Igual al detener el servidor a mitad de la subida |
| N28 | Detener FTP en plena copia | `copy running-config ftp://...` grande o `STOR` de un archivo grande y `mctl transfer stop ID` a mitad | `serve` vuelve en menos de 1 s, el parcial se borra y la bitácora lo registra como fallido (no espera el tiempo de inactividad de 30 s) |
| N29 | Nombres y caracteres | `copy running-config tftp://L/.bash_profile`, `.../" inicio"`, y un nombre con U+202E o espacios de ancho cero (con `tftp` de la laptop) | Todos se rechazan; nada con punto inicial, con espacios en los extremos, con caracteres de formato invisibles ni UTF-8 inválido llega a la carpeta |
| N30 | Plazo para autenticarse | `nc L PUERTO` en FTP y SSH, mandando bytes o `NOOP` cada pocos segundos sin autenticar | A los ~30 s el servidor cierra la conexión aunque haya actividad (no se renueva con cada byte) |
| N31 | Algoritmos SSH | `ssh -o KexAlgorithms=diffie-hellman-group14-sha1 -o Ciphers=aes128-cbc -p PUERTO U@L` contra un servidor con y sin `--legacy-ssh`; `nmap --script ssh2-enum-algos -p PUERTO L` | Sin la opción no negocia nada antiguo ni `hmac-sha1` ni `ssh-rsa`; con ella aparecen exactamente `aes128-cbc`, `3des-cbc`, `diffie-hellman-group14-sha1`, `hmac-sha1` y `ssh-rsa`; nunca group1, RC4 ni `hmac-sha1-96` |
| N32 | Regla de nftables | Aplicar la regla que muestra la app para un servidor TFTP; luego cerrarlo | La regla trae `ip daddr L` y vive en `macuahuitl_tftp_PUERTO` (otro servidor tiene su propia tabla); al cerrar, el evento y la vista muestran el comando exacto para quitarla y `sudo nft list ruleset` queda limpio al ejecutarlo |
| N33 | Puertos pasivos y FTP en claro | `--pasv-ports 80-90`, `--pasv-ports 1023-2000` y luego `50000-50031`; revisar el pcap de una copia FTP | Los dos primeros se rechazan antes de abrir; la credencial de FTP viaja en claro en el pcap (por eso el aviso y el `no ip ftp password` al terminar) |
| N34 | Redirecciones HTTP | `mctl transfer get https://...` contra un servidor que redirige a `http://` | Se rechaza (no se baja de https a http) y la bitácora no guarda la query string de la URL pedida |

## Transcripciones para el simulador

1. Correr el playbook `tac-baseline` contra cada plataforma con `disable_masking: true` en una carpeta aparte.
2. Por cada comando, copiar la salida a `test/transcripts/<plataforma>/<comando_con_guiones>.txt` con la primera línea `# command: <comando exacto>`.
3. Anonimizar antes de commitear: hostnames, IPs (usar 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), números de serie, MACs y todo secreto. Sustituir los secretos por los marcadores `MARKER-*` que esperan las pruebas de enmascarado.
4. Guardar también la secuencia cruda del login (`enable`, `Password:`, `--More--`) de al menos un equipo, para afinar el driver.

## Criterio de salida

La sesión se considera exitosa si todos los casos de A, B, D5, E1–E4 y F pasan. Cualquier FALLA en B5, B9, D3 o F4 bloquea el release, porque toca una promesa de seguridad.
