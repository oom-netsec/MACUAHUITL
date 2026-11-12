# Laboratorio en el Catalyst 3560CX (IOS 15.2)

El equipo es el del dueño, en casa. Las reglas son:
- **Los `show` se pueden correr libremente.**
- **Escritura solo en puertos libres** (sin nada conectado), siempre con `--asistido` y confirmando cada paso.

Este documento es el orden de las pruebas. Lo que se espera de cada caso está en `laboratorio-bateria-de-pruebas.md`, secciones J, K, L y M, y en los hallazgos de laboratorio de la 16a.

Antes de la fase 2 hay que anotar aquí:
- los puertos libres elegidos: `Gi0/__`, `Gi0/__` y `Gi0/__`;
- la VLAN de pruebas: `__`.

## Fase 0 — Preparación (una vez)

En el switch, por consola:
```
ip domain-name lab.local
crypto key generate rsa modulus 2048
ip ssh version 2
username macua-admin privilege 15 secret <una contraseña>
username lab-rotar privilege 1 secret <otra contraseña>     ! usuario para probar la rotación
line vty 0 4
 login local
 transport input ssh
```

Con `username` hay dos usuarios:
- `macua-admin`: con él se conecta la app.
- `lab-rotar`: el que se rota. La regla es que nunca se rota el usuario con el que se está conectado.

Para la prueba de `configure replace` (fase 16c) hace falta además:
```
archive
 path flash:archivo
 maximum 5
```

En la app:
```sh
./dev.sh                                  # levanta núcleo y app
mctl vault create                         # si no existe
mctl vault unlock
mctl cred add --label lab-admin --user macua-admin
mctl cred add --label lab-rotar --user lab-rotar
```

## Fase 1 — Solo lectura: capturar salidas reales

Hay que correr estos comandos y guardar el CSV o Markdown:
```sh
mctl run -d IP_DEL_SWITCH --cred ID_LAB_ADMIN --md -f comandos-lab.txt > lab-3560cx-$(date +%F).md
```

`comandos-lab.txt`:
```
show version
show inventory
show clock detail
show vtp status
show vlan brief
show vlan id 1
show interfaces status
show interfaces Gi0/X switchport
show running-config interface Gi0/X
show interfaces Gi0/X
show interfaces trunk
show etherchannel summary
show spanning-tree detail
show cdp neighbors detail
show lldp neighbors detail
show ip interface brief
show ip route
show running-config | include ^username
show archive
show flash:
show processes cpu sorted
show processes memory sorted
show logging
show environment all
show startup-config
```

Con esas salidas:
- cada parser de `internal/parse/iosxe` se valida contra el equipo real, y las salidas pasan como fixtures marcadas «validado en 3560CX 15.2»;
- se cubren J2 (VTP), J4 (trunk), K1 (startup) y M (forense).

Después:
- **Respaldos (K1-K3):** `mctl backup run -d IP --cred ID --startup`, una vez con `--secrets` y otra sin él.
- **Deriva:** dos respaldos, con un cambio de `description` hecho a mano entre ambos, y `mctl backup diff`.
- **Terminal (K5-K9):** abrir la pestaña Terminal, hacer `enable`, `show running-config` y dejarla inactiva hasta el exec-timeout. Revisar la grabación en `outputs/terminal/`: ningún secreto en claro.

## Fase 2 — Escritura en puertos libres (modo asistido)

Cada prueba corre primero **sin** `--asistido`, para revisar el plan y su reversa, y después con `--asistido`. En cada caso se prueba también la reversa (`r`) y que el puerto queda exactamente como estaba (`show running-config interface`).

| # | Prueba | Comando | Qué valida |
|---|---|---|---|
| 1 | VLAN de acceso y descripción | `mctl ports set IP Gi0/X --vlan N --desc PRUEBA --cred ID --asistido` | Flujo completo, reversa y prompt de configuración del 3560CX |
| 2 | Volver a VLAN 1 | `ports set IP Gi0/X --vlan 1 ...` | Hallazgo 4 de la 16a: el post-check acepta que la línea no aparezca |
| 3 | VLAN inexistente | `ports set IP Gi0/X --vlan 3999 ...` | Hallazgo 5: se rechaza en el pre-check, sin crear la VLAN |
| 4 | Shut / no shut | `ports set IP Gi0/X --shut ...` y luego `--no-shut` | La reversa restaura el estado |
| 5 | Puerto trunk | Configurar a mano un puerto libre como trunk e intentar `ports set` | Se rechaza (no es de acceso) |
| 6 | VTP | `show vtp status`: si el switch es servidor (lo normal de fábrica), `snippet vlan` se rechaza sin `--accept-vtp` | J1, J2 y J15. Si conviene, `vtp mode transparent` a mano antes de probar |
| 7 | Crear VLAN | `mctl snippet vlan IP 3999 --name PRUEBA --cred ID --asistido` (con VTP transparente) | J1: la reversa la borra porque no existía |
| 8 | Trunk add/remove | En el puerto del caso 5: `snippet trunk IP Gi0/Y add 3999`, luego `remove 3999` | J4: nunca reemplaza la lista |
| 9 | SVI | `snippet svi IP 3999 192.0.2.1 255.255.255.0 --desc PRUEBA ...` | J6/J7: la SVI nace y se revierte. Usa una red de documentación (192.0.2.0/24) |
| 10 | Rotar credencial | `mctl cred rotate IP --user lab-rotar --cred ID_LAB_ADMIN --update-cred ID_LAB_ROTAR --asistido` | J8/J9: sesión nueva, `write memory` obligatorio, bóveda con la anterior conservada |
| 11 | Abort y Ctrl-C | Repetir el caso 1 y abortar a mitad | La ejecución termina `aborted` y avisa los equipos cambiados |
| 12 | Corte de sesión | Caso 1 con `exec-timeout 1` en la vty, esperar más de un minuto y pedir la reversa | Hallazgo 1 (crítico) de la 16a: reconecta y revierte |
| 13 | Restaurar por diff (16c) | Respaldo → cambiar a mano una descripción → `mctl restore diff IP RESPALDO --asistido` | L: solo aplica la diferencia |
| 14 | configure replace (16c) | Con `archive` configurado: `mctl restore replace IP RESPALDO --timer 5 --asistido` y probar sin confirmar | L: se revierte solo al vencer el timer |

## Al terminar

```
write memory     ! solo si quieres conservar la VLAN y los usuarios de prueba; si no, reload sin guardar
```

Las salidas y los resultados (pasa o falla, con su texto) se pegan en el chat o en `outputs/lab/`, para pasarlos a fixtures y corregir lo que falle.
