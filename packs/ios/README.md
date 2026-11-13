# oom/ios

## Español

Paquete oficial con los playbooks de diagnóstico de solo lectura para IOS clásico 12.2/15.x (Catalyst 2960, 3560,
3750, 3560-CX e ISR G2): capa 1, 2 y 3, plataforma, servicios, VPN y casos TAC. Son los de `oom/ios-xe` adaptados: sin
los comandos que solo existen en IOS-XE (`show platform software/hardware fed`, `bootflash:`, licencias inteligentes) y
con el equivalente clásico cuando existe (`show platform tcam utilization`, `show controllers cpu-interface`,
`show license detail`). Los comandos vienen de la documentación pública de Cisco y se validaron en un WS-C3560CX-12PC-S con IOS 15.2(7)E4
(2026-11-13); los que no existen en ese modelo (stack, SSO, MPLS, módulos, ambiente) llevan la nota «no existe en 3560CX».
Los scripts de biblioteca derivados llevan el prefijo `lib-ios-`, así que conviven con los de `oom/ios-xe`. Con los dos
paquetes instalados, un equipo detectado como IOS clásico corre el playbook de este paquete aunque se haya elegido el
de `oom/ios-xe` con el mismo nombre (y al revés en IOS-XE), así una ronda sobre una flota mixta usa en cada equipo sus
comandos. Los comandos de switch (`mls qos`, `sdm`, `power inline`, stack) darán inválido en un ISR.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-ios-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-ios-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with the read-only diagnostic playbooks for classic IOS 12.2/15.x (Catalyst 2960, 3560, 3750,
3560-CX and ISR G2): layers 1, 2 and 3, platform, services, VPN and TAC cases. They are the `oom/ios-xe` ones adapted:
without the commands that only exist on IOS-XE (`show platform software/hardware fed`, `bootflash:`, Smart Licensing)
and with the classic equivalent where one exists (`show platform tcam utilization`, `show controllers cpu-interface`,
`show license detail`). Commands come from Cisco's public documentation and were validated on a WS-C3560CX-12PC-S running IOS 15.2(7)E4
(2026-11-13); those that do not exist on that model (stack, SSO, MPLS, modules, environment) carry the note «no existe en 3560CX».
The derived library scripts use the `lib-ios-` prefix, so they coexist with those of `oom/ios-xe`. With both packages
installed, a device detected as classic IOS runs this package's playbook even if the `oom/ios-xe` one with the same
name was chosen (and the other way around on IOS-XE), so a round over a mixed fleet uses each device's own commands.
Switch commands (`mls qos`, `sdm`, `power inline`, stack) will be invalid on an ISR.

How to load it (the application never downloads packages):

1. Download `oom-ios-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-ios-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
