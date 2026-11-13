# oom/ios

## Español

Paquete oficial con los playbooks de diagnóstico de solo lectura para IOS clásico 12.2/15.x (Catalyst 2960, 3560,
3750, 3560-CX e ISR G2): capa 1, 2 y 3, plataforma, servicios, VPN y casos TAC. Son los de `oom/ios-xe` adaptados: sin
los comandos que solo existen en IOS-XE (`show platform software/hardware fed`, `bootflash:`, licencias inteligentes) y
con el equivalente clásico cuando existe (`show platform tcam utilization`, `show controllers cpu-interface`,
`show license detail`). Los comandos vienen de la documentación pública de Cisco y están sin validar en laboratorio.
Los scripts de biblioteca derivados llevan el prefijo `lib-ios-`, así que conviven con los de `oom/ios-xe`.

Cómo cargarlo (la aplicación nunca descarga paquetes):

1. Baja `oom-ios-<versión>.mpack` de los releases de GitHub y verifica su suma en `SHA256SUMS`.
2. Con la línea de comandos: `mctl pack install oom-ios-<versión>.mpack`. En la aplicación: Ajustes → Paquetes → Instalar.
3. Revisa con `mctl pack list` o en Ajustes → Paquetes.

## English

Official package with the read-only diagnostic playbooks for classic IOS 12.2/15.x (Catalyst 2960, 3560, 3750,
3560-CX and ISR G2): layers 1, 2 and 3, platform, services, VPN and TAC cases. They are the `oom/ios-xe` ones adapted:
without the commands that only exist on IOS-XE (`show platform software/hardware fed`, `bootflash:`, Smart Licensing)
and with the classic equivalent where one exists (`show platform tcam utilization`, `show controllers cpu-interface`,
`show license detail`). Commands come from Cisco's public documentation and are not yet validated in a lab.
The derived library scripts use the `lib-ios-` prefix, so they coexist with those of `oom/ios-xe`.

How to load it (the application never downloads packages):

1. Download `oom-ios-<version>.mpack` from the GitHub releases and check its sum in `SHA256SUMS`.
2. From the command line: `mctl pack install oom-ios-<version>.mpack`. In the app: Settings → Packages → Install.
3. Check with `mctl pack list` or in Settings → Packages.
