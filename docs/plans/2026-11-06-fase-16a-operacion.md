# Fase 16a, frente B: herramientas de operación de solo lectura

Fecha: 2026-11-06 · Rama: `fase-16a-operacion` · Spec: ADR 0008 y `docs/roadmap.md` (fase 16, puntos 1, 2 y 7).

Las tres herramientas son de solo lectura: ninguna envía configuración a un equipo. Cada una es un módulo
vertical del ADR 0008 (dominio, servicio, proto, mctl, puente y vista) y se registra con una línea en
`internal/core/modules.go`, `cmd/mctl/main.go`, `tools/archcheck/domains.go`, `App.tsx`, `main.tsx`,
`core.ts` y `fake.ts`.

## Ejecutor ad-hoc en lote (`internal/adhoc`)
- `mctl run -d EQUIPO[:PUERTO]... (-c COMANDO... | -f ARCHIVO) --cred ID [--accept HUELLA] [--exclude EQUIPO] [--csv|--md|--json] [--timeout 10m]`.
- Los comandos pasan por `playbook.Ephemeral`, que usa `playbook.CheckDenied`: un solo comando que no sea de lectura
  rechaza el lote entero antes de crear nada (`adhoc.denied` en la bitácora). Máximo 50 comandos.
- Corre como un trabajo de Patrol de una ronda (`StartAdhoc` crea y arma; `AdhocResult` lee la carpeta con
  `capture.ReadDir`). Bóveda, Login Test, guard y auditoría son los de Patrol. Si el armado falla (llave de host nueva),
  el trabajo queda creado y la respuesta trae el motivo; se repite con `--accept`.
- Resultado por equipo (texto), tabla consolidada, CSV y Markdown. Un comando sin salida queda como fila "sin salida"
  con su nota, nunca se omite. El CSV neutraliza celdas que empiezan con `= + - @` (la salida es de un equipo).
- UI: pestaña Lotes (`modules/adhoc`).

## Deriva (`internal/drift`)
- `mctl drift TRABAJO|CARPETA [--round N] [--device EQUIPO] [--json]`.
- Compara el `show running-config` de la ronda N con la anterior que lo tenga, por equipo (`drift.Pair`), línea por
  línea con su sección (`iosconf`). Ignora `ntp clock-period`, `! Last configuration change`,
  `! NVRAM config last updated` y `Current configuration : N bytes`, y los lista como "ignoradas" en el informe.
- Decisión: no reutiliza `analyze.Diff` (fase 9). Ese diff es por contadores y vecinos, y un dominio no importa a otro
  (ADR 0008); el servicio sí lee la carpeta con `analyze.Load`.
- Atajo conocido: un cambio solo de orden entre líneas (ACL sin secuencia) no se reporta.
- UI: pestaña Deriva (`modules/drift`).

## Limpiador (`internal/cleaner`)
- `mctl config clean ARCHIVO [-o SALIDA] [--sort] [--json]`. Sin `-o` solo muestra el informe; con `-o` escribe
  (0600) y se niega a sobrescribir el archivo de entrada.
- Quita líneas vacías y `!` repetidos, recorta espacios finales. No toca cuerpos de banner ni macro. Cada cambio
  sale en el informe con su línea de origen.
- `--sort`: grupos contiguos de `interface`, `vlan`, `ip route` y `username`, en orden natural (Gi1/0/2 antes de
  Gi1/0/10). Las ACL numeradas y todo lo que depende del orden no se tocan.
- Huérfanas, solo marcadas con `! HUERFANA: ...` encima de la línea, nunca borradas: `ip access-group`/`access-class`/
  `ipv6 traffic-filter` sin ACL, `route-map X` usado sin definición, `class` o `match class-map` sin `class-map`,
  `service-policy` sin `policy-map`, y `class-map` sin uso.
- UI: pestaña Limpiador (`modules/cleaner`).

## Pruebas y mutaciones
- Dominios con pruebas propias; servicios contra el núcleo real (`internal/core/{adhoc,drift,cleaner}_test.go`,
  el ad-hoc contra `test/simulator`); mctl, puente y vistas con sus pruebas.
- Mutaciones a mano, todas detectadas: sin neutralizar fórmulas del CSV; sin `CheckDenied` en el lote;
  `ntp clock-period` o `Current configuration` fuera de lo volátil; conteo de líneas repetidas; ruta de sección;
  sin protección de banner; sin marcar huérfanas; `!` repetido; ordenar ACL; orden no natural; `class-default`;
  referencias sin definición; class-map sin uso. Dos sobrevivieron al principio y se cerraron con prueba
  (línea repetida en deriva, `class-default` en el limpiador).
- Fixtures de la documentación pública de Cisco, marcadas "sin validar en laboratorio".

## Correcciones de la revisión independiente
- `CheckDenied` rechaza todo lo que no sea ASCII imprimible (0x20-0x7e): con `exec-character-bits 7` el equipo quita el
  bit alto y `Í` llegaba como `C`+CR. También rechaza el tabulador. Tras cualquier pipe, `r`, `t` y `a` cuentan como
  redirect, tee y append (antes pasaban `| r flash:x` después del primer pipe). Una regex con `|a` o `|t` en `include` se rechaza: costo aceptado.
- Ad-hoc: una carpeta `outputs/adhoc/lote-*` por lote (dos lotes en el mismo segundo compartían manifest y zip); `cmds` se
  libera al entregar; si el cierre del trabajo falla, `AdhocResult` devuelve `done` con `error` (campo nuevo del proto);
  la vista deja de consultar a los 15 min y muestra el error. CSV neutraliza `= + - @ \t \r` en todas las celdas;
  Markdown escapa `& < >`, `|` y comillas invertidas en todos los campos.
- `mctl config clean -o`: `O_EXCL` y 0600; no sigue enlaces simbólicos ni duros ni pisa archivos existentes.
- Deriva: avisa en CLI y vista si el manifest dice `masked` (los cambios en secretos no se ven; el enmascarado no cambia),
  copia los avisos del paquete al informe y reconoce las abreviaturas de `show running-config` (`sh run`, `show running`,
  `sh ru`...). Solo sin argumentos: `all`, `full` y cualquier `| filtro` no cuentan. Atajo: el manifest se lee suelto, no desde un zip.
- Limpiador: protege también `refuse-message`, `vacant-message` y `menu ... title/text/prompt` (en `iosconf` también) y
  no recorta el espacio final de la línea que abre un banner.

## Pendiente
- `mctl drift` no devuelve código distinto de cero cuando hay deriva (útil para cron).
- El limpiador no ordena bloques con dependencia de orden; la lista de bloques ordenables es corta a propósito.
- Las salidas no se han comparado con equipos reales.
