# Fase 31 — Hallazgos de la prueba de punta a punta en el 3560CX

La prueba de punta a punta del 2026-11-12 en el 3560CX (IOS 15.2(7)E4, plataforma detectada `ios`) dejó cuatro defectos del núcleo. Se suma una decisión del dueño sobre FTP. Esta fase los corrige todos.

## Reglas
- TDD: la prueba falla primero. Toda lógica nueva lleva al menos una mutación a mano.
- Nada de dependencias nuevas.
- Mientras trabajas, solo corren las pruebas del paquete tocado. La suite completa la corre quien coordina.
- En las listas compartidas (`i18n/{es,en}.ts` y `contratos-front.md`) se agrega al final.

## 1. GetRun manda el puerto efectivo
`patrolSvc.GetRun` (`internal/core/services.go`) devuelve `Target.Port` tal como viene en la spec, que trae 0 cuando el puerto es el de omisión. Por eso la UI muestra `192.168.3.2:0`.
- Devuelve el puerto efectivo, con la misma regla que `patrolHostport` (0 → 22). No dupliques la regla: extrae una función de puerto efectivo y úsala en los dos lados.
- Revisa con grep si otras respuestas del núcleo mandan `Target`/`Port` desde la spec, por ejemplo `GetJob` o eventos de equipo, y aplica lo mismo.
- Prueba: un trabajo con puerto 0 devuelve 22 en GetRun, y uno con puerto 2222 devuelve 2222.

## 2. El Login Test del armado tiene su propia fase
`ArmJob` vuelve a correr el Login Test, sin interacción, justo antes de armar. Eso es a propósito: verifica las credenciales en el momento de armar. Pero registra la misma fase `JOB_PHASE_KIND_LOGIN_TEST_DONE` que el Login Test manual, y el Job muestra «Login Test completed» dos veces.
- `patrol.proto`: agrega `JOB_PHASE_KIND_ARM_CHECK_DONE = 11;` al final del enum, sin renumerar. Su comentario: el Login Test que repite el armado.
- `ArmJob` usa la fase nueva. El Login Test manual sigue con `LOGIN_TEST_DONE`.
- `buf lint` y `buf generate`; `gen/` se sube.
- UI:
  - `patrol.phase.ARM_CHECK_DONE` al final de `lib/i18n/es.ts` («Login Test al armar») y de `en.ts` («Login Test at arming»);
  - la clave en `phaseKeys` de `modules/patrol/JobDetail.tsx`;
  - revisa el `fake.ts` de patrol por si arma fases.
- Prueba del núcleo: un trabajo con Login Test manual y armado tiene `LOGIN_TEST_DONE` una vez y `ARM_CHECK_DONE` una vez. Prueba de la UI: la etiqueta nueva se ve.
- Contrato: una línea en `docs/plans/contratos-front.md`, sección nueva al final.

## 3. La carpeta de salida de un trabajo se valida como la de Ajustes
Un Job acepta `output_dir` bajo `/tmp`, pero Ajustes → Almacenamiento (fase 29e, `internal/service/prefs/outputs.go`) lo prohíbe. Hoy el Job solo comprueba que se pueda escribir (`writable` en `internal/patrol/job.go:123`).
- Un `output_dir` explícito pasa por la MISMA validación que la carpeta de salida de Ajustes:
  - ruta absoluta y sin `..`;
  - existe, es un directorio del usuario y se puede escribir;
  - modo 0700;
  - ningún ancestro con escritura para todos;
  - no es `/`, `$HOME`, `/tmp`, la carpeta de datos ni la de config.
- Vacío sigue siendo la carpeta de salida vigente.
- No dupliques las reglas. Mueve la validación a un lugar que puedan importar `prefs` y `patrol`, o quien valide la spec, sin romper el ADR 0008: corre `archcheck`. Las pruebas de 29e siguen verdes sin cambiar sus aserciones.
- El mensaje y el código de error se quedan como en 29e (`prefs.outputs.<motivo>`), con el campo `output_dir`.
- Busca con grep los demás RPC que aceptan una carpeta del cliente (por ejemplo `output_dir` de `internal/service/diag/diag.go:45`) y aplícales la misma validación. Anota en el PR cuáles tocaste.
- Pruebas: `/tmp/x` se rechaza; una carpeta 0755 se rechaza con el `chmod 700` sugerido; una carpeta 0700 propia se acepta; vacío usa la vigente. Revisa los fixtures de pruebas existentes que hoy pasan `t.TempDir()` como `output_dir`: `t.TempDir()` cae bajo `/tmp`, con modo 0700 y dentro de `/tmp`, así que la regla «no `/tmp`» solo debe prohibir `/tmp` mismo, no lo que esté dentro. Confirma qué hace hoy 29e (la regla es «no ser `/tmp`»: igualdad tras resolver enlaces, no prefijo) y conserva ese comportamiento.

## 4. Los playbooks de IOS-XE sirven para IOS clásico
Al ejecutar, el núcleo ya usa los playbooks `ios-xe` en un equipo `ios` (`compatible` en `internal/patrol/job.go`). Faltan dos cosas:
- **Listado.** `ListPlaybooks` con `platform: ios` sale vacío. Debe devolver los de `ios-xe`, con la misma regla `compatible` sin duplicarla: expórtala de `patrol` o muévela a `internal/playbook`. Prueba: `mctl playbooks --platform ios` lista los de `ios-xe`.
- **Comandos que no existen en IOS clásico.** En el 3560CX, `ios-xe/flota` falla en `dir bootflash:`. El YAML gana un campo opcional por comando, `platforms: [ios-xe]`: el comando solo corre si la plataforma detectada está en la lista; si no, se omite y queda anotado en el manifest como omitido por plataforma. Vacío = corre en todas las compatibles.
  - Marca `dir bootflash:` como `platforms: [ios-xe]` en los 4 playbooks que lo usan: `upgrade-check`, `plat-flash-fs`, `flota` y `plat-reloads-crashinfo`.
  - No marques otros comandos sin evidencia.
  - Si el campo trae una plataforma desconocida, `Load` falla con el nombre del archivo.
  - Revisa también qué pasa hoy cuando un comando es inválido en el equipo: si un solo comando inválido marca el equipo entero como fallido, anótalo en el PR, pero no lo cambies en esta fase.
- **No crees playbooks `ios/*` nuevos.** El dueño está decidiendo si habrá paquetes cargables de playbooks por tecnología.
- Pruebas: carga del campo, con su caso válido y el inválido; un trabajo en un equipo `ios` del simulador omite `dir bootflash:` y lo anota; en `ios-xe` lo corre; el catálogo real (`playbooks/catalog_test.go`) sigue cargando.

## 5. FTP: una ruta que empieza con `/` es absoluta
Decisión del dueño del 2026-11-12: en el cliente de transferencias (área `transfer`), una ruta remota FTP que empieza con `/` es absoluta, igual que en SCP y SFTP. Sin `/` es relativa a la carpeta de inicio de la sesión.
- Revisa cómo la trata hoy el cliente FTP (`internal/diag/...` o donde viva). Si ya es así, deja solo la prueba que lo fija. Si no, corrígelo.
- Pruebas: con el servidor FTP de prueba, `/x/y` es absoluta, `x/y` es relativa y la descarga y el listado se comportan igual que en SFTP.

## Contrato
Sección nueva al final de `docs/plans/contratos-front.md`: la fase `ARM_CHECK_DONE`, el puerto efectivo en GetRun, la validación de `output_dir` y el campo `platforms` (incluida la nota de omitido en el manifest).
