# Fase 29d — Respaldo cifrado de la bóveda

Pedido del dueño (vía la sesión de front): exportar la bóveda a un archivo cifrado con una frase DISTINTA a la maestra, e importarlo después, con confirmación explícita, auditoría y conflictos por etiqueta. Nunca forma parte de exports generales.

## Diseño (decidido)
- **El respaldo ES un archivo de bóveda nuevo.** Tiene el mismo formato que `internal/vault` (cabecera, Argon2id y cifrado autenticado), pero con su propio VaultID, su propia sal y una clave de datos (DEK) NUEVA, sellada con la frase del respaldo.
  - Se crea con `vault.Create(ruta, frase, params)`. Luego cada credencial no reservada de la bóveda viva se lee (`List` + `Get`) y se escribe en el respaldo con `Put`.
  - No se reutiliza la DEK de la bóveda viva: una frase débil en el respaldo no compromete la bóveda viva. Tampoco se copia el archivo tal cual.
- **No hay criptografía nueva.** Todo pasa por las funciones existentes de `internal/vault`. Si hace falta, se agrega a `internal/vault` lo mínimo, por ejemplo una función `Backup(dst, frase, params)` o un indicador «es respaldo» en la cabecera. No escribas primitivas propias.
- **Parámetros.** Argon2id con, como mínimo, los mismos parámetros que la bóveda viva y nunca por debajo del mínimo de `vault` (`ErrWeakParams`).
- **Frase del respaldo.**
  - Mínimo 12 caracteres.
  - Debe ser distinta de la maestra. Se rechaza si es igual: compara intentando `Unlock` de la bóveda viva con esa frase sin cambiar su estado, o con la verificación que ya exista. No guardes ni registres la frase.
  - Las frases viajan por la petición y se borran de memoria al terminar (`secret`/`Wipe`, como en el resto del núcleo).
- **Confirmación explícita.** El RPC de export exige `confirm: true`. Sin ella devuelve FailedPrecondition con el motivo («el respaldo contiene todas tus credenciales…»).
- **Endurecimiento tras la revisión de seguridad.**
  - Exportar exige la bóveda abierta ANTES de evaluar la frase: cerrada, una frase igual y una distinta dan el mismo error, así no sirve de oráculo de la maestra. `Matches` deriva el Argon2 fuera del lock de la bóveda.
  - Al abrir un respaldo: máximo 10 000 credenciales (antes de descifrar ninguna) y los mismos topes de parámetros (1 GiB, 8 hilos) que al escribirlo.
  - El destino no puede estar en la carpeta de datos del núcleo (bóveda, `.bak`, base): se comparan rutas resueltas, con enlaces.
  - Dos «reemplazar» hacia la misma credencial local son una decisión mala (el token se conserva).
  - Sistema de archivos sin permisos (vfat): si `chmod 0600` falla con EPERM o «no soportado», el export sigue y la respuesta avisa; cualquier otro error falla. Solo el respaldo es tolerante, la bóveda viva no.
- **Archivo.**
  - 0600, sin seguir symlinks, sin sobrescribir salvo `overwrite`, con escritura atómica (temporal + rename). Usa el helper compartido de export si encaja.
  - Extensión sugerida: `.mcvault`.
  - Si la bóveda está cerrada, FailedPrecondition.
- **Import en 2 pasos** (como scripts y hosts):
  - `PreviewVaultImport(ruta, frase)`:
    - abre el archivo y verifica que sea un respaldo o bóveda válida; si no, el error dice claramente «no es un respaldo de bóveda de MACUAHUITL»;
    - lo desbloquea con la frase; si es incorrecta, el error lo dice, sin distinguir más;
    - lista por credencial `{etiqueta, usuario, estado}`, donde estado es `nueva`, `igual` (misma etiqueta y mismo contenido), `conflicto_etiqueta` o `reservada` (se omite);
    - devuelve un token de un solo uso de 10 min, sacado bajo lock.
  - El estado de la vista previa guarda las credenciales descifradas en memoria protegida. Se borran al aplicar, al vencer el token o al cerrarse la bóveda.
  - `ApplyVaultImport(token, decisiones)` aplica por etiqueta: renombrar (`<etiqueta> (importada)`), reemplazar u omitir. Es todo o nada.
  - Si la bóveda viva está cerrada al aplicar, FailedPrecondition. Cerrar la bóveda descarta la vista previa por seguridad (lo descifrado se borra, por cualquier vía de cierre), así que el token no sobrevive: la UI avisa que se descartó y pide abrir la bóveda y el archivo de nuevo.
- **Auditoría.** `vault.respaldo.exportar` (ruta y conteo) y `vault.respaldo.importar` (ruta, conteos y decisiones por etiqueta). NUNCA secretos, usuarios ni la frase.
- **Fuera de alcance.** No hay plantilla; los exports generales nunca incluyen la bóveda.

## Proto, mctl, puente y contrato
- `VaultService` gana `ExportBackup(path, passphrase, overwrite, confirm)`, `PreviewBackupImport(path, passphrase)` y `ApplyBackupImport(token, decisions)`, sin renumerar.
- mctl: `mctl cred backup export|import`. Las frases se leen sin eco por la terminal y nunca como argumento. `--yes` cuenta como confirmación. Con su `help.golden`.
- Puente y TS en el módulo de la bóveda (`api.ts`/`fake.ts`). Contrato: sección nueva al final de `docs/plans/contratos-front.md`.

## Pruebas mínimas
- Ida y vuelta: 3 credenciales normales más 1 reservada → el respaldo trae 3; importarlas en una bóveda vacía da las 3 iguales.
- La DEK y la sal del respaldo son distintas de las de la bóveda viva, y abrir el respaldo con la frase maestra falla.
- Se rechazan una frase igual a la maestra, una frase corta y la falta de confirmación.
- Un archivo ajeno (texto, JSON, vacío o truncado) da el error claro. Una frase incorrecta da su error.
- Cada estado y cada decisión. El token se rechaza vencido o en paralelo. Con la bóveda cerrada al aplicar, el token se conserva.
- Ningún secreto ni la frase en la auditoría, los errores o los registros (busca el texto en la auditoría y en la salida de mctl).
- Archivo 0600, sin seguir un symlink, sin sobrescribir sin `overwrite`.
- mctl de punta a punta con las frases por stdin.
