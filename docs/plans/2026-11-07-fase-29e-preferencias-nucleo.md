# Fase 29e — Preferencias del núcleo (pantalla Ajustes)

Pedido del dueño (vía la sesión de front), para la pantalla Ajustes:
1. Carpeta base de salida (`outputs/`) configurable, con validación.
2. Retención y rotación por defecto que usan syslog, traps y flows cuando la vista no manda opciones.

Hoy `ResolvePaths` (`internal/core/paths.go`) fija `~/MACUAHUITL/outputs` y `coreDeps.Outputs()` lo devuelve. `PrefsService` es un clave/valor genérico (`GetPreference`/`SetPreference`, tabla `preferences`).

## Diseño
- **Preferencias tipadas del núcleo, sin tabla nueva.** Se guardan con claves reservadas `core.*` en `preferences`, y `SetPreference` genérico NO puede escribir esas claves (InvalidArgument). Hay dos RPC nuevos en `PrefsService`: `GetCorePrefs()` y `SetCorePrefs(CorePrefs)`.
  - `CorePrefs.outputs_dir` (string, vacío = el de fábrica). La respuesta incluye `outputs_dir_effective` y `outputs_dir_default`.
  - `CorePrefs.ingest_defaults`: `{rotate_mb, rotate_minutes, max_files, format}`, con los mismos rangos que valida la fase 28a/29a. 0 o vacío = el de fábrica.
- **Validación de `outputs_dir`:**
  - ruta absoluta, sin `..`;
  - se resuelve con EvalSymlinks: debe existir y ser un directorio del usuario actual (uid del proceso);
  - escribible (prueba de crear y borrar un temporal);
  - modo exactamente 0700. Si es más permisivo, se rechaza con el motivo y la orden sugerida (`chmod 700 <ruta>`). El núcleo no cambia los permisos del usuario.
  - No puede estar dentro de la carpeta de datos del núcleo ni ser `/`, `$HOME`, `/tmp` o la carpeta de configuración.
  - Los errores llevan código para el paso de idioma (fase 30a): `prefs.outputs.<motivo>`. Por ahora, texto en español.
- **Cuándo aplica.** El cambio aplica a lo que empiece después. Los trabajos y escuchas en curso conservan la ruta con que arrancaron. `coreDeps.Outputs()` lee el valor vigente bajo un lock ligero.
  - Los datos de la carpeta anterior NO se mueven. La respuesta y el contrato lo dicen.
  - Revisa todos los usuarios de `Outputs()` (grep) para confirmar que ninguno guarda la ruta en caché al iniciar el núcleo. Si alguno lo hace, adáptalo.
- **Defaults de ingest.** El servicio usa `ingest_defaults` cuando la petición deja el campo en 0 o vacío. Hoy los defaults están fijos en `service.IngestOpts` (`DefPerSource`, etc.). Los de tasa NO son configurables en esta fase, solo rotate/retención/formato.
- **Auditoría.** `prefs.core` con los campos cambiados (valor anterior y nuevo; rutas sí, sin datos sensibles).

## Proto, mctl, puente y contrato
- `prefs.proto`: los mensajes y los dos RPC, sin renumerar.
- mctl: `mctl prefs show|set --outputs DIR --rotate-mb N --rotate-min N --max-files N --format F` (o el área que ya exista), con su `help.golden`.
- Puente y TS en el módulo de ajustes (`api.ts`/`fake.ts`).
- Contrato: sección nueva al final de `docs/plans/contratos-front.md`.

## Pruebas mínimas
- Cada regla de validación de la carpeta: relativa, inexistente, archivo, de otro dueño (si no se puede en la prueba, con un stat inyectable), 0755 rechazada, 0700 aceptada, symlink a una carpeta 0700 aceptado y resuelto, carpeta de datos rechazada, `$HOME` rechazado.
- `SetPreference` con una clave `core.*` se rechaza.
- Cambiar `outputs_dir`: un trabajo nuevo escribe en la nueva y una escucha en curso sigue en la vieja. Persistencia tras reabrir el núcleo.
- Defaults de ingest: una escucha sin opciones usa los de prefs y una con opciones explícitas los ignora. Rangos inválidos dan InvalidArgument.
- Auditoría del cambio. mctl de punta a punta.
