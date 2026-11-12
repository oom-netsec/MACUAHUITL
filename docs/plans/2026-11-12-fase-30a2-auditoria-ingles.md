# Fase 30a-2 — Auditoría siempre en inglés

Decisión del dueño del 2026-11-12: el registro de auditoría se escribe siempre en inglés, con un código fijo por acción. Esto reemplaza la decisión anterior, que era escribirlo en español. El diseño está en la sección 4 de `docs/plans/2026-11-12-fase-30a-idioma-nucleo.md`.

## Reglas
- **La acción no cambia.** El primer argumento de `d.Audit(acción, objetivo, detalle)` ya es un código fijo (`job.logintest`, `vault.respaldo.exportar`, …). Se queda igual aunque tenga palabras en español: es un identificador, y la UI y las búsquedas lo usan.
- **El detalle va en inglés fijo.** Hay unas 160 llamadas: `grep -rn 'd.Audit\|c.audit(\|\.Audit(' --include=*.go internal ui cmd`.
  - El formato es `clave=valor` en inglés: `passed=1 of 2` en vez de `pasaron=1 de 2`, y `reason=`/`guard=` en vez de `razon=`/`guard=`.
  - Los valores que son datos (rutas, IPs, nombres de usuario permitidos, ids) se quedan tal cual.
  - Los textos fijos dentro del detalle pasan al inglés: estados, motivos, «sí/no», etc.
  - El detalle NUNCA pasa por `i18n` ni por el locale del contexto: `accept-language` no lo cambia.
- **Errores incluidos en el detalle.** Cuando el detalle incluye `err.Error()` de un error del núcleo que ya tiene código en el catálogo (`i18n`), usa su texto en inglés con `i18n.TIn("en", …)` o lo que exista para pedir un idioma fijo. Si no tiene código, va tal cual. Anota en el PR cuántos quedaron así.
- **Registros viejos.** Los registros existentes NO se reescriben, porque la cadena de hashes no se toca. `audit verify` debe seguir íntegro con registros mixtos (español viejos, inglés nuevos).
- **Ninguna prueba debe depender de los textos viejos en español del detalle.** Actualiza las aserciones que los buscan; son las que hoy hacen `strings.Contains(auditText, "…")`.
- **Seguridad.** Al cambiar textos, no agregues datos sensibles al detalle: ni secretos, ni frases, ni contenidos de credenciales. Revisa que ningún detalle nuevo los incluya.
- **UI.** Revisa si la vista de auditoría (`ui/frontend/src/modules/audit`) traduce o interpreta el detalle (por ejemplo, busca `razon=`). Si lo hace, actualízala para que reconozca los dos formatos, el viejo y el nuevo.

## Pruebas
- Para un par de acciones representativas (`job.logintest` y una de bóveda), el detalle en inglés sale igual con o sin `accept-language: es`.
- Una prueba general recorre el texto de auditoría de una sesión de pruebas con varias acciones y falla si encuentra palabras típicas del español en el detalle (lista corta: «pasaron», « de », «razón», «sí», «carpeta», «equipo», «falló», «inválid», á/é/í/ó/ú/ñ fuera de valores de usuario). Ajusta la lista para que no dé falsos positivos con datos.
- `audit verify` pasa con registros viejos en español y nuevos en inglés en la misma base.

## Contrato
Sección nueva al final de `docs/plans/contratos-front.md`: el detalle de auditoría está en inglés desde esta fase, la acción no cambia y los registros viejos se quedan en español.
