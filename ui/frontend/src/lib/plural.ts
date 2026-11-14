import type { useT } from "./i18n";
import type { Key } from "./i18n/es";

// Texto con la unidad ya en singular o plural ("1 equipo", "3 equipos"): `unit.*` y `unit.*.one` en los diccionarios.
// Sirve para las cadenas con varios números, donde `t` solo puede resolver el singular de `n`.
export const plural = (t: ReturnType<typeof useT>, key: Key, n: number) => t(key, { n });
