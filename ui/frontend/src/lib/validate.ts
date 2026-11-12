// Validaciones de campos que solo sirven de ayuda en pantalla: la autoritativa es la del núcleo
// (internal/assist/templates.go y ports.go); estas reglas la reflejan para no avisar de más ni de menos.

const dec = (s: string) => /^\d+$/.test(s);

// Como netip.ParseAddr: cuatro octetos 0-255 sin ceros a la izquierda.
export function ipv4Ok(s: string): boolean {
  const p = s.split(".");
  return p.length === 4 && p.every((o) => /^(0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255);
}

// Máscara decimal (255.255.255.0), no prefijo: de /1 a /32, unos contiguos y luego ceros.
export function maskOk(s: string): boolean {
  if (!ipv4Ok(s)) return false;
  const v = s.split(".").reduce((a, o) => a * 256 + Number(o), 0);
  if (v === 0) return false;
  const inv = (~v) >>> 0; // los ceros finales de una máscara válida forman 2^k - 1
  return ((inv & (inv + 1)) >>> 0) === 0;
}

// Entero sin signo ni ceros a la izquierda; max 0 = sin tope.
export function intOk(s: string, min = 0, max = 0): boolean {
  if (!dec(s) || (s.length > 1 && s[0] === "0")) return false;
  const n = Number(s);
  return Number.isSafeInteger(n) && n >= min && (max === 0 || n <= max);
}

// Hasta tres dígitos enteros y dos decimales, sin signo (el regex del núcleo).
export function decimalOk(s: string, min = 0, max = 0): boolean {
  if (!/^\d{1,3}(\.\d{1,2})?$/.test(s)) return false;
  const n = Number(s);
  return n >= min && (max === 0 || n <= max);
}

// VLAN de 1 a 4094; min y max del campo la acotan (nunca pasa de 4094).
export function vlanOk(s: string, min = 1, max = 0): boolean {
  return intOk(s, Math.max(min, 1), max > 0 ? Math.min(max, 4094) : 4094);
}

// Puerto físico como el núcleo (ifaceRe): hasta cuatro números separados por «/».
const PHYS = /^(gigabitethernet|tengigabitethernet|fastethernet|twentyfivegige|fortygigabitethernet|hundredgige|ethernet|gi|te|fa|twe|fo|hu|eth)\d+(\/\d+){0,3}$/i;
const PORT_CHANNEL = /^(port-channel|po)\d+$/i;

// Campo `interface` (un puerto): físico o Port-channel.
export const interfaceOk = (s: string) => PHYS.test(s) || PORT_CHANNEL.test(s);

// Cuántos puertos distintos nombra una lista como "Gi1/0/1-4, Gi1/0/9" (separada por comas o espacios; rangos sobre el último número,
// que solo se reconocen después de «/»); null si algún elemento no es un puerto físico o el rango es inválido.
// shortcut: los repetidos se comparan en minúsculas sin normalizar Gi/GigabitEthernet; el núcleo sí (ShortIf), lo cuenta él.
export function countInterfaces(s: string): number | null {
  const seen = new Set<string>();
  for (const tok of s.split(/[, ]+/).filter(Boolean)) {
    const m = /^(.+\/)(\d+)-(\d+)$/.exec(tok);
    const lo = m ? Number(m[2]) : 0, hi = m ? Number(m[3]) : 0;
    if (m && lo > hi) return null;
    const names = m ? Array.from({ length: Math.min(hi - lo + 1, 1000) }, (_, i) => m[1] + (lo + i)) : [tok];
    for (const n of names) {
      if (!PHYS.test(n)) return null;
      seen.add(n.toLowerCase());
    }
  }
  return seen.size;
}
