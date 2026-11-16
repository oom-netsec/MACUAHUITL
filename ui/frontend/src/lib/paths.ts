import { isWindows } from "./platform";

// Rutas locales de la máquina del usuario. En Windows separan «\» y «/»; en Linux solo «/» («\» es válido en un nombre).
const lastSep = (p: string) => (isWindows() ? Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\")) : p.lastIndexOf("/"));

/** Último componente; vacío si la ruta termina en separador. */
export const baseName = (p: string) => p.slice(lastSep(p) + 1);

/** Ruta completa de Windows: «C:\…» o «\\servidor\recurso\…» (no «\x», que es relativa a la unidad actual, ni «C:x»). */
export const isAbsWindows = (p: string) => /^([A-Za-z]:[\\/]|\\\\[^\\/]+[\\/][^\\/]+[\\/])/.test(p);

/** Carpeta que contiene el archivo; vacía si no hay separador. La raíz conserva su separador ("/", "C:\"). */
export function dirName(p: string): string {
  const i = lastSep(p);
  if (i < 0) return "";
  const d = p.slice(0, i);
  return d === "" || (isWindows() && /^[A-Za-z]:$/.test(d)) ? p.slice(0, i + 1) : d;
}
