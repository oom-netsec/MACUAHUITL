import { isWindows } from "./platform";

// Rutas locales de la máquina del usuario. En Windows separan «\» y «/»; en Linux solo «/» («\» es válido en un nombre).
const lastSep = (p: string) => (isWindows() ? Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\")) : p.lastIndexOf("/"));

/** Último componente; vacío si la ruta termina en separador. */
export const baseName = (p: string) => p.slice(lastSep(p) + 1);

/** Ruta completa de Windows: solo «C:\…» o «C:/…» (como winAbs del núcleo). No «\x» ni «C:x» (relativas a la unidad o a la raíz actual) ni UNC. */
export const isAbsWindows = (p: string) => /^[A-Za-z]:[\\/]/.test(p);

/** Carpeta que contiene el archivo; vacía si no hay separador. La raíz conserva su separador ("/", "C:\"). */
export function dirName(p: string): string {
  const i = lastSep(p);
  if (i < 0) return "";
  const d = p.slice(0, i);
  return d === "" || (isWindows() && /^[A-Za-z]:$/.test(d)) ? p.slice(0, i + 1) : d;
}

export type PathProblem = "paths.err.unc" | "paths.err.nt" | "paths.err.ads" | "paths.err.rel" | "paths.err.reserved";
const RESERVED = /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$)$/i;

/** Ruta que la app no acepta en Windows (clave de i18n) o null; vacía no es un problema. Solo Windows: en Linux «\\» y «:» son caracteres de un nombre y «//» es una ruta común.
 *  Una válida es solo «C:\…» (igual que winAbs del núcleo) sin UNC, \\?\ \\.\ \??\ \GLOBALROOT, flujos alternos (ADS) ni nombres reservados (CON, NUL, COM1…, con o sin extensión). */
export function pathProblem(p: string): PathProblem | null {
  if (!isWindows() || !p) return null;
  const n = p.replace(/\//g, "\\");
  if (/^\\\\/.test(n)) return "paths.err.unc"; // UNC, \\?\ y \\.\
  if (/^\\(?:\?\?\\|GLOBALROOT(?:\\|$))/i.test(n)) return "paths.err.nt"; // espacio de nombres del NT
  if ((/^[A-Za-z]:/.test(n) ? n.slice(2) : n).includes(":")) return "paths.err.ads";
  if (!isAbsWindows(p)) return "paths.err.rel";
  if (n.slice(3).split("\\").some((e) => RESERVED.test(e.split(".")[0].trimEnd()))) return "paths.err.reserved";
  return null;
}
