// Formulario del cliente de transferencias: la URL se arma desde los campos y la petición al núcleo sale del mismo estado.
import type { Key } from "../../lib/i18n/es";
import { parseFingerprints } from "../../lib/hostkeys";
import type { TransferGetParams, TransferPutParams } from "./api";
import { expectedHash, isIP } from "./validate";

export type ClientProto = "tftp" | "ftp" | "scp" | "sftp" | "http" | "https";
export const clientProtos: ClientProto[] = ["tftp", "ftp", "scp", "sftp", "http", "https"];
export const putProtos: ClientProto[] = ["tftp", "ftp", "scp", "sftp"];
export const defaultClientPort: Record<ClientProto, string> = { tftp: "69", ftp: "21", scp: "22", sftp: "22", http: "80", https: "443" };

export interface ClientForm {
  dir: "get" | "put"; proto: ClientProto; host: string; port: string; portTouched: boolean; path: string; cred: string; hash: string; name: string;
  destDir: string; src: string; accepted: string; maxMB: string; minutes: string; legacy: boolean; insecure: boolean;
}

export const MAX_MB = 1048576;
export const usesSsh = (p: ClientProto) => p === "scp" || p === "sftp";
// SCP, SFTP y FTP: una "/" inicial es ruta absoluta (el núcleo quita una y manda el resto).
export const absPath = (p: ClientProto) => usesSsh(p) || p === "ftp";
export const usesCred = (p: ClientProto) => usesSsh(p) || p === "ftp";
// Mientras la persona no toque el puerto, vale el estándar del protocolo.
export const portOf = (f: ClientForm) => (f.portTouched ? f.port : defaultClientPort[f.proto]);

const bracket = (h: string) => (h.includes(":") && !h.startsWith("[") ? `[${h}]` : h);

export function buildURL(f: ClientForm): string {
  const host = f.host.trim();
  if (!host) return "";
  const port = portOf(f);
  const q = f.path.indexOf("?");
  const web = f.proto === "http" || f.proto === "https";
  const raw = web && q >= 0 ? f.path.slice(0, q) : f.path; // la query de una URL web (tokens) viaja tal cual
  const enc = raw.split("/").map(encodeURIComponent).join("/");
  // El núcleo quita una "/" inicial de la ruta (remotePath): en SCP/SFTP/FTP "/tmp/x" debe viajar como "//tmp/x" para ser absoluta; sin "/" queda relativa al home.
  const path = absPath(f.proto) ? `/${enc}` : enc.replace(/^\/?/, "/");
  return `${f.proto}://${bracket(host)}${port && port !== defaultClientPort[f.proto] ? `:${port}` : ""}${path}${web && q >= 0 ? f.path.slice(q) : ""}`;
}

export interface ParsedClientURL { proto: ClientProto; host: string; port: string; path: string }
// URL pegada → campos. "password" si trae contraseña; null si no es una URL de cliente válida para el sentido.
export function parseClientURL(text: string, dir: "get" | "put"): ParsedClientURL | "password" | null {
  let u: URL;
  try { u = new URL(text.trim()); } catch { return null; }
  const proto = u.protocol.slice(0, -1) as ClientProto;
  if (!(dir === "put" ? putProtos : clientProtos).includes(proto) || !u.hostname) return null;
  if (u.password) return "password";
  const host = u.hostname.replace(/^\[|\]$/g, "");
  let path = u.pathname;
  try { path = decodeURIComponent(path); } catch { /* % suelto: se deja como vino */ }
  if (absPath(proto)) path = path.replace(/^\//, ""); // inversa de buildURL: "//tmp/x" → "/tmp/x", "/x" → "x"
  return { proto, host, port: u.port, path: path + u.search };
}

export type ClientErrors = Partial<Record<"host" | "port" | "path" | "cred" | "hash" | "src" | "minutes" | "maxMB", Key>>;

export function clientErrors(f: ClientForm): ClientErrors {
  const e: ClientErrors = {};
  const host = f.host.trim();
  const bare = host.replace(/^\[|\]$/g, "");
  if (!host || /[\s/@?#]/.test(host)) e.host = "transfer.err.host";
  else if (bare.includes("%")) e.host = "transfer.err.hostZone"; // la zona IPv6 no se admite
  else if (bare.includes(":") && !isIP(bare)) e.host = "transfer.err.hostPort"; // «host:puerto»: el puerto va en su campo
  const port = portOf(f);
  if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535) e.port = "transfer.err.cport";
  if (!f.path.replace(/[\s/]/g, "")) e.path = "transfer.err.path";
  if (usesSsh(f.proto) && !f.cred) e.cred = "transfer.err.cred";
  if (f.dir === "get" && expectedHash(f.hash) === null) e.hash = "transfer.err.hash";
  if (f.dir === "put" && !f.src) e.src = "transfer.err.src";
  else if (f.dir === "put" && (f.src.lastIndexOf("/") < 0 || f.src.endsWith("/"))) e.src = "transfer.err.srcPath";
  const m = f.minutes.trim();
  if (m && !(/^\d+$/.test(m) && Number(m) >= 1 && Number(m) <= 240)) e.minutes = "transfer.err.cminutes";
  const mb = f.maxMB.trim();
  // Decimal llano (sin 1e3, 0x ni Infinity); al menos 1 byte y hasta 1 TiB, lejos de los enteros inexactos.
  if (mb && !(/^\d+(\.\d+)?$/.test(mb) && Math.round(Number(mb) * 1048576) >= 1 && Number(mb) <= MAX_MB)) e.maxMB = "transfer.err.maxmb";
  return e;
}

// Opcionales: solo salen si se llenaron (0 = sin tope en el núcleo).
function limits(f: ClientForm): { maxBytes?: number; seconds?: number } {
  return {
    ...(f.maxMB.trim() ? { maxBytes: Math.round(Number(f.maxMB) * 1024 * 1024) } : {}),
    ...(f.minutes.trim() ? { seconds: Number(f.minutes) * 60 } : {}),
  };
}

export function getParams(f: ClientForm): TransferGetParams {
  const h = expectedHash(f.hash);
  return {
    url: buildURL(f), destDir: f.destDir, credentialId: usesCred(f.proto) ? f.cred : "", acceptedHostKeys: usesSsh(f.proto) ? parseFingerprints(f.accepted) : [],
    insecure: f.proto === "https" && f.insecure, legacySsh: usesSsh(f.proto) && f.legacy,
    ...(f.name.trim() ? { name: f.name.trim() } : {}), ...limits(f), ...(h ? { [h.kind]: h.value } : {}),
  };
}

export function putParams(f: ClientForm): TransferPutParams {
  const i = f.src.lastIndexOf("/");
  return {
    url: buildURL(f), fromDir: f.src.slice(0, i) || "/", name: f.src.slice(i + 1), credentialId: usesCred(f.proto) ? f.cred : "",
    acceptedHostKeys: usesSsh(f.proto) ? parseFingerprints(f.accepted) : [], legacySsh: usesSsh(f.proto) && f.legacy, ...limits(f),
  };
}
