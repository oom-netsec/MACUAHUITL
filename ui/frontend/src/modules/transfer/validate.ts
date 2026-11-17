import type { Key } from "../../lib/i18n/es";
import type { TransferProto } from "./api";

// Puerto estándar del protocolo por omisión (IOS no deja elegir otro). Si el sistema niega el bind, el núcleo explica cómo permitirlo.
const defaultPort: Record<TransferProto, string> = { tftp: "69", ftp: "21", scp: "22", sftp: "22", http: "80" };
export const portFor = (p: TransferProto) => defaultPort[p];

// Puerto alto que se usaba antes de los puertos estándar: una tabla nft que el usuario haya dejado redirige a él (HTTP nunca tuvo redirección).
const oldHighPort: Record<string, number> = { tftp: 6969, ftp: 2121, scp: 2222, sftp: 2222 };
// Orden para quitar esa tabla, con el formato del núcleo; ::ffff:a.b.c.d el núcleo la trata como IPv4. SCP y SFTP comparten el 22: van las dos.
export function nftLeftoverCmd(proto: string, host: string, port: number): string {
  const fam = host.includes(":") && !/^::ffff:\d+\.\d+\.\d+\.\d+$/i.test(host) ? "ip6" : "ip";
  const protos = proto === "scp" || proto === "sftp" ? ["scp", "sftp"] : [proto];
  return protos.map((p) => `sudo nft delete table ${fam} macuahuitl_${p}_${oldHighPort[p] ?? port}`).join("\n");
}

export const isIP = (s: string) =>
  (/^\d{1,3}(\.\d{1,3}){3}$/.test(s) && s.split(".").every((n) => Number(n) <= 255)) || (s.includes(":") && /^[0-9a-f:.]+$/i.test(s) && (s.match(/:/g) ?? []).length >= 2);

export const splitList = (s: string) => s.split(/[\s,;]+/).filter(Boolean);

export interface ServeForm { proto: TransferProto; any: boolean; listen: string; port: string; write: boolean; recvDir: string; fromDir: string; files: string; allow: string; minutes: string }

// Primer problema del formulario (clave de i18n) o null. El puerto bajo lo decide el bind del núcleo, no la UI.
export function serveProblem(f: ServeForm): Key | null {
  if (!f.any && !f.listen) return "transfer.err.listen";
  const port = Number(f.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return "transfer.err.port";
  if (!f.write && !f.fromDir && splitList(f.files).length === 0) return "transfer.err.nothing";
  if (!splitList(f.allow).every(isIP)) return "transfer.err.allow";
  const none = splitList(f.allow).length === 0;
  if (f.any && none) return "transfer.err.anyAllow"; // todas las interfaces: siempre con la lista de IP
  if (f.write && f.proto === "tftp" && none) return "transfer.err.tftpAllow"; // en UDP el origen se falsifica: sin lista cualquiera escribiría
  const m = Number(f.minutes);
  if (!Number.isInteger(m) || m < 1 || m > 1440) return "transfer.err.minutes";
  return null;
}

export const hexLen: Record<number, "md5" | "sha256" | "sha512"> = { 32: "md5", 64: "sha256", 128: "sha512" };
// Hash esperado: vacío es válido; si no, hexadecimal de MD5, SHA-256 o SHA-512.
export function expectedHash(s: string): { kind: "md5" | "sha256" | "sha512"; value: string } | "" | null {
  const v = s.trim().toLowerCase().replace(/^(md5|sha-?256|sha-?512)[:=]\s*/, "");
  if (!v) return "";
  return /^[0-9a-f]+$/.test(v) && hexLen[v.length] ? { kind: hexLen[v.length], value: v } : null;
}

export interface ParsedURL { scheme: string; userinfo: string; host: string }
// URL de cliente: esquema conocido, equipo y ninguna contraseña incrustada (va por la credencial de la bóveda).
export function parseURL(u: string): ParsedURL | "password" | null {
  const m = /^(tftp|ftp|scp|sftp|https?):\/\/(?:([^@/\s]*)@)?([^/@\s]+)(?:\/\S*)?$/.exec(u.trim());
  if (!m) return null;
  return m[2]?.includes(":") ? "password" : { scheme: m[1], userinfo: m[2] ?? "", host: m[3] };
}

// El núcleo manda la llave nueva en el error: «llave de host desconocida|cambiada de H: SHA256:…».
export { hostKeyFromError } from "../../lib/hostkeys";
