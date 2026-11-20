import { errorText } from "../../components/Field";
import { errInfo } from "../../lib/coreError";
import type { Key } from "../../lib/i18n/es";
import type { Host, HostDraft, HostPlatform, HostProtocol } from "./api";

// Formulario de un host: todo en texto hasta guardar. Las reglas son las del contrato (docs/plans/contratos-front.md, fase 29b);
// el núcleo vuelve a validar y su palabra manda.
export interface HostForm { name: string; address: string; port: string; platform: HostPlatform; folder: string; tags: string; credentialId: string; notes: string; startCommand: string; protocol: HostProtocol }
export type HostField = keyof HostForm;

export const PLATFORMS: [HostPlatform, string][] = [["ios", "IOS"], ["ios-xe", "IOS-XE"], ["nx-os", "NX-OS"], ["asa", "ASA"], ["ftd", "FTD"], ["ise", "ISE"], ["iosxr", "IOS-XR"], ["wlc", "WLC"], ["linux", "Linux"], ["windows", "Windows"]];

// Plataforma detectada (Patrol) → la del inventario: las variantes de WLC (wlc-aireos, wlc-9800) son «wlc»; lo que no exista queda sin definir.
export const hostPlatformOf = (p: string): HostPlatform => {
  const v = p.startsWith("wlc-") ? "wlc" : p;
  return PLATFORMS.some(([x]) => x === v) ? (v as HostPlatform) : "";
};

export const emptyForm: HostForm = { name: "", address: "", port: "22", platform: "", folder: "", tags: "", credentialId: "", notes: "", startCommand: "", protocol: "ssh" };

export const formOf = (h: Pick<Host, "name" | "address" | "port" | "platform" | "folder" | "tags" | "credentialId" | "notes" | "startCommand"> & { protocol?: HostProtocol }): HostForm =>
  ({ name: h.name, address: h.address, port: String(h.port || 22), platform: h.platform, folder: h.folder, tags: h.tags.join(" "), credentialId: h.credentialId, notes: h.notes, startCommand: h.startCommand ?? "", protocol: h.protocol === "telnet" ? "telnet" : "ssh" });

// Agrupa por carpeta (una pasada, sin copiar arreglos): por nombre de carpeta y «sin carpeta» al final.
export function groupByFolder<T extends { folder: string }>(list: T[]): [string, T[]][] {
  const m = new Map<string, T[]>();
  for (const h of list) { const g = m.get(h.folder); if (g) g.push(h); else m.set(h.folder, [h]); }
  return [...m.entries()].sort(([a], [b]) => (a === "" ? 1 : b === "" ? -1 : a.localeCompare(b)));
}

export const parseTags = (s: string) => s.split(/[\s,]+/).filter(Boolean);

const TAG = /^[a-z0-9-]{1,24}$/;
const FOLDER = /^[A-Za-z0-9 _.-]{1,48}$/;
export const hasStartCommand = (p: HostPlatform) => p === "linux" || p === "windows"; // en equipos de red no aplica
export const defaultPort = (p: HostProtocol) => (p === "telnet" ? 23 : 22);
// Cambiar el protocolo: un puerto vacío o el de omisión del anterior se vacía (toma el del nuevo); uno elegido a mano se conserva. Telnet no admite orden de inicio.
export function withProtocol(f: HostForm, protocol: HostProtocol): HostForm {
  const p = f.port.trim();
  return { ...f, protocol, port: p === "" || p === String(defaultPort(f.protocol)) ? "" : f.port, startCommand: protocol === "telnet" ? "" : f.startCommand };
}
// Nombre de carpeta nuevo o renombrado (sin espacios en los extremos).
export const validFolderName = (s: string) => FOLDER.test(s) && s === s.trim();

export function validateHost(f: HostForm): Partial<Record<HostField, Key>> {
  const e: Partial<Record<HostField, Key>> = {};
  const name = f.name.trim();
  if (!name || [...name].length > 64) e.name = "hosts.v.name";
  const a = f.address.trim();
  if (!a || a.length > 253 || /[\s@/]/.test(a) || a.includes("://") || (a.split(":").length === 2 && a.includes(":"))) e.address = "hosts.v.address";
  if (f.port.trim() !== "" && !(/^\d+$/.test(f.port.trim()) && Number(f.port) >= 1 && Number(f.port) <= 65535)) e.port = "hosts.v.port";
  if (f.folder !== "" && (!FOLDER.test(f.folder) || f.folder !== f.folder.trim())) e.folder = "hosts.v.folder";
  const tags = parseTags(f.tags);
  if (tags.length > 10 || new Set(tags).size !== tags.length || !tags.every((t) => TAG.test(t))) e.tags = "hosts.v.tags";
  if ([...f.notes].length > 2000) e.notes = "hosts.v.notes";
  if (f.protocol !== "telnet" && hasStartCommand(f.platform) && ([...f.startCommand].length > 256 || f.startCommand !== f.startCommand.trim() || /[\p{Cc}\p{Cf}\u2028\u2029]/u.test(f.startCommand))) e.startCommand = "hosts.v.startCommand";
  return e;
}

export const draftOf = (f: HostForm, id?: string): HostDraft => ({
  ...(id ? { id } : {}), name: f.name.trim(), address: f.address.trim(), port: f.port.trim() ? Number(f.port) : defaultPort(f.protocol), platform: f.platform,
  folder: f.folder, tags: parseTags(f.tags), credentialId: f.credentialId, notes: f.notes,
  startCommand: f.protocol !== "telnet" && hasStartCommand(f.platform) ? f.startCommand : "", protocol: f.protocol,
});

const FIELDS: HostField[] = ["protocol", "name", "address", "port", "platform", "folder", "tags", "notes", "credentialId", "startCommand", "protocol"];

// El campo y el duplicado salen de reason y metadata.field. El texto en español solo es respaldo de errores sin reason.
// Las duplicadas van primero: el nombre del host puede contener cualquier palabra («credencial», «puerto»…).
export function coreErrorKey(e: unknown): "hosts.err.nameDup" | "hosts.err.addrDup" | "hosts.err.protocol" | "hosts.err.startTelnet" | "" {
  const i = errInfo(e);
  if (i) return i.reason === "hosts.duplicate_name" ? "hosts.err.nameDup" : i.reason === "hosts.duplicate_address" ? "hosts.err.addrDup" : i.reason === "hosts.invalid_protocol" ? "hosts.err.protocol" : i.reason === "hosts.invalid_startup_command" ? "hosts.err.startTelnet" : "";
  const msg = errorText(e);
  if (/ya hay un host llamado/i.test(msg)) return "hosts.err.nameDup";
  if (/ya está en la libreta/i.test(msg)) return "hosts.err.addrDup";
  return "";
}

const wireField: Record<string, string> = { startup_command: "startCommand", credential_id: "credentialId" };

export function coreErrorField(e: unknown): HostField | "" {
  const i = errInfo(e);
  // El cable nombra los campos como el proto (snake_case); en la UI son camelCase.
  if (i) return i.reason.startsWith("hosts.") ? FIELDS.find((f) => f === (wireField[i.metadata.field] ?? i.metadata.field)) ?? "" : "";
  const msg = errorText(e);
  const dup = coreErrorKey(e);
  if (dup) return dup === "hosts.err.nameDup" ? "name" : "address";
  if (/orden de inicio|start ?command/i.test(msg)) return "startCommand";
  if (/credencial/i.test(msg)) return "credentialId";
  if (/direcci[oó]n/i.test(msg)) return "address";
  if (/nombre/i.test(msg)) return "name";
  if (/puerto/i.test(msg)) return "port";
  if (/plataforma/i.test(msg)) return "platform";
  if (/carpeta/i.test(msg)) return "folder";
  if (/etiqueta/i.test(msg)) return "tags";
  if (/notas/i.test(msg)) return "notes";
  return "";
}

// Borrar una carpeta con hosts sin confirm: el núcleo responde FailedPrecondition con la cuenta. n = "" si el error no la trae.
export function folderNotEmpty(e: unknown): { n: string } | null {
  const i = errInfo(e);
  return i?.reason === "hosts.err.folder_not_empty" ? { n: i.metadata.host_count ?? "" } : null;
}
