// Doble del módulo para pruebas y para trabajar los selectores sin núcleo.
import { vi } from "vitest";
import type { Host, HostField, HostFileFormat, HostFilter, HostImportDecision, HostsFormat, HostsImportPreview, KnownDevice, KnownDevices } from "./api";

const t = Date.UTC(2026, 10, 6, 9, 0, 0);

const dev = (d: Pick<KnownDevice, "address" | "hostname" | "platform" | "lastSeenMs" | "sources"> & Partial<KnownDevice>): KnownDevice => ({
  id: d.address || `nombre:${d.hostname}`, name: "", port: 0, folder: "", tags: [], credentialId: "", credentialLabel: "", notes: "", ...d,
});

export const sampleDevices: KnownDevices = {
  devices: [
    dev({ address: "10.0.0.1", hostname: "SW-CORE", platform: "ios-xe", lastSeenMs: t, sources: ["patrol", "flota", "respaldos"] }),
    dev({ address: "10.0.0.2", hostname: "SW-ACC1", platform: "ios-xe", lastSeenMs: t - 86_400_000, sources: ["patrol", "flota"] }),
    dev({ address: "10.0.0.9", hostname: "CAIDO", platform: "ios-xe", lastSeenMs: 0, sources: ["patrol"] }),
    dev({ address: "", hostname: "SOLO-RESP", platform: "", lastSeenMs: t - 5 * 86_400_000, sources: ["respaldos"] }),
  ],
  warnings: [],
};

const host = (h: Partial<Host> & Pick<Host, "id" | "name" | "address">): Host => ({
  port: 22, platform: "ios-xe", folder: "", tags: [], credentialId: "", credentialLabel: "", notes: "", ...h,
});

export const sampleHosts: Host[] = [
  host({ id: "a".repeat(32), name: "LAB-CORE", address: "10.9.0.1", folder: "Lab", tags: ["core"], credentialId: "c".repeat(32), credentialLabel: "admin lab", notes: "piso 2" }),
  host({ id: "b".repeat(32), name: "LAB-AP", address: "ap1.lab", port: 2222, platform: "wlc", folder: "Lab" }),
  host({ id: "d".repeat(32), name: "OFI-SW", address: "10.8.0.1", platform: "", folder: "Oficina", tags: ["acceso", "dc-1"] }),
];

// Archivo de ejemplo para el import: uno nuevo, uno igual, un conflicto de dirección y uno de nombre (con su credencial sin resolver).
export const sampleHostsImport: HostsImportPreview = {
  token: "token-1",
  expiresMs: t + 600_000,
  format: "csv",
  warnings: ["1 host(s) traen una etiqueta de credencial que no está en la bóveda (o está repetida) y quedarían sin credencial"],
  errors: [{ line: 14, field: "address", reason: "dirección \"admin@10.0.0.9\": use una IP o un nombre DNS" }, { line: 15, field: "", reason: "tiene 3 columnas; se esperaban 8" }],
  items: [
    { host: host({ id: "", name: "NUEVO", address: "10.7.0.1" }), key: "10.7.0.1:22", state: "nuevo", reason: "", conflictsWith: "", credentialMissing: false },
    { host: host({ id: "", name: "OFI-SW", address: "10.8.0.1", platform: "", folder: "Oficina", tags: ["acceso", "dc-1"] }), key: "10.8.0.1:22", state: "igual", reason: "", conflictsWith: "d".repeat(32), credentialMissing: false },
    { host: host({ id: "", name: "OTRO-NOMBRE", address: "10.9.0.1", credentialLabel: "admin lab" }), key: "10.9.0.1:22", state: "conflicto", reason: "direccion", conflictsWith: "a".repeat(32), credentialMissing: false },
    { host: host({ id: "", name: "LAB-AP", address: "ap2.lab", credentialLabel: "no existe" }), key: "ap2.lab:22", state: "conflicto", reason: "nombre", conflictsWith: "b".repeat(32), credentialMissing: true },
  ],
};

// La misma tabla de campos que usa el núcleo para validar, leer y escribir el archivo.
export const sampleHostFields: HostField[] = [
  { name: "name", type: "texto", required: true, example: "SW-CORE", description: "Nombre del host: 1 a 64 caracteres, sin espacios en los extremos. No se repite (sin importar mayúsculas)." },
  { name: "address", type: "texto", required: true, example: "10.0.0.1", description: "IP o nombre DNS, sin usuario, esquema, puerto ni ruta. La dirección con el puerto no se repite." },
  { name: "port", type: "entero", required: false, example: "22", description: "Puerto SSH, de 1 a 65535. Vacío = 22." },
  { name: "platform", type: "texto", required: false, example: "ios-xe", description: "Plataforma: ios, ios-xe, nx-os, asa, iosxr, wlc. Vacío = sin definir." },
  { name: "folder", type: "texto", required: false, example: "Lab", description: "Carpeta de un solo nivel: 1 a 48 caracteres entre letras, números, espacio, _, . y -. Vacío = sin carpeta." },
  { name: "tags", type: "lista", required: false, example: "core;dc-1", description: "Hasta 10 etiquetas de 1 a 24 caracteres entre a-z, 0-9 y -. En CSV separadas por «;»; en JSON, un arreglo." },
  { name: "credential_label", type: "texto", required: false, example: "admin lab", description: "Etiqueta de una credencial de la bóveda local (nunca el usuario ni la contraseña)." },
  { name: "notes", type: "texto", required: false, example: "Piso 2", description: "Notas libres, hasta 2000 caracteres." },
];
export const sampleHostsFormat: HostsFormat = { fields: sampleHostFields, maxRows: 1000, maxBytes: 5 << 20 };

const templateRows = [
  ["SW-CORE", "10.0.0.1", "22", "ios-xe", "Lab", "core;dc-1", "admin lab", "Piso 2"],
  ["SW-ACC1", "10.0.0.2", "22", "nx-os", "Lab", "acceso", "", ""],
  ["AP-1", "ap1.lab.example.com", "2222", "wlc", "Oficina", "wifi", "", ""],
];
const sampleTemplate = (format: HostFileFormat) => ({
  format,
  filename: `hosts-plantilla.${format}`,
  content: format === "csv"
    ? "\ufeff" + [sampleHostFields.map((f) => f.name), ...templateRows].map((r) => r.join(",")).join("\n") + "\n" // con BOM UTF-8, como el export
    : JSON.stringify({ formato: "macuahuitl-hosts", version: 1, exportado: new Date(t).toISOString(), hosts: templateRows.map((r) => Object.fromEntries(sampleHostFields.map((f, i) => [f.name, f.name === "port" ? Number(r[i]) : f.name === "tags" ? r[i].split(";") : r[i]]))) }),
});

const key = (h: Pick<Host, "address" | "port">) => `${h.address.toLowerCase()}:${h.port || 22}`;

export function fakeInventory(initial: Host[] = sampleHosts) {
  let hosts = initial.map((h) => ({ ...h }));
  let n = 0;
  const find = (id: string) => {
    const h = hosts.find((x) => x.id === id);
    if (!h) throw new Error(`no hay un host de la libreta con id "${id}"`);
    return h;
  };
  const matches = (h: Host, f: HostFilter) => {
    const q = (f.query ?? "").trim().toLowerCase();
    return (!q || [h.address, h.name, h.platform, h.folder, ...h.tags].join("\n").toLowerCase().includes(q)) &&
      (!f.folder || h.folder.toLowerCase() === f.folder.toLowerCase()) && (!f.tag || h.tags.includes(f.tag));
  };
  return {
    listDevices: vi.fn(async (q?: string) => {
      const s = (q ?? "").trim().toLowerCase();
      return s ? { ...sampleDevices, devices: sampleDevices.devices.filter((d) => `${d.address} ${d.hostname} ${d.platform}`.toLowerCase().includes(s)) } : sampleDevices;
    }),
    listHosts: vi.fn(async (f: HostFilter = {}) => hosts.filter((h) => matches(h, f)).sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase())).map((h) => ({ ...h }))),
    saveHost: vi.fn(async (d: Parameters<import("./api").InventoryAPI["saveHost"]>[0]) => {
      if (d.id) find(d.id);
      if (!d.name || d.name.length > 64) throw new Error("el nombre va de 1 a 64 caracteres");
      if (/[\s@/]/.test(d.address) || !d.address) throw new Error(`dirección "${d.address}" inválida`);
      if (hosts.some((h) => h.id !== d.id && h.name.toLowerCase() === d.name.toLowerCase())) throw new Error(`ya hay un host llamado "${d.name}"`);
      if (hosts.some((h) => h.id !== d.id && key(h) === key(d))) throw new Error(`${key(d)} ya está en la libreta`);
      const { credentialLabel = "" } = hosts.find((h) => h.credentialId === d.credentialId) ?? {};
      const h = host({ ...d, id: d.id || String(++n).padStart(32, "0"), address: d.address.toLowerCase(), port: d.port || 22, credentialLabel });
      hosts = d.id ? hosts.map((x) => (x.id === h.id ? h : x)) : [...hosts, h];
      return { id: h.id, warnings: [] as string[] };
    }),
    deleteHost: vi.fn(async (id: string) => {
      find(id);
      hosts = hosts.filter((h) => h.id !== id);
    }),
    exportHosts: vi.fn(async (ids: string[], _path: string, _overwrite: boolean, _format?: HostFileFormat | "") => {
      ids.forEach(find);
      return { count: ids.length || hosts.length, warnings: [] as string[] };
    }),
    previewHostsImport: vi.fn(async (_path: string, _format?: HostFileFormat | "") => sampleHostsImport),
    hostsImportTemplate: vi.fn(async (format: HostFileFormat) => sampleTemplate(format)),
    hostsImportFormat: vi.fn(async () => sampleHostsFormat),
    applyHostsImport: vi.fn(async (_token: string, decisions: HostImportDecision[]) => {
      const conflicts = sampleHostsImport.items.filter((i) => i.state === "conflicto");
      if (conflicts.some((i) => !decisions.some((d) => d.key === i.key))) throw new Error("falta la decisión de un conflicto");
      if (decisions.some((d) => d.action === "renombrar" && conflicts.find((i) => i.key === d.key)?.reason === "direccion")) throw new Error("un conflicto de dirección solo se puede reemplazar u omitir");
      const by = (a: string) => decisions.filter((d) => d.action === a).length;
      const invalid = sampleHostsImport.errors.length;
      return { created: 1, replaced: by("reemplazar"), renamed: by("renombrar"), skipped: by("omitir") + 1 + invalid, invalid }; // el «igual» y las filas inválidas se omiten solos
    }),
  };
}
