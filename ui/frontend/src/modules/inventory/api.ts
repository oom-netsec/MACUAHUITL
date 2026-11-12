// Contrato del módulo con el puente (ui/bridge/inventory.go) y su implementación de Wails.
// Equipos que la app ya conoce, para los selectores y la lista de IP permitidas, y la libreta de hosts (fase 29b):
// los que el usuario agrega a mano son la fuente «manual» del mismo inventario, no una segunda lista.
// Una credencial es siempre la referencia (credentialId) a la bóveda; nunca un secreto.

export type DeviceSource = "patrol" | "flota" | "respaldos" | "manual";

export interface KnownDevice {
  address: string; // vacío si solo se conoce por sus respaldos: no sirve para una lista de IP
  hostname: string;
  platform: string; // la que detectó Patrol (ios-xe, nx-os…); vacío si no se sabe
  lastSeenMs: number; // unix ms de la evidencia más reciente; 0 = nunca se alcanzó
  sources: DeviceSource[]; // patrol: objetivo de un trabajo; flota: tiene evidencia; respaldos: tiene respaldos; manual: está en la libreta
  // Con «manual» en sources: id es el del host de la libreta (con él se edita o se borra), name su nombre (también es hostname),
  // y se fusionó por dirección con lo descubierto: el nombre y la plataforma del host mandan. Sin «manual»: id es la dirección o «nombre:<host>».
  id: string;
  name: string; // vacío si no hay host manual
  port: number; // 0 si no hay host manual
  folder: string; // un solo nivel; vacío = sin carpeta
  tags: string[];
  credentialId: string;
  credentialLabel: string; // solo lectura; vacía si no hay credencial, la bóveda está cerrada o la credencial ya no existe
  notes: string;
}
export interface KnownDevices { devices: KnownDevice[]; warnings: string[] }

// ---- Libreta de hosts ----

export type HostPlatform = "" | "ios" | "ios-xe" | "nx-os" | "asa" | "iosxr" | "wlc"; // vacío = sin definir

export interface Host {
  id: string; // 32 hex; vacío al crear
  name: string; // 1 a 64, sin espacios en los extremos; único sin importar mayúsculas
  address: string; // IP o nombre DNS, sin usuario, esquema, puerto ni ruta; se guarda en minúsculas
  port: number; // 1 a 65535; 0 al guardar = 22. Dirección y puerto no se repiten
  platform: HostPlatform;
  folder: string; // un solo nivel: [A-Za-z0-9 _.-]{1,48}; vacío = sin carpeta
  tags: string[]; // hasta 10, [a-z0-9-]{1,24}
  credentialId: string; // id de la bóveda; vacío = sin credencial
  credentialLabel: string; // solo lectura: al guardar se ignora
  notes: string; // hasta 2000
}
// Lo que se envía al guardar: sin id se crea; con el id de un host de la libreta se edita.
export type HostDraft = Omit<Host, "id" | "credentialLabel"> & { id?: string };
export interface HostFilter { query?: string; folder?: string; tag?: string }
// warnings: p. ej. la bóveda está cerrada y la credencial se guardó sin validar.
export interface SaveHostResult { id: string; warnings: string[] }
// warnings: hosts cuya credencial no se pudo traducir a etiqueta (bóveda cerrada o credencial borrada): salen sin credencial.
export interface ExportHostsResult { count: number; warnings: string[] }

export type HostImportState = "nuevo" | "igual" | "conflicto";
// Solo en conflicto: direccion = misma dirección y puerto con otros datos (reemplazar u omitir); nombre = mismo nombre en otra dirección (también renombrar).
export type HostImportReason = "" | "direccion" | "nombre";
export type HostImportAction = "renombrar" | "reemplazar" | "omitir";
export interface HostImportItem {
  host: Host; // como viene en el archivo: sin credentialId y con su credentialLabel
  key: string; // «dirección:puerto» (IPv6 sin corchetes): identifica al host en las decisiones
  state: HostImportState;
  reason: HostImportReason;
  conflictsWith: string; // id del host guardado con el que choca o coincide; vacío si es nuevo
  credentialMissing: boolean; // trae etiqueta pero no hay (o hay varias) credencial con ella: quedaría sin credencial
}
// Una fila (CSV) o entrada (JSON) inválida. No bloquea las demás: al aplicar cuenta como omitida.
export interface HostImportError {
  line: number; // CSV: línea del archivo (el encabezado es la 1); JSON: posición, desde 1, dentro de «hosts»
  field: string; // name, address, port, platform, folder, tags, credential_label, notes; vacío = la fila entera (columnas de menos, comillas, entrada ilegible)
  reason: string;
}
export type HostFileFormat = "csv" | "json";
export interface HostsImportPreview {
  token: string;
  expiresMs: number;
  format: HostFileFormat; // el detectado
  items: HostImportItem[]; // solo las filas válidas
  errors: HostImportError[]; // las inválidas
  warnings: string[]; // p. ej. «archivo sin suma de verificación» (JSON sin sha256)
}
export interface HostImportDecision { key: string; action: HostImportAction }
export interface HostsImportResult { created: number; replaced: number; renamed: number; skipped: number; invalid: number } // skipped incluye los igual y las inválidas; invalid es el subconjunto inválido

export interface HostsTemplate { format: HostFileFormat; filename: string; content: string } // el JSON va sin sha256
export interface HostField {
  name: string; // columna del CSV y clave del JSON
  type: "texto" | "entero" | "lista";
  required: boolean;
  example: string;
  description: string;
}
export interface HostsFormat { fields: HostField[]; maxRows: number; maxBytes: number } // fields en el orden del encabezado del CSV

export interface InventoryAPI {
  // query filtra por dirección, nombre, plataforma, carpeta o etiqueta (sin importar mayúsculas); vacío = todos.
  listDevices(query?: string): Promise<KnownDevices>;
  // Solo los hosts de la libreta con SUS valores (dirección, puerto, plataforma…), sin fusionar con lo descubierto: es lo que se edita
  // (listDevices sí trae la plataforma que detectó Patrol; guardar desde esa fila la fijaría en el host). Por nombre sin importar mayúsculas
  // de Unicode. query busca solo en los valores del host (dirección, nombre, plataforma, carpeta, etiquetas); folder se compara sin importar mayúsculas; tag es exacta.
  listHosts(filter?: HostFilter): Promise<Host[]>;
  saveHost(draft: HostDraft): Promise<SaveHostResult>;
  // No borra la evidencia de las otras fuentes (patrol, flota, respaldos).
  deleteHost(id: string): Promise<void>;
  // Escribe los hosts (ninguno = todos, hasta 1000) en una ruta absoluta (el núcleo la crea 0600). La credencial viaja solo como su etiqueta.
  // format: csv o json; vacío = por la extensión de la ruta (.csv / .json), y sin ninguna de las dos falla.
  // Sin overwrite una ruta que existe da error; pickSavePath ya deja el archivo creado vacío tras confirmar, así que ahí va true.
  exportHosts(ids: string[], path: string, overwrite: boolean, format?: HostFileFormat | ""): Promise<ExportHostsResult>;
  // Paso 1 del import: valida el archivo y da el estado de cada fila válida y el error de cada inválida. No escribe nada; el token vale 10 minutos y un solo uso.
  // format: csv o json; vacío = por la extensión de la ruta.
  previewHostsImport(path: string, format?: HostFileFormat | ""): Promise<HostsImportPreview>;
  // Paso 2: cada conflicto necesita una decisión (renombrar solo si reason = nombre); si falta una o no cabe, falla y no escribe nada.
  // Las filas inválidas no necesitan decisión: no se aplican y cuentan como omitidas.
  applyHostsImport(token: string, decisions: HostImportDecision[]): Promise<HostsImportResult>;
  // Archivo de ejemplo (encabezado y 3 filas válidas) para que la persona lo baje y lo llene; pasa limpio por previewHostsImport.
  hostsImportTemplate(format: HostFileFormat): Promise<HostsTemplate>;
  // Descripción de los campos del archivo, de la misma tabla que lo valida.
  hostsImportFormat(): Promise<HostsFormat>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const inventoryWails = (call: Call): InventoryAPI => ({
  listDevices: (q = "") => call("ListDevices", q),
  listHosts: (f = {}) => call("ListHosts", f.query ?? "", f.folder ?? "", f.tag ?? ""),
  saveHost: (d) => call("SaveHost", { id: "", credentialLabel: "", ...d }),
  deleteHost: (id) => call("DeleteHost", id),
  exportHosts: (ids, path, overwrite, format = "") => call("ExportHosts", ids, path, overwrite, format),
  previewHostsImport: (path, format = "") => call("PreviewHostsImport", path, format),
  applyHostsImport: (token, decisions) => call("ApplyHostsImport", token, decisions),
  hostsImportTemplate: (format) => call("HostsImportTemplate", format),
  hostsImportFormat: () => call("HostsImportFormat"),
});
