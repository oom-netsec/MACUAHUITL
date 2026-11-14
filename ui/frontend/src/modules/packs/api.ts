// Contrato del módulo con el puente (ui/bridge/pack.go) y su implementación de Wails: paquetes de contenido (.mpack,
// ADR 0010). Todo texto del paquete (nombre, descripción, autor, README) es texto plano: la vista lo dibuja sin HTML,
// sin imágenes y sin enlaces clicables. Toda lista llega como arreglo (nunca null).

export interface PackInfo {
  id: string; // «<editor>/<nombre>», p. ej. «oom/ios-xe»
  version: string; minCore: string;
  name: string; nameEn: string; description: string; descriptionEn: string; // texto plano
  platforms: string[]; author: string; license: string;
  official: boolean; // firma oficial válida (se deriva al arrancar); false = de terceros
  playbookCount: number; scriptCount: number;
  shadowed: string[]; // IDs de playbook que uno de los tuyos (config/playbooks) tapa
  hidden: string[]; // fase 32b: IDs de playbook o script que el usuario ocultó
}
export interface PackInstallResult { pack: PackInfo; replacedVersion: string } // replacedVersion vacío = era nuevo
export interface PackDetail { pack: PackInfo; readme: string; playbookIds: string[]; scriptIds: string[] }
export interface PackInspectResult { pack: PackInfo; playbookIds: string[]; scriptIds: string[]; replacedVersion: string; sha256: string }

// Fase 32c: paquete personal.
export interface PackExportRequest {
  editorName: string; scriptIds: string[]; includePlaybooks: boolean; license: string; path: string; overwrite: boolean;
  name: string; nameEn: string; description: string; descriptionEn: string; author: string;
}
export interface PackExportResult { id: string; version: string; sha256: string; scripts: number; playbooks: number; omittedPlaybooks: string[] }
export interface PackImportItem { kind: string; id: string; name: string; state: string; conflictsWith: string } // kind: script|playbook; state: nuevo|igual|conflicto_id|conflicto_nombre
export interface PackImportDecision { itemId: string; action: string } // renombrar | omitir
export interface PackImportResult {
  pack: PackInfo; items: PackImportItem[]; sha256: string; applied: boolean;
  scriptsCreated: number; scriptsRenamed: number; scriptsSkipped: number; playbooksCreated: number; playbooksRenamed: number; playbooksSkipped: number; playbookIds: string[];
}

export interface PacksAPI {
  // Ruta absoluta del .mpack. Un paquete de terceros exige allowUnsigned (el diálogo con aviso); sin él falla con pack.err.unsigned.
  // sha256 es obligatorio: el de packInspect (si falta o no coincide con el archivo, el núcleo no instala).
  packInstall(path: string, allowUnsigned: boolean, sha256: string): Promise<PackInstallResult>;
  // Con la selección del diálogo: hide = IDs que quedan ocultos; replaceHidden = hide es el conjunto exacto.
  packInstallHiding(path: string, allowUnsigned: boolean, hide: string[], replaceHidden: boolean, sha256: string): Promise<PackInstallResult>;
  packList(): Promise<PackInfo[]>;
  packShow(id: string): Promise<PackDetail>;
  packRemove(id: string): Promise<number>; // favoritos quitados
  packSetItems(packId: string, hide: string[], show: string[]): Promise<PackInfo>; // hide y show no pueden ir los dos vacíos
  packInspect(path: string, allowUnsigned: boolean): Promise<PackInspectResult>; // vista previa: no instala nada
  packExport(req: PackExportRequest): Promise<PackExportResult>;
  packImportPreview(path: string): Promise<PackImportResult>;
  packImport(path: string, sha256: string, decisions: PackImportDecision[]): Promise<PackImportResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const packsWails = (call: Call): PacksAPI => ({
  packInstall: (path, allowUnsigned, sha256) => call("PackInstall", path, allowUnsigned, sha256),
  packInstallHiding: (path, allowUnsigned, hide, replaceHidden, sha256) => call("PackInstallHiding", path, allowUnsigned, hide, replaceHidden, sha256),
  packList: () => call("PackList"),
  packShow: (id) => call("PackShow", id),
  packRemove: (id) => call("PackRemove", id),
  packSetItems: (packId, hide, show) => call("PackSetItems", packId, hide, show),
  packInspect: (path, allowUnsigned) => call("PackInspect", path, allowUnsigned),
  packExport: (req) => call("PackExport", req),
  packImportPreview: (path) => call("PackImportPreview", path),
  packImport: (path, sha256, decisions) => call("PackImport", path, sha256, decisions),
});
