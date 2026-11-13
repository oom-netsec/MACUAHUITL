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
}
export interface PackInstallResult { pack: PackInfo; replacedVersion: string } // replacedVersion vacío = era nuevo
export interface PackDetail { pack: PackInfo; readme: string; playbookIds: string[]; scriptIds: string[] }

export interface PacksAPI {
  // Ruta absoluta del .mpack. Un paquete de terceros exige allowUnsigned (el diálogo con aviso); sin él falla con pack.err.unsigned.
  packInstall(path: string, allowUnsigned: boolean): Promise<PackInstallResult>;
  packList(): Promise<PackInfo[]>;
  packShow(id: string): Promise<PackDetail>;
  packRemove(id: string): Promise<number>; // favoritos quitados
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const packsWails = (call: Call): PacksAPI => ({
  packInstall: (path, allowUnsigned) => call("PackInstall", path, allowUnsigned),
  packList: () => call("PackList"),
  packShow: (id) => call("PackShow", id),
  packRemove: (id) => call("PackRemove", id),
});
