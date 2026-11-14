// Contrato del módulo con el puente (ui/bridge/scripts.go) y su implementación de Wails.
// Bóveda de scripts: los del usuario más una biblioteca predefinida, con colecciones (favoritos es la primera), fijados y export/import.
// Un script nunca se aplica a un equipo desde aquí (ADR 0007): la vista lo inserta en la terminal sin Enter.

export type ScriptTech = "l2" | "l3" | "gestion" | "seguridad" | "qos" | "etherchannel" | "wireless" | "diagnostico" | "otro";
export type ScriptPlatform = "ios" | "ios-xe" | "nx-os" | "asa" | "cualquiera";
export type ScriptOrigin = "biblioteca" | "usuario";

export interface ScriptItem {
  id: string; // 32 hex (usuario) o «lib-<nombre>» (biblioteca: no se edita ni se borra)
  name: string; // 1 a 64
  tech: ScriptTech;
  platform: ScriptPlatform;
  description: string; // hasta 512
  commands: string[]; // 1 a 200 líneas de hasta 512, ASCII imprimible
  tags: string[]; // hasta 10, [a-z0-9-]{1,24}
  origin: ScriptOrigin;
  createdMs: number;
  updatedMs: number;
  readOnly: boolean; // ios/ios-xe con solo comandos de lectura (las líneas «!» se ignoran; nx-os, asa y cualquiera: siempre false): Patrol puede correrlo
  favorite: boolean; // está en la colección «favoritos»
  pinned: boolean; // fijado para la barra corta de la terminal (máximo 5, aparte de las colecciones)
  collections: string[]; // IDs de las colecciones que lo contienen (incluye «favoritos» si es favorito)
}

export interface ScriptFilter {
  tech?: ScriptTech | "";
  platform?: ScriptPlatform | ""; // con un valor también entran los «cualquiera»
  tag?: string;
  text?: string; // en nombre, descripción, etiquetas y comandos, sin importar mayúsculas
  onlyFavorites?: boolean;
}

// Lo que se envía al guardar: sin id se crea; con id de un script del usuario se edita.
export type ScriptDraft = Pick<ScriptItem, "name" | "tech" | "platform" | "description" | "commands" | "tags"> & { id?: string };

export type ImportState = "nuevo" | "igual" | "conflicto_id" | "conflicto_nombre";
export type ImportAction = "renombrar" | "reemplazar" | "omitir";

export interface ImportItem {
  script: ScriptItem; // como viene en el archivo
  state: ImportState;
  conflictsWith: string; // ID guardado con el que choca o coincide; vacío si es nuevo
}
export interface ImportPreview { token: string; expiresMs: number; items: ImportItem[]; warnings: string[] } // warnings: p. ej. «archivo sin suma de verificación»
export interface ImportDecision { scriptId: string; action: ImportAction }
export interface ImportResult { created: number; replaced: number; renamed: number; skipped: number }

// ---- Colecciones (fase 29c): listas ordenadas de IDs de script (también «lib-*»), de un solo nivel, sin copias ----
export const FAVORITES_ID = "favoritos"; // la colección por defecto: no se borra ni se renombra, sí se reordena
export const MAX_PINNED = 5;

export interface Collection {
  id: string; // 32 hex, o «favoritos»
  name: string; // 1 a 64, único sin importar mayúsculas
  description: string; // hasta 512
  order: number; // posición entre todas las colecciones, desde 0
  scriptIds: string[]; // en orden; de usuario o de biblioteca
  hiddenScriptIds: string[]; // los de scriptIds que un paquete oculta (siempre arreglo); siguen en la colección
  createdMs: number;
  updatedMs: number;
}
// Sin id se crea; con id se editan nombre y descripción (los scripts van por setCollectionScripts).
export type CollectionDraft = Pick<Collection, "name"> & { id?: string; description?: string };

export type CollectionImportState = "nueva" | "igual" | "fusionar" | "conflicto_id" | "conflicto_nombre";
export interface CollectionImportItem {
  collection: Collection; // como viene en el archivo
  state: CollectionImportState; // «fusionar» solo en favoritos: se le agregan los que falten, sin decisión
  conflictsWith: string; // ID local con el que choca o coincide; vacío si es nueva
}
export interface CollectionsImportPreview {
  token: string;
  expiresMs: number;
  collections: CollectionImportItem[];
  scripts: ImportItem[]; // los scripts de usuario del archivo, con el estado de siempre
  warnings: string[]; // por ejemplo, un «lib-*» que esta biblioteca no trae (se omite de la colección)
}
export interface CollectionsImportResult {
  scriptsCreated: number; scriptsReplaced: number; scriptsRenamed: number; scriptsSkipped: number;
  collectionsCreated: number; collectionsReplaced: number; collectionsRenamed: number; collectionsMerged: number; collectionsSkipped: number;
  warnings: string[];
}

// Plantilla y descripción de los archivos de import: salen de las mismas reglas que validan el import.
export type ImportKind = "scripts" | "colecciones";
export interface ImportFormatField {
  name: string; // «formato», «scripts[].name», «colecciones[].script_ids»
  type: string;
  required: boolean;
  example: string; // JSON, tomado de la plantilla
  description: string;
}

export interface ScriptsAPI {
  // Biblioteca y scripts del usuario juntos, por nombre.
  listScripts(filter?: ScriptFilter): Promise<ScriptItem[]>;
  getScript(id: string): Promise<ScriptItem>;
  saveScript(draft: ScriptDraft): Promise<ScriptItem>;
  deleteScript(id: string): Promise<void>;
  setScriptFavorite(id: string, favorite: boolean): Promise<void>;
  duplicateScript(id: string): Promise<ScriptItem>;
  // Escribe los scripts en una ruta absoluta (el núcleo la crea 0600). Devuelve cuántos exportó. Sin overwrite una ruta
  // que existe da error; pickSavePath ya deja el archivo creado vacío tras confirmar con la persona, así que ahí va true.
  exportScripts(ids: string[], path: string, overwrite: boolean): Promise<number>;
  // Paso 1 del import: valida el archivo y da el estado de cada script. No escribe nada; el token vale 10 minutos.
  previewScriptsImport(path: string): Promise<ImportPreview>;
  // Paso 2: cada conflicto (conflicto_id y conflicto_nombre) necesita una decisión; si falta una, falla y no escribe nada.
  applyScriptsImport(token: string, decisions: ImportDecision[]): Promise<ImportResult>;

  // Todas por orden; la primera vez solo existe «favoritos». setScriptFavorite sigue siendo el atajo para agregar o quitar en ella.
  listCollections(): Promise<Collection[]>;
  getCollection(id: string): Promise<Collection>;
  saveCollection(draft: CollectionDraft): Promise<Collection>;
  deleteCollection(id: string): Promise<void>; // «favoritos» da error
  reorderCollections(ids: string[]): Promise<void>; // debe traer todas (también «favoritos») una sola vez
  // Deja la colección con exactamente esos scripts y en ese orden: agregar, quitar y reordenar de una vez. Un script puede estar en varias.
  setCollectionScripts(id: string, scriptIds: string[]): Promise<Collection>;
  // Fijados para la barra corta de la terminal: el sexto da error con el motivo; borrar el script lo desfija.
  setScriptPinned(id: string, pinned: boolean): Promise<void>;
  listPinnedScripts(): Promise<ScriptItem[]>; // en su orden
  reorderPinnedScripts(ids: string[]): Promise<void>; // debe traer cada fijado una sola vez
  // Colecciones completas más los scripts de usuario que referencian (los de biblioteca van por ID). Ruta absoluta; mismas reglas que exportScripts.
  exportCollections(ids: string[], path: string, overwrite: boolean): Promise<{ collections: number; scripts: number }>;
  // Paso 1: no escribe nada; el token vale 10 minutos y se gasta al aplicar.
  previewCollectionsImport(path: string): Promise<CollectionsImportPreview>;
  // Paso 2, en una sola transacción: cada conflicto (de colecciones y de scripts) necesita su decisión; «favoritos» solo se fusiona u omite.
  applyCollectionsImport(token: string, scriptDecisions: ImportDecision[], collectionDecisions: ImportDecision[]): Promise<CollectionsImportResult>;

  // JSON de ejemplo de un archivo de import, sin sha256 (opcional al importar). La vista previa lo acepta tal cual: todo «nuevo» y solo el aviso de que no trae suma.
  importTemplate(kind: ImportKind): Promise<string>;
  // Los campos del archivo, cabecera incluida, con tipo, si son obligatorios, ejemplo y descripción.
  importFormat(kind: ImportKind): Promise<ImportFormatField[]>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const scriptsWails = (call: Call): ScriptsAPI => ({
  listScripts: (f = {}) => call("ListScripts", { tech: "", platform: "", tag: "", text: "", onlyFavorites: false, ...f }),
  getScript: (id) => call("GetScript", id),
  saveScript: (d) => call("SaveScript", { id: "", ...d }),
  deleteScript: (id) => call("DeleteScript", id),
  setScriptFavorite: (id, favorite) => call("SetScriptFavorite", id, favorite),
  duplicateScript: (id) => call("DuplicateScript", id),
  exportScripts: (ids, path, overwrite) => call("ExportScripts", ids, path, overwrite),
  previewScriptsImport: (path) => call("PreviewScriptsImport", path),
  applyScriptsImport: (token, decisions) => call("ApplyScriptsImport", token, decisions),
  listCollections: () => call("ListCollections"),
  getCollection: (id) => call("GetCollection", id),
  saveCollection: (d) => call("SaveCollection", d.id ?? "", d.name, d.description ?? ""),
  deleteCollection: (id) => call("DeleteCollection", id),
  reorderCollections: (ids) => call("ReorderCollections", ids),
  setCollectionScripts: (id, scriptIds) => call("SetCollectionScripts", id, scriptIds),
  setScriptPinned: (id, pinned) => call("SetScriptPinned", id, pinned),
  listPinnedScripts: () => call("ListPinnedScripts"),
  reorderPinnedScripts: (ids) => call("ReorderPinnedScripts", ids),
  exportCollections: (ids, path, overwrite) => call("ExportCollections", ids, path, overwrite),
  previewCollectionsImport: (path) => call("PreviewCollectionsImport", path),
  applyCollectionsImport: (token, scriptDecisions, collectionDecisions) => call("ApplyCollectionsImport", token, scriptDecisions, collectionDecisions),
  importTemplate: (kind) => call("ImportTemplate", kind),
  importFormat: (kind) => call("ImportFormat", kind),
});
