// Contrato del módulo con el puente (ui/bridge/prefs.go) y su implementación de Wails.
// Preferencias tipadas del núcleo (fase 29e): carpeta base de salidas y defaults de archivo de syslog, traps y flujos.

export interface CorePrefs {
  outputsDir: string; // "" = la de fábrica
  // Defaults de archivo cuando la vista no manda opciones; 0 o "" = el de fábrica. Rangos: rotateMb 1-1024, rotateMin 1-10080, maxFiles 1-1000.
  rotateMb: number;
  rotateMin: number;
  maxFiles: number;
  format: "" | "texto" | "crudo" | "jsonl";
}

export interface CorePrefsState extends CorePrefs {
  outputsDirEffective: string; // la carpeta que rige hoy
  outputsDirDefault: string;
  // Solo al guardar un cambio de carpeta: aplica a lo que empiece después y los datos anteriores no se mueven.
  note: string;
}

// El error de una carpeta rechazada empieza con «prefs.outputs.<motivo>: » (relativa, punto_punto, no_existe, ilegible,
// no_directorio, otro_dueno, reservada, permisos, no_escribible); el paso de idioma (fase 30a) lo traduce por ese código.
export interface SettingsAPI {
  getCorePrefs(): Promise<CorePrefsState>;
  // Reemplaza todo: lo que va en 0 o vacío vuelve al de fábrica.
  setCorePrefs(p: CorePrefs): Promise<CorePrefsState>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const settingsWails = (call: Call): SettingsAPI => ({
  getCorePrefs: () => call("GetCorePrefs"),
  setCorePrefs: (p) => call("SetCorePrefs", { outputsDir: p.outputsDir, rotateMb: p.rotateMb, rotateMin: p.rotateMin, maxFiles: p.maxFiles, format: p.format }),
});
