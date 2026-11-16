// Sistema donde corre la app. Wails lo inyecta en window._wails.environment antes de cargar la página (lo mismo que lee
// System.IsWindows del runtime); se lee directo porque las pruebas simulan el runtime sin System. Fuera de Wails (vista
// previa, pruebas): Linux.
type WailsEnv = { _wails?: { environment?: { OS?: string } } };
let override: string | undefined;

export const isWindows = () => (override ?? (window as unknown as WailsEnv)._wails?.environment?.OS) === "windows";

/** Solo pruebas: fija el sistema; undefined vuelve al de Wails. */
export function setOSForTests(os: string | undefined) { override = os; }
