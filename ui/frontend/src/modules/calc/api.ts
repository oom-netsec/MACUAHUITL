// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
/** Clave del catálogo del núcleo (calc.title.*, calc.col.*, calc.row.*, calc.note.*) con sus argumentos. */
export interface CalcKey { key: string; args?: Record<string, string> }
/**
 * Fase 30b: los campos con clave son opcionales (un núcleo anterior no los manda). columns trae una clave por celda de
 * head; rowLabels, una por fila (key "" si la primera celda es un dato); titleArgs son los valores del título.
 */
export interface CalcTable { title: string; head: string[]; rows: string[][]; titleKey?: string; titleArgs?: Record<string, string>; columns?: CalcKey[]; rowLabels?: CalcKey[] }
export interface CalcResult { text: string; tables: CalcTable[]; notes: string[]; notesStructured?: CalcKey[] }

export interface CalcAPI {
  calc(kind: string, req: object): Promise<CalcResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const calcWails = (call: Call): CalcAPI => ({
  calc: (k, r) => call("Calc", k, JSON.stringify(r)),
});
