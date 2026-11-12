// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
/** Clave del catálogo del núcleo (calc.title.*, calc.col.*, calc.row.*, calc.note.*) con sus argumentos. */
export interface CalcKey { key: string; args?: Record<string, string> }
/**
 * Fase 30c-A: celda con palabras como código cerrado (veredicto, límite, tipo de dirección, clase DSCP, paso de BGP,
 * capa de MTU, sí/no): col cuenta desde 0 y key es calc.val.*; la celda de rows ya viene en el idioma de la interfaz.
 * rowCoded trae una lista por fila (vacía si ninguna celda es un código) y falta si la tabla no tiene ninguna.
 */
export interface CalcCoded { col: number; key: string; args?: Record<string, string> }
/**
 * Fase 30b: los campos con clave son opcionales (un núcleo anterior no los manda). columns trae una clave por celda de
 * head; rowLabels, una por fila (key "" si la primera celda es un dato); titleArgs son los valores del título.
 */
export interface CalcTable { title: string; head: string[]; rows: string[][]; titleKey?: string; titleArgs?: Record<string, string>; columns?: CalcKey[]; rowLabels?: CalcKey[]; rowCoded?: CalcCoded[][] }
export interface CalcResult { text: string; tables: CalcTable[]; notes: string[]; notesStructured?: CalcKey[] }

export interface CalcAPI {
  calc(kind: string, req: object): Promise<CalcResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const calcWails = (call: Call): CalcAPI => ({
  calc: (k, r) => call("Calc", k, JSON.stringify(r)),
});
