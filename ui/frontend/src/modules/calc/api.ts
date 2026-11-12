// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export interface CalcTable { title: string; head: string[]; rows: string[][] }
export interface CalcResult { text: string; tables: CalcTable[]; notes: string[] }

export interface CalcAPI {
  calc(kind: string, req: object): Promise<CalcResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const calcWails = (call: Call): CalcAPI => ({
  calc: (k, r) => call("Calc", k, JSON.stringify(r)),
});
