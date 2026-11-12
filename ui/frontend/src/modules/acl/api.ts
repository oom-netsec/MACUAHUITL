// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export interface AclRule { action: string; protocol: string; source: string; destination: string; sourcePorts: string; destinationPorts: string; log: boolean; established: boolean; remark: string }
export interface Acl { name: string; rules: AclRule[] }
export interface AclFinding { index: number; kind: string; detail: string; detailKey?: string; detailArgs?: Record<string, string> }

export interface AclAPI {
  aclImport(vendor: string, text: string): Promise<Acl>;
  aclAnalyze(acl: Acl): Promise<AclFinding[]>;
  aclGenerate(vendor: string, acl: Acl): Promise<string>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const aclWails = (call: Call): AclAPI => ({
  aclImport: (v, t) => call("AclImport", v, t),
  aclAnalyze: (a) => call("AclAnalyze", a),
  aclGenerate: (v, a) => call("AclGenerate", v, a),
});
