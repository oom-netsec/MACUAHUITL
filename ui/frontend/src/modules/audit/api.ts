// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
// La API solo ofrece verificar la cadena; exportar sigue siendo por la CLI.
export const AUDIT_EXPORT_CMD = "mctl audit export";

export interface AuditAPI {
  auditVerify(): Promise<{ intact: boolean; firstBroken: number; head: string }>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const auditWails = (call: Call): AuditAPI => ({
  auditVerify: () => call("AuditVerify"),
});
