// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export interface ChangeSpec { name: string; targets: { address: string; port?: number }[]; defaultCredentialId: string; outputDir: string }
export interface ChangeSummary { id: string; name: string; preJobId: string; preState: string; postJobId: string; postState: string }
export interface CaptureResult { jobId: string; armed: boolean; detail: string }
export interface Report { json: string; text: string }
export interface UpgradeRequest { outputs: string; image: string; size: number; md5: string; verify: string }
export interface Topo { text: string; json: string; svg: string }

export interface ChangeAPI {
  changeCreate(spec: ChangeSpec): Promise<string>;
  changeCapture(changeId: string, phase: "pre" | "post", accept: string[], exclude: string[]): Promise<CaptureResult>;
  listChanges(): Promise<ChangeSummary[]>;
  changeReport(changeId: string, preDir: string, postDir: string): Promise<Report>;
  upgradeCheck(r: UpgradeRequest): Promise<Report>;
  complianceCheck(config: string, template: string): Promise<Report>;
  topoBuild(jobOrDir: string, pcap: string): Promise<Topo>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const changeWails = (call: Call): ChangeAPI => ({
  changeCreate: (s) => call("ChangeCreate", JSON.stringify(s)),
  changeCapture: (id, p, a, x) => call("ChangeCapture", id, p, a, x),
  listChanges: () => call("ListChanges"),
  changeReport: (id, pre, post) => call("ChangeReport", id, pre, post),
  upgradeCheck: (r) => call("UpgradeCheck", r),
  complianceCheck: (c, t) => call("ComplianceCheck", c, t),
  topoBuild: (j, p) => call("TopoBuild", j, p),
});
