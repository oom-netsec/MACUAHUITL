// Contrato del módulo con el puente (ui/bridge) y su implementación de Wails.
export interface RadiusRequest {
  host: string; authPort: number; acctPort: number; secretCredId: string; secret: string; credId: string; username: string; password: string;
  method: string; nasIp: string; nasId: string; portType: string; serviceType: string; called: string; calling: string; statusServer: boolean; accounting: boolean;
}
export interface TacacsRequest {
  host: string; port: number; secretCredId: string; secret: string; credId: string; username: string; password: string;
  authenType: string; command: string; accounting: boolean;
}
export interface CsrRequest { cn: string; o: string; ou: string; l: string; st: string; c: string; dns: string[]; ips: string[]; algorithm: string; sealedKey: string; keyPassword: string }
export interface PkiResult { pem: string; key: string; text: string }
export interface ExportRequest { format: string; cert: string; chain: string; sealedKey: string; keyPassword: string; exportPassword: string; plainKey: boolean; path: string }

export interface SecurityAPI {
  secRadius(r: RadiusRequest): Promise<string>;
  secTacacs(r: TacacsRequest): Promise<string>;
  secIkeDecode(text: string): Promise<string>;
  secPkiDecode(text: string): Promise<string>;
  secPkiCsr(r: CsrRequest): Promise<PkiResult>;
  secPkiCaInit(name: string, days: number, algorithm: string, keyPassword: string): Promise<PkiResult>;
  secPkiCaSign(caCert: string, caKey: string, caKeyPassword: string, csr: string, profile: string, days: number): Promise<PkiResult>;
  secPkiExport(r: ExportRequest): Promise<string>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const securityWails = (call: Call): SecurityAPI => ({
  secRadius: (r) => call("SecRadius", r),
  secTacacs: (r) => call("SecTacacs", r),
  secIkeDecode: (t) => call("SecIkeDecode", t),
  secPkiDecode: (t) => call("SecPkiDecode", t),
  secPkiCsr: (r) => call("SecPkiCsr", r),
  secPkiCaInit: (n, d, a, p) => call("SecPkiCaInit", n, d, a, p),
  secPkiCaSign: (c, k, p, r, prof, d) => call("SecPkiCaSign", c, k, p, r, prof, d),
  secPkiExport: (r) => call("SecPkiExport", r),
});
