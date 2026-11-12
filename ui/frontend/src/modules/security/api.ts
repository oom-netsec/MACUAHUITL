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
export interface PkiResult { pem: string; key: string; text: string; certificates?: Certificate[]; labWarning?: boolean }
export interface ExportRequest { format: string; cert: string; chain: string; sealedKey: string; keyPassword: string; exportPassword: string; plainKey: boolean; path: string }

// Fase 30b: lo mismo que dice el texto de cada prueba, con claves estables (sin secretos). Los códigos cerrados van en
// inglés: severity warning|error|info, messageAuthenticator absent|valid|invalid, direction sent|received,
// kind (certificado) certificate|csr.
/** Texto de catálogo: clave, argumentos y el texto en el idioma de la interfaz. */
export interface SecText { key: string; args?: Record<string, string>; text: string }
/** code estable en inglés desde 30c: no_response, invalid_response, blast_radius, ma_invalid, reject (RADIUS); secret, no_response, authen_fail, author_fail, status (TACACS+). Antes eran sin-respuesta, respuesta-invalida, blast-radius, ma-invalido, reject, secreto, authen-fail, author-fail, estado. */
export interface SecFindingData { code: string; severity: "warning" | "error" | "info"; args?: Record<string, string>; message: string }
export interface RadiusExchangeData {
  kind: string; code?: string; rttMs: number; attempts: number; messageAuthenticator?: "absent" | "valid" | "invalid"; error?: SecText; attrs: { name: string; value: string }[];
  /** Fase 30c: solo en MS-CHAPv2: true si el MS-CHAP2-Success verificó al servidor (autenticación mutua). Ausente en los demás métodos. */
  mschap2Verified?: boolean;
}
export interface RadiusReportData { text: string; server: string; method?: string; exchanges: RadiusExchangeData[]; findings: SecFindingData[] }
export interface TacacsStepData {
  kind: string; status?: string; rttMs: number; error?: SecText; prompts: string[]; message?: string; data?: string; avPairs: { direction: "sent" | "received"; value: string }[];
}
export interface TacacsReportData { text: string; server: string; steps: TacacsStepData[]; findings: SecFindingData[] }
export interface CertWarning { code: string; args?: Record<string, string>; message: string }
/** Fechas RFC 3339 UTC; un CSR no trae fechas ni daysLeft ni issuer/serial. signature.valid solo viene en CSR. */
export interface Certificate {
  kind: "certificate" | "csr"; subject: string; issuer?: string; serial?: string; notBefore?: string; notAfter?: string; daysLeft?: number;
  key: { algorithm: string; bits: number; curve?: string; description: string }; signature: { algorithm: string; valid?: boolean };
  san: string[]; keyUsage: string[]; extKeyUsage: string[]; isCa: boolean; selfSigned: boolean; sha1?: string; sha256?: string; warnings: CertWarning[];
}
export interface PkiReportData { text: string; certificates: Certificate[] }

// Fase 30c-A: el decodificador IKE estructurado. Textos y json en el idioma de la interfaz; phase1 y phase2 ∈ established,
// failed, mixed, incomplete, no_data; severity warning|error|info. key es ike.finding.<código> (con .title y .action) y
// explanationKey la de la explicación (con variantes); las evidencias son líneas del equipo.
export interface IkeFindingData {
  code: string; severity: "warning" | "error" | "info"; phase?: number; key: string; explanationKey: string; args?: Record<string, string>;
  title: string; explanation: string; action: string; evidence: string[];
}
export interface IkeProposalData { phase: number; sourceKey: string; sourceArgs?: Record<string, string>; source: string; detail: string; result?: "accepted" | "rejected" }
export interface IkeReportData {
  text: string; json: string; phase1: string; phase2: string; findings: IkeFindingData[]; proposals: IkeProposalData[]; note: string;
}

export interface SecurityAPI {
  /** Como secIkeDecode, con el informe estructurado. */
  secIkeReport?(text: string): Promise<IkeReportData>;
  /** Como secRadius, con el informe estructurado. */
  secRadiusReport?(r: RadiusRequest): Promise<RadiusReportData>;
  secTacacsReport?(r: TacacsRequest): Promise<TacacsReportData>;
  secPkiDecodeReport?(text: string): Promise<PkiReportData>;
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
  secRadiusReport: (r) => call("SecRadiusReport", r),
  secTacacsReport: (r) => call("SecTacacsReport", r),
  secPkiDecodeReport: (t) => call("SecPkiDecodeReport", t),
  secIkeReport: (t) => call("SecIkeReport", t),
});
