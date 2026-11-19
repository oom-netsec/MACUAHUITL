import type { ErrInfo } from "../../lib/coreError";
import type { AcceptedKey } from "../../lib/hostkeys";
// Contrato del módulo con el puente (ui/bridge/transfer.go) y su implementación de Wails.
import { Events } from "@wailsio/runtime";

export type TransferProto = "tftp" | "ftp" | "scp" | "sftp" | "http";

export interface TransferServeParams {
  protocol: TransferProto; listen: string; allowAny: boolean; files: string[]; fromDir: string;
  write: boolean; recvDir: string; allow: string[]; seconds: number; legacySsh: boolean;
  maxFileBytes?: number; maxTotalBytes?: number; passiveMin?: number; passiveMax?: number;
}
// transfer:ready: lo que el usuario necesita para llegar al servidor recién abierto.
export interface TransferReady {
  serverId: string; protocol: TransferProto; listening: string; hint: string; user: string; password: string;
  fingerprints: string[] | null; recvDir: string; fromDir: string; files: string[] | null;
  warnings?: ServerWarning[] | null; // avisos de carpeta (43d-2b): message es texto; cmd, la orden que lo corrige (vacía si no hay una segura)
}
export interface ServerWarning { code: string; message: string; cmd: string }
// Una transferencia o rechazo (JSON de fileserve.Transfer; Duration en nanosegundos).
export interface TransferLine {
  Proto: string; Client: string; File: string; Bytes: number; Duration: number; Result: string;
  Dir?: string; dirCode?: "read" | "write"; Path?: string; SHA256?: string; Error?: string; Rejected?: boolean;
}
export interface TransferEvent { runId: string; ready?: TransferReady; line?: TransferLine; done?: boolean; error?: string; errorInfo?: ErrInfo; cleanup?: string }
export interface TransferServer { serverId: string; protocol: string; listening: string; started: number; write: boolean; recvDir: string; fromDir: string; transfers: number; rejected: number }
export interface TransferResult { path: string; bytes: number; md5: string; sha256: string; verified: string; seconds: number; report: string }
export interface TransferGetParams {
  url: string; destDir: string; credentialId: string; sha256?: string; md5?: string; sha512?: string;
  acceptedHostKeys: string[]; acceptedKeys?: AcceptedKey[]; name?: string; insecure?: boolean; legacySsh?: boolean; maxBytes?: number; seconds?: number;
}
export interface TransferPutParams { url: string; fromDir: string; name: string; credentialId: string; acceptedHostKeys: string[]; acceptedKeys?: AcceptedKey[]; legacySsh?: boolean; maxBytes?: number; seconds?: number }
export interface TransferHintInfo { standardPort: number; nftables: string; remove: string; note?: string; noteCode?: string }


// ---- Explorador remoto, avance y descarga múltiple (Fase 19) ----
export interface TransferBrowseParams {
  url: string; credentialId?: string; path?: string; acceptedHostKeys?: string[]; acceptedKeys?: AcceptedKey[];
  insecure?: boolean; legacySsh?: boolean; maxEntries?: number; seconds?: number;
}
export interface RemoteEntry {
  name: string; // ya saneado: sin caracteres de control ni invisibles
  type: "file" | "dir" | "link" | "other";
  size: number; // bytes; -1 si el servidor no lo dice
  modifiedMs: number; // unix ms; 0 si no la dice
  perms: string; // «rw-r--r--», «0644» o los permisos de MLSD; vacío si no los hay
  downloadable: boolean; // archivo cuyo nombre Get puede pedir (los nombres con espacios no)
  unsafeName: boolean; // el nombre original traía caracteres de control o invisibles: mostrar con aviso
}
// listable=false no es una falla: TFTP no lista, y un SCP sin SFTP tampoco; `reason` es el mensaje para mostrar.
export interface TransferListing {
  listable: boolean; reason: string; reasonCode?: string; reasonArgs?: Record<string, string>; path: string; entries: RemoteEntry[]; truncated: boolean;
  method: "mlsd" | "list" | "sftp" | "http" | "";
}
export interface TransferGetManyParams {
  url: string; // carpeta remota
  names: string[]; // nombres base, hasta 200
  destDir: string; credentialId?: string; acceptedHostKeys?: string[]; acceptedKeys?: AcceptedKey[]; insecure?: boolean; legacySsh?: boolean;
  maxBytes?: number; seconds?: number; // por archivo
}
// Eventos de una ejecución asíncrona (transfer:progress, transfer:file, transfer:finished), todos con el runId que devolvió la llamada.
export interface TransferProgress { runId: string; index: number; count: number; name: string; bytes: number; total: number; bytesPerSec: number } // total 0 = no se conoce; a lo más ~10 por segundo
export interface TransferFileDone { runId: string; index: number; name: string; ok: boolean; error?: string; result?: TransferResult }
export interface TransferFinished { runId: string; ok?: number; failed?: number; canceled?: boolean; error?: string } // ok y failed solo en el lote
export type TransferRunEvent =
  | ({ kind: "progress" } & TransferProgress)
  | ({ kind: "file" } & TransferFileDone)
  | ({ kind: "finished" } & TransferFinished);

// Fase 45b (#196): una transferencia de un servidor abierto o cerrado hace menos de 10 min.
export interface TransferRejection { serverId: string; ip: string; protocol: string; cause: string; name: string; count: number; first: number; last: number; reason: string; reasonCode: string } // ip sin puerto; first/last en unix ms; name vacío si el rechazo fue antes de pedir archivo
export interface TransferSessions { sessions: TransferSession[]; rejections: TransferRejection[] }
export interface TransferSession { id: string; serverId: string; client: string; name: string; direction: "in" | "out"; protocol: string; bytes: number; total: number; bytesPerSec: number; started: number; ended: number; state: "active" | "done" | "failed"; error?: string; errorCode?: string } // total 0 = desconocido; client llega como IP:puerto; started/ended en unix ms, ended 0 = sigue activa

export interface TransferAPI {
  transferServe(p: TransferServeParams): Promise<string>;
  transferStop(serverId: string): Promise<boolean>;
  transferServers(): Promise<TransferServer[]>;
  transferGet(p: TransferGetParams): Promise<TransferResult>;
  transferPut(p: TransferPutParams): Promise<TransferResult>;
  transferHint(protocol: string, ip: string, port: number): Promise<TransferHintInfo>;
  onTransfer(cb: (e: TransferEvent) => void): () => void;
  transferBrowse(p: TransferBrowseParams): Promise<TransferListing>;
  // Como transferGet/transferPut pero con avance: devuelven el runId y el resto llega por onTransferRun.
  transferGetAsync(p: TransferGetParams): Promise<string>;
  transferPutAsync(p: TransferPutParams): Promise<string>;
  transferGetMany(p: TransferGetManyParams): Promise<string>;
  transferCancel(runId: string): Promise<void>;
  onTransferRun(cb: (e: TransferRunEvent) => void): () => void;
  transferSessions(serverId: string): Promise<TransferSessions>; // fase 45b; Unimplemented hasta el bloque 45b-3 del núcleo
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const transferWails = (call: Call): TransferAPI => ({
  transferServe: (p) => call("TransferServe", p),
  transferStop: (id) => call("TransferStop", id),
  transferServers: () => call("TransferServers"),
  transferGet: (p) => call("TransferGet", p),
  transferPut: (p) => call("TransferPut", p),
  transferHint: (proto, ip, port) => call("TransferHint", proto, ip, port),
  onTransfer: (cb) => {
    const a = Events.On("transfer:ready", (e) => { const d = e.data as TransferReady & { runId: string }; cb({ runId: d.runId, ready: d }); });
    const b = Events.On("transfer:msg", (e) => {
      const d = e.data as { runId: string; transfer: string };
      try { cb({ runId: d.runId, line: JSON.parse(d.transfer) as TransferLine }); } catch { /* evento malformado: se ignora */ }
    });
    const c = Events.On("transfer:done", (e) => cb({ ...(e.data as TransferEvent), done: true }));
    return () => { a(); b(); c(); };
  },
  transferBrowse: (p) => call("TransferBrowse", { credentialId: "", path: "", acceptedHostKeys: [], insecure: false, legacySsh: false, maxEntries: 0, seconds: 0, ...p }),
  transferGetAsync: (p) => call("TransferGetAsync", { name: "", sha256: "", md5: "", sha512: "", insecure: false, legacySsh: false, maxBytes: 0, seconds: 0, ...p }),
  transferPutAsync: (p) => call("TransferPutAsync", { legacySsh: false, maxBytes: 0, seconds: 0, ...p }),
  transferGetMany: (p) => call("TransferGetMany", { credentialId: "", acceptedHostKeys: [], insecure: false, legacySsh: false, maxBytes: 0, seconds: 0, ...p }),
  transferCancel: (id) => call("TransferCancel", id),
  transferSessions: async (id) => {
    const r = await call<Partial<TransferSessions> | null>("TransferSessions", id);
    return { sessions: r?.sessions ?? [], rejections: r?.rejections ?? [] };
  },
  onTransferRun: (cb) => {
    const a = Events.On("transfer:progress", (e) => cb({ kind: "progress", ...(e.data as TransferProgress) }));
    const b = Events.On("transfer:file", (e) => cb({ kind: "file", ...(e.data as TransferFileDone) }));
    const c = Events.On("transfer:finished", (e) => cb({ kind: "finished", ...(e.data as TransferFinished) }));
    return () => { a(); b(); c(); };
  },
});
