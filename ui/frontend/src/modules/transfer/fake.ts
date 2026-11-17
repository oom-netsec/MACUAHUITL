// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { TransferSession, TransferEvent, TransferListing, TransferResult, TransferRunEvent } from "./api";

export const okResult: TransferResult = { path: "/o/recibidos/c4.bin", bytes: 1024, md5: "a".repeat(32), sha256: "b".repeat(64), verified: "", seconds: 1.5, report: "guardado" };

const t0 = Date.UTC(2026, 10, 6, 10, 15, 0);
// Carpeta remota de ejemplo: una subcarpeta, una imagen grande, una config con espacios en el nombre (no descargable) y un nombre hostil.
export const sampleListing: TransferListing = {
  listable: true, reason: "", path: "/imagenes", truncated: false, method: "mlsd",
  entries: [
    { name: "respaldos", type: "dir", size: -1, modifiedMs: t0 - 86_400_000, perms: "0755", downloadable: false, unsafeName: false },
    { name: "c9300-universalk9.17.09.04a.SPA.bin", type: "file", size: 1_288_490_188, modifiedMs: t0, perms: "rw-r--r--", downloadable: true, unsafeName: false },
    { name: "r1.cfg", type: "file", size: 12_288, modifiedMs: t0, perms: "rw-r--r--", downloadable: true, unsafeName: false },
    { name: "sala de juntas.cfg", type: "file", size: 512, modifiedMs: 0, perms: "", downloadable: false, unsafeName: false },
    { name: "evil?gnp.exe", type: "file", size: 7, modifiedMs: 0, perms: "", downloadable: false, unsafeName: true },
  ],
};
export const noListing: TransferListing = { listable: false, reason: "este servidor no permite listar: TFTP no tiene comando para listar carpetas", path: "", entries: [], truncated: false, method: "" };

// Una activa, una completa y una fallida (contrato provisional, fase 45).
export const sampleSessions = (now = Date.now()): TransferSession[] => [
  { id: "t1", serverId: "s1", client: "192.0.2.21:50123", ended: 0, name: "c9300-universalk9.17.09.04a.SPA.bin", direction: "out", protocol: "tftp", bytes: 412_000_000, total: 1_180_000_000, bytesPerSec: 9_800_000, started: now - 40_000, state: "active" },
  { id: "t2", serverId: "s1", client: "[2001:db8::22]:50124", name: "running-SW1.cfg", direction: "in", protocol: "tftp", bytes: 18_204, total: 18_204, bytesPerSec: 0, started: now - 90_000, ended: now - 89_000, state: "done" },
  { id: "t3", serverId: "s1", client: "192.0.2.23:50125", name: "backup.cfg", direction: "in", protocol: "tftp", bytes: 512, total: 0, bytesPerSec: 0, started: now - 60_000, ended: now - 59_000, state: "failed", error: "tiempo agotado" },
];

export function fakeTransfer() {
  const evs = new Set<(e: TransferEvent) => void>();
  const runs = new Set<(e: TransferRunEvent) => void>();
  return {
    transferServe: vi.fn(async () => "r1"),
    transferStop: vi.fn(async () => true),
    transferServers: vi.fn(async () => []),
    transferGet: vi.fn(async () => okResult),
    transferPut: vi.fn(async () => okResult),
    transferHint: vi.fn(async (p: string, ip: string, port: number) => ({
      standardPort: 69, nftables: `nft add rule ip macuahuitl_${p}_${port} pre ip daddr ${ip} udp dport 69 redirect to :${port}`, remove: `sudo nft delete table ip macuahuitl_${p}_${port}`,
    })),
    onTransfer: (cb: (e: TransferEvent) => void) => (evs.add(cb), () => evs.delete(cb)),
    emitTransfer: (e: TransferEvent) => evs.forEach((cb) => cb(e)),
    transferBrowse: vi.fn(async () => sampleListing),
    transferGetAsync: vi.fn(async () => "run-1"),
    transferPutAsync: vi.fn(async () => "run-1"),
    transferGetMany: vi.fn(async () => "run-1"),
    transferCancel: vi.fn(async () => {}),
    listTransferSessions: vi.fn(async (_id: string): Promise<TransferSession[]> => []),
    onTransferRun: (cb: (e: TransferRunEvent) => void) => (runs.add(cb), () => runs.delete(cb)),
    emitTransferRun: (e: TransferRunEvent) => runs.forEach((cb) => cb(e)),
  };
}
