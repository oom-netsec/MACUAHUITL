// Doble del módulo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import type { TransferEvent, TransferListing, TransferResult, TransferRunEvent } from "./api";

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
      standardPort: 69, nftables: `nft add rule ip macuahuitl_${p}_${port} pre ip daddr ${ip} udp dport 69 redirect to :${port}`, setcap: "", remove: `sudo nft delete table ip macuahuitl_${p}_${port}`,
    })),
    onTransfer: (cb: (e: TransferEvent) => void) => (evs.add(cb), () => evs.delete(cb)),
    emitTransfer: (e: TransferEvent) => evs.forEach((cb) => cb(e)),
    transferBrowse: vi.fn(async () => sampleListing),
    transferGetAsync: vi.fn(async () => "run-1"),
    transferPutAsync: vi.fn(async () => "run-1"),
    transferGetMany: vi.fn(async () => "run-1"),
    transferCancel: vi.fn(async () => {}),
    onTransferRun: (cb: (e: TransferRunEvent) => void) => (runs.add(cb), () => runs.delete(cb)),
    emitTransferRun: (e: TransferRunEvent) => runs.forEach((cb) => cb(e)),
  };
}
