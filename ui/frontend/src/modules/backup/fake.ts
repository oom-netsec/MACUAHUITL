// Doble de Respaldos para pruebas.
import { vi } from "vitest";
import type { BackupCollect, BackupDiff, BackupEntry, BackupList, RestoreResult } from "./api";

export const sampleEntry = (over: Partial<BackupEntry> = {}): BackupEntry =>
  ({ id: "SW1_192.0.2.1/20261106T100000Z-running", device: "SW1_192.0.2.1", kind: "running", at: "2026-11-06T10:00:00Z", bytes: 1200, masked: true, ...over });

export const sampleRestore: RestoreResult = {
  planId: "rs1",
  plan: {
    function: "restore-diff",
    devices: [{
      device: "192.0.2.1",
      pre: ["show running-config"],
      apply: ["no ntp server 10.0.0.1", "ntp server 10.0.0.2", "interface GigabitEthernet1/0/1", "description PC-contabilidad"],
      rollback: ["no ntp server 10.0.0.2", "ntp server 10.0.0.1", "interface GigabitEthernet1/0/1", "description PC-ventas"],
      post: ["show running-config"],
      expect: [{ command: "show running-config", line: "interface GigabitEthernet1/0/1\u001fdescription PC-contabilidad", present: true }],
    }],
  },
};

export function fakeBackup() {
  return {
    assistPlanRestore: vi.fn(async () => sampleRestore),
    backupStart: vi.fn(async () => ({ jobId: "j1", armed: true, detail: "" })),
    backupCollect: vi.fn(async () => ({ state: "completed", done: true, saved: [], skipped: 0, pruned: 0, warnings: [] }) as BackupCollect),
    backupList: vi.fn(async () => ({ backups: [], masked: false }) as BackupList),
    backupGet: vi.fn(async () => ({ meta: sampleEntry(), text: "" })),
    backupDiff: vi.fn(async () => ({ from: sampleEntry(), to: sampleEntry(), added: 0, removed: 0, changes: [], ignored: [], masked: false }) as BackupDiff),
  };
}
