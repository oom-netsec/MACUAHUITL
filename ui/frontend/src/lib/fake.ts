// Doble del núcleo para pruebas: registra llamadas y permite emitir eventos.
import { vi } from "vitest";
import { fakePorts } from "../modules/ports/fake";
import { fakeSnippets } from "../modules/snippets/fake";
import { fakeCredRotate } from "../modules/credrotate/fake";
import { fakeBackup } from "../modules/backup/fake";
import { fakeTerminal } from "../modules/terminal/fake";
import { fakeVault } from "../modules/vault/fake";
import { fakeAudit } from "../modules/audit/fake";
import { fakePatrol } from "../modules/patrol/fake";
import { fakeDiag } from "../modules/diag/fake";
import { fakeAcl } from "../modules/acl/fake";
import { fakeTools } from "../modules/tools/fake";
import { fakeSecurity } from "../modules/security/fake";
import { fakeChange } from "../modules/change/fake";
import { fakeVisibility } from "../modules/visibility/fake";
import { fakeAnalysis } from "../modules/analysis/fake";
import { fakeCalc } from "../modules/calc/fake";
import { fakeConsole } from "../modules/console/fake";
import { fakeField } from "../modules/field/fake";
import { fakeFleet } from "../modules/fleet/fake";
import { fakeAdhoc } from "../modules/adhoc/fake";
import { fakeDrift } from "../modules/drift/fake";
import { fakeCleaner } from "../modules/cleaner/fake";
import { fakeForensic } from "../modules/forensic/fake";
import { fakeTransfer } from "../modules/transfer/fake";
import { fakeMetrics } from "../modules/metrics/fake";
import { fakeInventory } from "../modules/inventory/fake";
import { fakeScripts } from "../modules/scripts/fake";
import { fakeSettings } from "../modules/settings/fake";
import { fakePacks } from "../modules/packs/fake";
import type { CoreAPI, CoreStatus } from "./core";

export function fakeCore(over: Partial<CoreAPI> = {}) {
  const status = new Set<(s: CoreStatus) => void>();
  const prefs = new Map<string, string>();
  const drops = new Set<(e: { target: string; paths: string[] }) => void>();
  const core = {
    coreStatus: vi.fn(async () => "connected" as CoreStatus),
    onStatus: (cb: (s: CoreStatus) => void) => (status.add(cb), () => status.delete(cb)),
    // Preferencias en memoria: sobreviven mientras viva el doble, como el store del núcleo.
    getPreference: vi.fn(async (k: string) => prefs.get(k) ?? ""),
    setPreference: vi.fn(async (k: string, v: string) => { prefs.set(k, v); }),
    pickPath: vi.fn(async () => ""),
    copyText: vi.fn(async () => {}),
    saveFile: vi.fn(async (name: string) => `/home/u/Descargas/${name}`),
    pickSavePath: vi.fn(async (name: string) => `/home/u/Descargas/${name}`),
    writeFile: vi.fn(async () => {}),
    pasteText: vi.fn(async () => ""),
    confirmPaste: vi.fn(async () => true),
    onFilesDropped: (cb: (e: { target: string; paths: string[] }) => void) => (drops.add(cb), () => { drops.delete(cb); }),
    emitFilesDropped: (e: { target: string; paths: string[] }) => drops.forEach((cb) => cb(e)),
    ...fakeVault(),
    ...fakeAudit(),
    ...fakePatrol(),
    ...fakeDiag(),
    ...fakeAcl(),
    ...fakeTools(),
    ...fakeSecurity(),
    ...fakeChange(),
    ...fakeVisibility(),
    ...fakeAnalysis(),
    ...fakeCalc(),
    ...fakeField(),
    ...fakeConsole(),
    ...fakeFleet(),
    ...fakeAdhoc(),
    ...fakeDrift(),
    ...fakeCleaner(),
    ...fakePorts(),
    ...fakeSnippets(),
    ...fakeCredRotate(),
    ...fakeBackup(),
    ...fakeTerminal(),
    ...fakeForensic(),
    ...fakeTransfer(),
    ...fakeMetrics(),
    ...fakeInventory(),
    ...fakeScripts(),
    ...fakeSettings(),
    ...fakePacks(),
    ...over,
    emitStatus: (s: CoreStatus) => status.forEach((cb) => cb(s)),
  };
  return core;
}
