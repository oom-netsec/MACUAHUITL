// Doble del módulo para pruebas y para trabajar la vista sin núcleo.
import { vi } from "vitest";
import type { PackDetail, PackInfo } from "./api";

export const samplePack: PackInfo = {
  id: "oom/ios-xe", version: "1.0.0", minCore: "0.2.0", name: "IOS-XE, diagnóstico TAC", nameEn: "IOS-XE, TAC diagnostics",
  description: "Playbooks de solo lectura para IOS-XE.", descriptionEn: "Read-only playbooks for IOS-XE.",
  platforms: ["ios-xe"], author: "oom-netsec", license: "Apache-2.0", official: true, playbookCount: 52, scriptCount: 52, shadowed: [], hidden: [],
};

export const sampleThirdParty: PackInfo = { ...samplePack, id: "acme/demo", name: "Demo <b>de terceros</b>", official: false, playbookCount: 1, scriptCount: 1, shadowed: ["ios-xe/acme-a"] };

export const sampleDetail: PackDetail = { pack: samplePack, readme: "# oom/ios-xe\n\nTexto plano <script>no se ejecuta</script>\n", playbookIds: ["ios-xe/l2-stp"], scriptIds: ["lib-l2-stp"] };

const emptyImport = { pack: samplePack, items: [], sha256: "", applied: false, scriptsCreated: 0, scriptsRenamed: 0, scriptsSkipped: 0, playbooksCreated: 0, playbooksRenamed: 0, playbooksSkipped: 0, playbookIds: [] };

export function fakePacks() {
  return {
    packInstall: vi.fn(async () => ({ pack: samplePack, replacedVersion: "" })),
    packInstallHiding: vi.fn(async () => ({ pack: samplePack, replacedVersion: "" })),
    packList: vi.fn(async () => [samplePack, sampleThirdParty]),
    packShow: vi.fn(async () => sampleDetail),
    packRemove: vi.fn(async () => 0),
    packSetItems: vi.fn(async () => samplePack),
    packInspect: vi.fn(async () => ({ pack: samplePack, playbookIds: sampleDetail.playbookIds, scriptIds: sampleDetail.scriptIds, replacedVersion: "", sha256: "a".repeat(64) })),
    packExport: vi.fn(async () => ({ id: "yo/mis", version: "2026.1113.100000", sha256: "", scripts: 0, playbooks: 0, omittedPlaybooks: [] })),
    packImportPreview: vi.fn(async () => emptyImport),
    packImport: vi.fn(async () => ({ ...emptyImport, applied: true })),
  };
}
