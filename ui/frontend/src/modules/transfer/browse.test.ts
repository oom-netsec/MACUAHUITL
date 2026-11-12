import { describe, expect, it, vi } from "vitest";
import { transferWails, type TransferRunEvent } from "./api";
import { fakeTransfer, noListing, sampleListing } from "./fake";

vi.mock("@wailsio/runtime", () => {
  const handlers = new Map<string, (e: { data: unknown }) => void>();
  return { Events: { On: (n: string, cb: (e: { data: unknown }) => void) => (handlers.set(n, cb), () => handlers.delete(n)), __emit: (n: string, data: unknown) => handlers.get(n)?.({ data }) } };
});

describe("transfer: explorador y avance", () => {
  it("transferBrowse completa los valores por omisión del puente", async () => {
    const call = vi.fn(async () => sampleListing);
    await transferWails(call as never).transferBrowse({ url: "ftp://10.0.0.1/" });
    expect(call).toHaveBeenCalledWith("TransferBrowse", { url: "ftp://10.0.0.1/", credentialId: "", path: "", acceptedHostKeys: [], insecure: false, legacySsh: false, maxEntries: 0, seconds: 0 });
  });
  it("transferGetMany y transferCancel llaman a su método", async () => {
    const call = vi.fn(async () => "run-1");
    const api = transferWails(call as never);
    await api.transferGetMany({ url: "ftp://h/d/", names: ["a.cfg"], destDir: "/tmp/x" });
    await api.transferCancel("run-1");
    expect(call).toHaveBeenNthCalledWith(1, "TransferGetMany", expect.objectContaining({ names: ["a.cfg"], destDir: "/tmp/x", acceptedHostKeys: [] }));
    expect(call).toHaveBeenNthCalledWith(2, "TransferCancel", "run-1");
  });
  it("onTransferRun etiqueta cada evento del puente con su clase", async () => {
    const { Events } = (await import("@wailsio/runtime")) as unknown as { Events: { __emit: (n: string, d: unknown) => void } };
    const got: TransferRunEvent[] = [];
    const off = transferWails(vi.fn() as never).onTransferRun((e) => got.push(e));
    Events.__emit("transfer:progress", { runId: "r", index: 0, count: 1, name: "a", bytes: 5, total: 10, bytesPerSec: 100 });
    Events.__emit("transfer:file", { runId: "r", index: 0, name: "a", ok: true });
    Events.__emit("transfer:finished", { runId: "r", ok: 1, failed: 0 });
    off();
    expect(got.map((e) => e.kind)).toEqual(["progress", "file", "finished"]);
  });
  it("el doble ofrece un listado con nombre hostil, un nombre no descargable y el caso «no lista»", async () => {
    const f = fakeTransfer();
    const l = await f.transferBrowse();
    expect(l.entries.find((e) => e.unsafeName)?.downloadable).toBe(false);
    expect(l.entries.find((e) => e.name.includes(" "))?.downloadable).toBe(false);
    expect(noListing.listable).toBe(false);
    const seen: string[] = [];
    f.onTransferRun((e) => seen.push(e.kind));
    f.emitTransferRun({ kind: "finished", runId: "r" });
    expect(seen).toEqual(["finished"]);
  });
});
