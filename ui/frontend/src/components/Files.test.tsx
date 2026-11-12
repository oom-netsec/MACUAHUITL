import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext } from "../app/activity";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";
import { DownloadButton, DropZone, ExportMenu, TransferProgress, formatBytes } from "./Files";

const withCore = (core: ReturnType<typeof fakeCore>, ui: React.ReactNode) => render(<CoreContext.Provider value={core as unknown as CoreAPI}>{ui}</CoreContext.Provider>);

test("formatBytes usa unidades binarias legibles", () => {
  expect(formatBytes(512)).toBe("512 B");
  expect(formatBytes(1536)).toBe("1.5 KiB");
  expect(formatBytes(80 * 1024 * 1024)).toBe("80 MiB");
});

test("DropZone recibe las rutas soltadas sobre ella, filtra por extensión y también deja elegir", async () => {
  const core = fakeCore({ pickPath: vi.fn(async () => "/home/u/cap.pcapng") });
  const onPaths = vi.fn();
  withCore(core, <DropZone label="Captura" accept={["pcap", "pcapng"]} onPaths={onPaths} />);
  const zone = screen.getByRole("group", { name: "Captura" });
  expect(zone).toHaveAttribute("data-file-drop-target");
  act(() => core.emitFilesDropped({ target: "otra", paths: ["/x/ajeno.pcap"] }));
  expect(onPaths).not.toHaveBeenCalled();
  act(() => core.emitFilesDropped({ target: zone.id, paths: ["/x/a.pcap", "/x/b.txt"] }));
  expect(onPaths).toHaveBeenCalledWith(["/x/a.pcap"]);
  expect(screen.getByRole("alert")).toHaveTextContent("b.txt");
  await userEvent.click(within(zone).getByRole("button", { name: "Elegir archivo…" }));
  expect(core.pickPath).toHaveBeenCalledWith(expect.objectContaining({ filters: [{ name: "Captura", pattern: "*.pcap;*.pcapng" }] }));
  expect(onPaths).toHaveBeenLastCalledWith(["/home/u/cap.pcapng"]);
});

test("DownloadButton y ExportMenu guardan con el nombre sugerido", async () => {
  const core = fakeCore();
  withCore(core, <>
    <DownloadButton name="running-SW1.cfg" data={() => "hostname SW1"} label="Descargar la configuración" />
    <ExportMenu name="hallazgos" formats={[{ fmt: "csv", data: () => "a,b" }, { fmt: "md", data: () => "# x" }]} />
  </>);
  await userEvent.click(screen.getByRole("button", { name: "Descargar la configuración" }));
  expect(core.saveFile).toHaveBeenCalledWith("running-SW1.cfg", "hostname SW1", "utf8");
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Markdown (.md)" }));
  expect(core.saveFile).toHaveBeenLastCalledWith("hallazgos.md", "# x", "utf8");
  expect(screen.queryByRole("menu")).not.toBeInTheDocument();
});

test("TransferProgress muestra bytes, porcentaje, velocidad y tiempo restante, y permite cancelar", async () => {
  const cancel = vi.fn();
  const { rerender } = render(<TransferProgress file="cat9k.bin" bytes={20 * 1024 * 1024} total={80 * 1024 * 1024} rateBps={4 * 1024 * 1024} etaSeconds={15} onCancel={cancel} />);
  const bar = screen.getByRole("progressbar", { name: "cat9k.bin" });
  expect(bar).toHaveAttribute("aria-valuenow", "25");
  expect(screen.getByText("20 MiB de 80 MiB · 25 % · 4 MiB/s · 15 s restantes")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancelar cat9k.bin" }));
  expect(cancel).toHaveBeenCalled();
  rerender(<TransferProgress file="cat9k.bin" bytes={80 * 1024 * 1024} total={80 * 1024 * 1024} rateBps={0} etaSeconds={0} done verified />);
  expect(screen.getByText("Hash verificado")).toBeInTheDocument();
  rerender(<TransferProgress file="cat9k.bin" bytes={1} total={2} rateBps={0} etaSeconds={-1} done error="conexión cerrada" />);
  expect(screen.getByRole("alert")).toHaveTextContent("conexión cerrada");
});
