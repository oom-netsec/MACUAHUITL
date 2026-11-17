import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HostsDataCard } from "./HostsDataCard";
import { fakeInventory, sampleHostsImport } from "../inventory/fake";
import { fakeCore } from "../../lib/fake";
import { I18nProvider } from "../../lib/i18n";

const evil = '<img src=x onerror="window.__pwn=1"><script>window.__pwn=2</script>';
async function preview(name: string, reason = evil) {
  const item = { ...sampleHostsImport.items[0], host: { ...sampleHostsImport.items[0].host, name } };
  const p = { ...sampleHostsImport, items: [item], errors: [{ line: 3, field: "name", reason }], warnings: [reason] };
  const core = fakeCore({ ...fakeInventory(), pickPath: vi.fn(async () => "/h.csv"), previewHostsImport: vi.fn(async () => p) });
  render(<I18nProvider><HostsDataCard core={core} /></I18nProvider>);
  await userEvent.click(screen.getByRole("button", { name: "Importar…" }));
  return screen.findByRole("region", { name: /Vista previa/ });
}

test("host y errores con HTML se ven como texto en la vista previa: sin elementos nuevos", async () => {
  const sec = await preview(evil);
  expect(sec.querySelector("img, script")).toBeNull();
  expect(sec.textContent!.split(evil).length - 1).toBe(3); // nombre, error y aviso
  expect((window as unknown as { __pwn?: number }).__pwn).toBeUndefined();
});

test("bidi y controles en el nombre del host salen como código visible", async () => {
  const sec = await preview("SW‮evil⁦⁩\u0007\u0000");
  const cell = within(sec).getByRole("table", { name: "Filas válidas del archivo" }).querySelector("tbody td")!;
  expect(cell.textContent).toBe("SW⟦U+202E⟧evil⟦U+2066⟧⟦U+2069⟧⟦U+0007⟧⟦U+0000⟧");
});
