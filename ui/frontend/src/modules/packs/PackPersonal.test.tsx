import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PacksSection } from "./PacksSection";
import { I18nProvider } from "../../lib/i18n";
import { fakeCore } from "../../lib/fake";
import type { ScriptItem } from "../scripts/api";
import type { PackImportItem } from "./api";

const mk = (id: string, name: string, origin: "usuario" | "biblioteca") => ({ id, name, tech: "cli", platform: "ios", description: "", commands: ["show version"], tags: [], origin, createdMs: 0, updatedMs: 0, readOnly: true, favorite: false, pinned: false, collections: [] }) as unknown as ScriptItem;
const scripts = [mk("a".repeat(32), "Mi script", "usuario"), mk("lib-x", "De biblioteca", "biblioteca")];
const view = (core = fakeCore()) => { localStorage.setItem("macuahuitl.idioma", "es"); return render(<I18nProvider><PacksSection core={core} /></I18nProvider>); };
const exportBase = { id: "yo/mis", version: "2026.1113.100000", sha256: "abc", scripts: 1, playbooks: 2, omittedPlaybooks: [] as string[] };

async function openExport(over = {}) {
  const core = fakeCore({ listScripts: vi.fn(async () => scripts), pickSavePath: vi.fn(async () => "/tmp/p.mpack"), ...over });
  view(core);
  await userEvent.click(await screen.findByRole("button", { name: "Exportar mi paquete…" }));
  const d = await screen.findByRole("dialog");
  return { core, d };
}

beforeEach(() => localStorage.clear());

test("exportar: solo scripts de usuario, valida el editor y manda overwrite tras pickSavePath", async () => {
  const exp = vi.fn(async () => ({ ...exportBase, omittedPlaybooks: ["ios/raro"] }));
  const { core, d } = await openExport({ packExport: exp });
  expect(await within(d).findByRole("checkbox", { name: /Mi script/ })).toBeVisible();
  expect(within(d).queryByRole("checkbox", { name: /De biblioteca/ })).toBeNull();
  const go = within(d).getByRole("button", { name: "Exportar" });
  expect(go).toBeDisabled();
  const ed = within(d).getByLabelText(/Editor y nombre/);
  await userEvent.type(ed, "Mal/Nombre");
  expect(go).toBeDisabled();
  await userEvent.clear(ed);
  await userEvent.type(ed, "yo/mis");
  await userEvent.click(within(d).getByRole("checkbox", { name: /Mi script/ }));
  await userEvent.click(within(d).getByRole("checkbox", { name: /playbooks/i }));
  await userEvent.click(go);
  await waitFor(() => expect(exp).toHaveBeenCalledWith(expect.objectContaining({ editorName: "yo/mis", scriptIds: ["a".repeat(32)], includePlaybooks: true, path: "/tmp/p.mpack", overwrite: true })));
  expect(core.pickSavePath).toHaveBeenCalled();
  expect(await within(d).findByText(/abc/)).toBeVisible();
  expect(within(d).getByText(/ios\/raro/)).toBeVisible();
});

test("si packExport falla se borra el archivo vacío y se muestra el error", async () => {
  const { core, d } = await openExport({ packExport: vi.fn(async () => { throw new Error("disco lleno"); }) });
  await userEvent.type(within(d).getByLabelText(/Editor y nombre/), "yo/mis");
  await userEvent.click(await within(d).findByRole("checkbox", { name: /Mi script/ }));
  await userEvent.click(within(d).getByRole("button", { name: "Exportar" }));
  await waitFor(() => expect(core.removeEmptyFile).toHaveBeenCalledWith("/tmp/p.mpack"));
  expect(await within(d).findByText(/disco lleno/)).toBeVisible();
});

const items: PackImportItem[] = [
  { kind: "script", id: "lib-yo-1", name: "Nuevo <b>x</b>", state: "nuevo", conflictsWith: "" },
  { kind: "script", id: "lib-yo-2", name: "Igual", state: "igual", conflictsWith: "" },
  { kind: "playbook", id: "ios-xe/yo-a", name: "Choca", state: "conflicto_id", conflictsWith: "user" },
];
const preview = { pack: {} as never, items, sha256: "sha-prev", applied: false, scriptsCreated: 0, scriptsRenamed: 0, scriptsSkipped: 0, playbooksCreated: 0, playbooksRenamed: 0, playbooksSkipped: 0, playbookIds: [] as string[] };

async function openImport(over = {}) {
  const core = fakeCore({ pickPath: vi.fn(async () => "/tmp/i.mpack"), packImportPreview: vi.fn(async () => preview), ...over });
  view(core);
  await userEvent.click(await screen.findByRole("button", { name: "Importar paquete personal…" }));
  const d = await screen.findByRole("dialog");
  return { core, d };
}

test("importar: cada conflicto exige decisión, nunca hay reemplazar y viaja el sha256 de la vista previa", async () => {
  const imp = vi.fn(async () => ({ ...preview, applied: true, scriptsCreated: 1, playbooksRenamed: 1 }));
  const list = vi.fn(async () => []);
  const { core, d } = await openImport({ packImport: imp, packList: list });
  expect(await within(d).findByText(/Nuevo <b>x<\/b>/)).toBeVisible();
  expect(d.querySelector("img,a,b")).toBeNull();
  expect(within(d).getAllByRole("combobox")).toHaveLength(1);
  const sel = within(d).getByRole("combobox");
  expect(Array.from(sel.querySelectorAll("option")).map((o) => o.getAttribute("value"))).toEqual(["", "renombrar", "omitir"]);
  const go = within(d).getByRole("button", { name: "Importar" });
  expect(go).toBeDisabled();
  await userEvent.selectOptions(sel, "renombrar");
  expect(go).toBeEnabled();
  const before = list.mock.calls.length;
  await userEvent.click(go);
  await waitFor(() => expect(imp).toHaveBeenCalledWith("/tmp/i.mpack", "sha-prev", [{ itemId: "ios-xe/yo-a", action: "renombrar" }]));
  expect(core.packImportPreview).toHaveBeenCalledWith("/tmp/i.mpack");
  expect(await within(d).findByText(/1 creados/)).toBeVisible();
  await waitFor(() => expect(list.mock.calls.length).toBeGreaterThan(before));
});

test("importar: si el archivo cambió pide volver a abrirlo", async () => {
  const err = Object.assign(new Error("el archivo cambió"), { cause: { code: "FailedPrecondition", reason: "pack.err.import.changed", metadata: {} } });
  const { d } = await openImport({ packImport: vi.fn(async () => { throw err; }) });
  await userEvent.selectOptions(await within(d).findByRole("combobox"), "omitir");
  await userEvent.click(within(d).getByRole("button", { name: "Importar" }));
  expect(await within(d).findByText(/el archivo cambió/)).toBeVisible();
  expect(within(d).getByText(/Vuelve a abrir el archivo/)).toBeVisible();
});
