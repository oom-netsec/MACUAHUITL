import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { PacksSection, libOf } from "./PacksSection";
import { I18nProvider } from "../../lib/i18n";
import { fakeCore } from "../../lib/fake";
import { sampleDetail, samplePack, sampleThirdParty } from "./fake";
import { useScriptsVersion } from "../scripts/signal";

const view = (core = fakeCore(), lang = "es") => {
  localStorage.setItem("macuahuitl.lang", lang);
  return render(<I18nProvider><PacksSection core={core} /></I18nProvider>);
};
const detail = { ...sampleDetail, playbookIds: ["ios-xe/l2-stp", "ios-xe/mine"], scriptIds: ["lib-l2-stp", "lib-mine", "extra"] };
const withShow = (over = {}, hidden: string[] = [], shadowed: string[] = []) =>
  fakeCore({ packShow: vi.fn(async () => ({ ...detail, pack: { ...samplePack, hidden, shadowed } })), ...over });
const open = async () => { await userEvent.click((await screen.findAllByRole("button", { name: /Ver detalle/ }))[0]); return screen.findByRole("dialog"); };

beforeEach(() => localStorage.clear());

test("la lista muestra origen, cuentas, ocultos y el aviso de tapados", async () => {
  view(fakeCore({ packList: vi.fn(async () => [{ ...samplePack, hidden: ["a", "b"] }, { ...sampleThirdParty, shadowed: ["ios-xe/acme-a"] }]) }));
  expect(await screen.findByText("oom/ios-xe")).toBeVisible();
  expect(screen.getByText("de terceros")).toBeVisible();
  expect(screen.getByText("oficial")).toBeVisible();
  expect(screen.getByText(/52 playbooks · 52 scripts · 2 ocultos/)).toBeVisible();
  expect(screen.getByText(/ios-xe\/acme-a/)).toBeVisible();
  expect(screen.getByText("Demo <b>de terceros</b>")).toBeVisible(); // texto plano
});

test("en inglés usa nameEn", async () => {
  view(fakeCore(), "en");
  expect((await screen.findAllByText("IOS-XE, TAC diagnostics"))[0]).toBeVisible();
});

test("el detalle muestra el README como texto y nunca ejecuta HTML", async () => {
  view(withShow());
  const d = await open();
  expect(within(d).getByText(/<script>no se ejecuta<\/script>/)).toBeVisible();
  expect(d.querySelector("script,img,a")).toBeNull();
});

test("ocultar un playbook manda solo ese ID en hide y refresca con la respuesta", async () => {
  const setItems = vi.fn(async () => ({ ...samplePack, hidden: ["ios-xe/mine"] }));
  view(withShow({ packSetItems: setItems }));
  const d = await open();
  await userEvent.click(within(d).getByRole("checkbox", { name: /ios-xe\/mine/ }));
  expect(setItems).toHaveBeenCalledWith("oom/ios-xe", ["ios-xe/mine"], []);
  await waitFor(() => expect(within(d).getByRole("checkbox", { name: /ios-xe\/mine/ })).not.toBeChecked());
  expect(within(d).getByRole("checkbox", { name: /lib-mine/ })).not.toBeChecked(); // su lib-<id> se ve oculto
  expect(within(d).getByRole("checkbox", { name: /lib-mine/ })).toBeDisabled();
});

test("mostrar uno oculto manda solo show", async () => {
  const setItems = vi.fn(async () => ({ ...samplePack, hidden: [] }));
  view(withShow({ packSetItems: setItems }, ["extra"]));
  const d = await open();
  const box = within(d).getByRole("checkbox", { name: /extra/ });
  expect(box).not.toBeChecked();
  await userEvent.click(box);
  expect(setItems).toHaveBeenCalledWith("oom/ios-xe", [], ["extra"]);
});

test("un playbook tapado no se puede ocultar", async () => {
  view(withShow({}, [], ["ios-xe/mine"]));
  const d = await open();
  expect(within(d).getByRole("checkbox", { name: /ios-xe\/mine/ })).toBeDisabled();
});

test("instalar de terceros: aviso, casillas precargadas y packInstallHiding con lo desmarcado", async () => {
  const inspect = vi.fn(async () => ({ pack: { ...sampleThirdParty, hidden: ["ios-xe/mine"] }, playbookIds: ["ios-xe/l2-stp", "ios-xe/mine"], scriptIds: ["lib-l2-stp"], replacedVersion: "0.9.0", sha256: "abc" }));
  const install = vi.fn(async () => ({ pack: sampleThirdParty, replacedVersion: "" }));
  const list = vi.fn(async () => [samplePack]);
  const core = fakeCore({ packInspect: inspect, packInstallHiding: install, packList: list, pickPath: vi.fn(async () => "/tmp/x.mpack") });
  view(core);
  await userEvent.click(await screen.findByRole("button", { name: "Instalar paquete…" }));
  const d = await screen.findByRole("dialog");
  expect(inspect).toHaveBeenCalledWith("/tmp/x.mpack", true);
  expect(within(d).getByText(/no está firmado/)).toBeVisible();
  expect(within(d).getByText(/0\.9\.0/)).toBeVisible();
  expect(within(d).getByRole("checkbox", { name: /ios-xe\/mine/ })).not.toBeChecked();
  await userEvent.click(within(d).getByRole("checkbox", { name: /lib-l2-stp/ }));
  const calls = list.mock.calls.length;
  await userEvent.click(within(d).getByRole("button", { name: "Instalar" }));
  await waitFor(() => expect(install).toHaveBeenCalledWith("/tmp/x.mpack", true, ["ios-xe/mine", "lib-l2-stp"], true, "abc"));
  await waitFor(() => expect(list.mock.calls.length).toBeGreaterThan(calls));
});

test("instalar uno oficial manda allowUnsigned false y sin aviso", async () => {
  const install = vi.fn(async () => ({ pack: samplePack, replacedVersion: "" }));
  view(fakeCore({ packInstallHiding: install, pickPath: vi.fn(async () => "/tmp/o.mpack") }));
  await userEvent.click(await screen.findByRole("button", { name: "Instalar paquete…" }));
  const d = await screen.findByRole("dialog");
  expect(within(d).queryByText(/no está firmado/)).toBeNull();
  await userEvent.click(within(d).getByRole("button", { name: "Instalar" }));
  await waitFor(() => expect(install).toHaveBeenCalledWith("/tmp/o.mpack", false, [], true, "a".repeat(64)));
});

test("un error al instalar se muestra y aun así refresca la lista", async () => {
  const list = vi.fn(async () => [samplePack]);
  const install = vi.fn(async () => { throw new Error("rpc error: code = Internal desc = el paquete quedó instalado"); });
  view(fakeCore({ packInstallHiding: install, packList: list, pickPath: vi.fn(async () => "/tmp/o.mpack") }));
  await userEvent.click(await screen.findByRole("button", { name: "Instalar paquete…" }));
  const d = await screen.findByRole("dialog");
  const calls = list.mock.calls.length;
  await userEvent.click(within(d).getByRole("button", { name: "Instalar" }));
  expect(await within(d).findByRole("alert")).toHaveTextContent("el paquete quedó instalado");
  expect(list.mock.calls.length).toBeGreaterThan(calls);
});

test("quitar pide confirmación y avisa de los favoritos quitados", async () => {
  const remove = vi.fn(async () => 3);
  view(fakeCore({ packRemove: remove }));
  await userEvent.click((await screen.findAllByRole("button", { name: "Quitar oom/ios-xe" }))[0]);
  expect(remove).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: quitar oom/ios-xe" }));
  await waitFor(() => expect(remove).toHaveBeenCalledWith("oom/ios-xe"));
  expect(await screen.findByText(/3 favoritos/)).toBeVisible();
});

// La terminal (favoritos) y Scripts siguen montadas aunque ocultas: instalar o quitar un paquete cambia su biblioteca.
test("instalar y quitar un paquete avisan que los scripts cambiaron", async () => {
  let seen = 0;
  function Probe() { seen = useScriptsVersion(); return null; }
  render(<Probe />);
  const start = seen;
  view(fakeCore({ packRemove: vi.fn(async () => 0), pickPath: vi.fn(async () => "/tmp/o.mpack") }));
  await userEvent.click((await screen.findAllByRole("button", { name: "Quitar oom/ios-xe" }))[0]);
  await userEvent.click(screen.getByRole("button", { name: "Confirmar: quitar oom/ios-xe" }));
  await waitFor(() => expect(seen).toBe(start + 1));
  await userEvent.click(screen.getByRole("button", { name: "Instalar paquete…" }));
  await userEvent.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Instalar" }));
  await waitFor(() => expect(seen).toBe(start + 2));
});

test("ocultar un elemento en el detalle también avisa que los scripts cambiaron", async () => {
  let seen = 0;
  function Probe() { seen = useScriptsVersion(); return null; }
  render(<Probe />);
  const start = seen;
  view(withShow({}, [], []));
  const d = await open();
  await userEvent.click(within(d).getByRole("checkbox", { name: /lib-l2-stp/ }));
  await waitFor(() => expect(seen).toBe(start + 1));
});

test("libOf arma el ID del script derivado como el núcleo", () => {
  expect(libOf("ios-xe/l2-stp")).toBe("lib-l2-stp");
  expect(libOf("ios/l2-stp")).toBe("lib-ios-l2-stp");
  expect(libOf("wlc-9800/ap-join")).toBe("lib-wlc-9800-ap-join");
});

test("instalar: desmarcar un playbook oculta su script en la vista previa y marcarlo lo devuelve", async () => {
  const inspect = vi.fn(async () => ({ pack: { ...sampleThirdParty, hidden: ["ios-xe/mine"] }, playbookIds: ["ios-xe/l2-stp", "ios-xe/mine"], scriptIds: ["lib-l2-stp", "lib-mine"], replacedVersion: "", sha256: "abc" }));
  const install = vi.fn(async () => ({ pack: sampleThirdParty, replacedVersion: "" }));
  view(fakeCore({ packInspect: inspect, packInstallHiding: install, pickPath: vi.fn(async () => "/tmp/x.mpack") }));
  await userEvent.click(await screen.findByRole("button", { name: "Instalar paquete…" }));
  const d = await screen.findByRole("dialog");
  expect(within(d).getByText("Demo <b>de terceros</b>")).toBeVisible(); // nombre del paquete, como texto
  expect(within(d).getByRole("checkbox", { name: /lib-mine/ })).toBeDisabled();
  await userEvent.click(within(d).getByRole("checkbox", { name: /ios-xe\/mine/ }));
  expect(within(d).getByRole("checkbox", { name: /lib-mine/ })).toBeEnabled();
  expect(within(d).getByRole("checkbox", { name: /lib-mine/ })).toBeChecked();
  await userEvent.click(within(d).getByRole("checkbox", { name: /ios-xe\/l2-stp/ }));
  expect(within(d).getByRole("checkbox", { name: /lib-l2-stp/ })).not.toBeChecked();
  expect(within(d).getByRole("checkbox", { name: /lib-l2-stp/ })).toBeDisabled();
  await userEvent.click(within(d).getByRole("button", { name: "Instalar" }));
  await waitFor(() => expect(install).toHaveBeenCalledWith("/tmp/x.mpack", true, ["ios-xe/l2-stp"], true, "abc"));
});

test("instalar: un playbook tapado que estaba oculto no viaja en hide", async () => {
  const inspect = vi.fn(async () => ({ pack: { ...sampleThirdParty, hidden: ["ios-xe/acme-a"] }, playbookIds: ["ios-xe/acme-a"], scriptIds: [], replacedVersion: "", sha256: "abc" }));
  const install = vi.fn(async () => ({ pack: sampleThirdParty, replacedVersion: "" }));
  view(fakeCore({ packInspect: inspect, packInstallHiding: install, pickPath: vi.fn(async () => "/tmp/x.mpack") }));
  await userEvent.click(await screen.findByRole("button", { name: "Instalar paquete…" }));
  const d = await screen.findByRole("dialog");
  await userEvent.click(within(d).getByRole("button", { name: "Instalar" }));
  await waitFor(() => expect(install).toHaveBeenCalledWith("/tmp/x.mpack", true, [], true, "abc"));
});

test("si el selector de archivos falla, el error se muestra", async () => {
  view(fakeCore({ pickPath: vi.fn(async () => { throw new Error("portal no disponible"); }) }));
  await userEvent.click(await screen.findByRole("button", { name: "Instalar paquete…" }));
  expect(await screen.findByText(/portal no disponible/)).toBeInTheDocument();
});
