import { CoreContext } from "../../app/activity";
import type { CoreAPI } from "../../lib/core";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AclView } from "./AclView";
import { fakeCore } from "../../lib/fake";

const acl = { name: "EDGE", rules: [{ action: "permit", protocol: "tcp", source: "10.0.0.0/24", destination: "0.0.0.0/0", sourcePorts: "", destinationPorts: "eq 22", log: false, established: false, remark: "" }] };

test("importar, analizar y generar", async () => {
  const core = fakeCore({
    aclImport: vi.fn(async () => acl),
    aclAnalyze: vi.fn(async () => [{ index: 0, kind: "shadowed", detail: "la regla 1 ya cubre" }]),
    aclGenerate: vi.fn(async () => "ip access-list NEW\n  10 permit tcp 10.0.0.0/24 any eq 22\n"),
  });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><AclView core={core} /></CoreContext.Provider>);
  await userEvent.selectOptions(screen.getByLabelText("Plataforma de origen"), "asa");
  await userEvent.type(screen.getByLabelText("ACL a importar"), "access-list EDGE extended permit tcp any any");
  await userEvent.click(screen.getByRole("button", { name: "Importar y analizar" }));
  expect(await screen.findByText("EDGE")).toBeInTheDocument();
  const row = await screen.findByRole("row", { name: /10\.0\.0\.0\/24/ });
  expect(row).toHaveTextContent("eq 22");
  expect(await screen.findByText(/Sombreada/)).toBeInTheDocument();
  expect(screen.getByText("1 hallazgo")).toBeInTheDocument();
  expect(core.aclImport).toHaveBeenCalledWith("asa", expect.stringContaining("access-list EDGE"));
  await userEvent.selectOptions(within(screen.getByRole("group", { name: "Origen y destino" })).getByLabelText("Plataforma de destino"), "nx-os");
  await userEvent.click(screen.getByRole("button", { name: "Generar para Cisco NX-OS" }));
  expect(await screen.findByRole("log", { name: "Resultado" })).toHaveTextContent("ip access-list NEW");
  expect(core.aclGenerate).toHaveBeenCalledWith("nx-os", acl);
  await userEvent.click(screen.getByRole("button", { name: "Copiar Resultado" }));
  await waitFor(() => expect(core.copyText).toHaveBeenCalledWith(expect.stringContaining("ip access-list NEW")));
  await waitFor(() => expect(screen.getAllByRole("status").some((e) => e.textContent === "Copiado")).toBe(true));
});

test("antes de importar explica qué hacer y no ofrece generar", () => {
  render(<AclView core={fakeCore()} />);
  expect(screen.getByText("Sin ACL importada")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: /^Generar/ })).not.toBeInTheDocument();
});

test("un error de importación muestra la línea", async () => {
  const core = fakeCore({ aclImport: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = acl: línea 2: wildcard no contigua"); }) });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><AclView core={core} /></CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText("ACL a importar"), "x");
  await userEvent.click(screen.getByRole("button", { name: "Importar y analizar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("línea 2");
});

test("importar y analizar espera a que haya texto", async () => {
  render(<AclView core={fakeCore()} />);
  expect(screen.getByRole("button", { name: /Importar y analizar/ })).toBeDisabled();
  await userEvent.type(screen.getByLabelText("ACL a importar"), "permit ip any any");
  expect(screen.getByRole("button", { name: /Importar y analizar/ })).toBeEnabled();
});

test("Importar y analizar nombra la ACL que falta y deja de hacerlo al pegarla", async () => {
  render(<AclView core={fakeCore()} />);
  const btn = screen.getByRole("button", { name: "Importar y analizar" });
  expect(btn).toBeDisabled();
  expect(btn).toHaveAccessibleDescription("Falta: pegar la ACL a importar.");
  await userEvent.type(screen.getByLabelText("ACL a importar"), "x");
  expect(btn).toBeEnabled();
  expect(btn).not.toHaveAccessibleDescription();
});

test("autodetecta el origen, lo marca y la elección manual no se pisa", async () => {
  const core = fakeCore({ aclImport: vi.fn(async () => acl) });
  render(<AclView core={core} />);
  const from = screen.getByLabelText("Plataforma de origen");
  expect(from).toHaveValue("ios-xe");
  await userEvent.type(screen.getByLabelText("ACL a importar"), "access-list E extended permit ip any any");
  expect(from).toHaveValue("asa");
  expect(screen.getByRole("option", { name: "Cisco ASA (detectada)" })).toBeInTheDocument();
  await userEvent.selectOptions(from, "nx-os");
  expect(screen.queryByRole("option", { name: /detectada/ })).not.toBeInTheDocument();
  await userEvent.type(screen.getByLabelText("ACL a importar"), "\nip access-list extended Z");
  expect(from).toHaveValue("nx-os");
  await userEvent.click(screen.getByRole("button", { name: "Importar y analizar" }));
  expect(core.aclImport).toHaveBeenCalledWith("nx-os", expect.any(String));
});

test("texto ambiguo deja el origen como está", async () => {
  render(<AclView core={fakeCore()} />);
  await userEvent.type(screen.getByLabelText("ACL a importar"), "permit ip any any");
  expect(screen.getByLabelText("Plataforma de origen")).toHaveValue("ios-xe");
  expect(screen.queryByRole("option", { name: /detectada/ })).not.toBeInTheDocument();
});

test("la marca «(detectada)» se quita si el texto deja de detectarse, pero el origen se queda", async () => {
  render(<AclView core={fakeCore()} />);
  const box = screen.getByLabelText("ACL a importar");
  await userEvent.type(box, "access-list E extended permit ip any any");
  expect(screen.getByRole("option", { name: "Cisco ASA (detectada)" })).toBeInTheDocument();
  await userEvent.clear(box);
  expect(screen.getByLabelText("Plataforma de origen")).toHaveValue("asa");
  expect(screen.queryByRole("option", { name: /detectada/ })).not.toBeInTheDocument();
});
