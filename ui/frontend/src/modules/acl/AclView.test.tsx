import { render, screen, waitFor } from "@testing-library/react";
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
  render(<AclView core={core} />);
  await userEvent.selectOptions(screen.getByLabelText("Plataforma de origen"), "asa");
  await userEvent.type(screen.getByLabelText("ACL a importar"), "access-list EDGE extended permit tcp any any");
  await userEvent.click(screen.getByRole("button", { name: "Importar y analizar" }));
  expect(await screen.findByText("EDGE")).toBeInTheDocument();
  const row = await screen.findByRole("row", { name: /10\.0\.0\.0\/24/ });
  expect(row).toHaveTextContent("eq 22");
  expect(await screen.findByText(/Sombreada/)).toBeInTheDocument();
  expect(screen.getByText("1 hallazgo")).toBeInTheDocument();
  expect(core.aclImport).toHaveBeenCalledWith("asa", expect.stringContaining("access-list EDGE"));
  await userEvent.selectOptions(screen.getByLabelText("Plataforma de destino"), "nx-os");
  await userEvent.click(screen.getByRole("button", { name: "Generar" }));
  expect(await screen.findByRole("log", { name: "Resultado" })).toHaveTextContent("ip access-list NEW");
  expect(core.aclGenerate).toHaveBeenCalledWith("nx-os", acl);
  await userEvent.click(screen.getByRole("button", { name: "Copiar" }));
  await waitFor(() => expect(core.copyText).toHaveBeenCalledWith(expect.stringContaining("ip access-list NEW")));
});

test("antes de importar explica qué hacer y no ofrece generar", () => {
  render(<AclView core={fakeCore()} />);
  expect(screen.getByText("Sin ACL importada")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Generar" })).not.toBeInTheDocument();
});

test("un error de importación muestra la línea", async () => {
  const core = fakeCore({ aclImport: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = acl: línea 2: wildcard no contigua"); }) });
  render(<AclView core={core} />);
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
