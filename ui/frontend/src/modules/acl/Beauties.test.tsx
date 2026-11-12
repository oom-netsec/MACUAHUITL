import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AclView } from "./AclView";
import { CoreContext } from "../../app/activity";
import { fakeCore } from "../../lib/fake";
import type { CoreAPI } from "../../lib/core";

const acl = { name: "EDGE", rules: [
  { action: "permit", protocol: "tcp", source: "10.0.0.0/24", destination: "any", sourcePorts: "", destinationPorts: "eq 22", log: true, established: false, remark: "" },
  { action: "deny", protocol: "ip", source: "any", destination: "192.168.1.5", sourcePorts: "", destinationPorts: "", log: false, established: false, remark: "" },
] };

async function loaded() {
  const core = fakeCore({ aclImport: vi.fn(async () => acl), aclAnalyze: vi.fn(async () => [{ index: 1, kind: "redundant", detail: "ya está cubierta, con \"comillas\"" }]) });
  render(<CoreContext.Provider value={core as unknown as CoreAPI}><AclView core={core} /></CoreContext.Provider>);
  await userEvent.type(screen.getByLabelText("ACL a importar"), "x");
  await userEvent.click(screen.getByRole("button", { name: "Importar y analizar" }));
  await screen.findByRole("table", { name: "EDGE" });
  return core;
}

test("cada regla y cada IP tienen su botón de copiar", async () => {
  const core = await loaded();
  const table = screen.getByRole("table", { name: "EDGE" });
  const rows = within(table).getAllByRole("row");
  await userEvent.click(within(rows[1]).getByRole("button", { name: "Copiar regla 1" }));
  expect(core.copyText).toHaveBeenLastCalledWith("permit tcp 10.0.0.0/24 any eq 22 log");
  await userEvent.click(within(rows[2]).getByRole("button", { name: "Copiar 192.168.1.5" }));
  expect(core.copyText).toHaveBeenLastCalledWith("192.168.1.5");
  expect(within(rows[2]).queryByRole("button", { name: "Copiar any" })).not.toBeInTheDocument();
});

test("exporta las reglas con sus hallazgos a CSV y Markdown", async () => {
  const core = await loaded();
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "CSV (.csv)" }));
  const [name, data] = vi.mocked(core.saveFile).mock.lastCall!;
  expect(name).toBe("EDGE.csv");
  expect(data).toBe(['#,Acción,Protocolo,Origen,Puertos de origen,Destino,Puertos de destino,Hallazgo', '1,permit,tcp,10.0.0.0/24,,any,eq 22 log,', '2,deny,ip,any,,192.168.1.5,,"Redundante: ya está cubierta, con ""comillas"""'].join("\n"));
  await userEvent.click(screen.getByRole("button", { name: "Exportar" }));
  await userEvent.click(screen.getByRole("menuitem", { name: "Markdown (.md)" }));
  expect(vi.mocked(core.saveFile).mock.lastCall![0]).toBe("EDGE.md");
  expect(vi.mocked(core.saveFile).mock.lastCall![1]).toContain("| 2 | deny | ip | any |");
});
