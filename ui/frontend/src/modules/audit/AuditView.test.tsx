import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuditView } from "./AuditView";
import { fakeCore } from "../../lib/fake";
import { CoreContext } from "../../app/activity";

test("verificar muestra la cadena íntegra con su cabeza", async () => {
  const core = fakeCore();
  render(<AuditView core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Verificar cadena" }));
  // Los botones de copiar traen su propio estado (role=status): se busca el aviso por su texto.
  await screen.findByText("Cadena íntegra. Último hash: abc");
  expect(screen.getAllByRole("status").some((el) => el.textContent === "Cadena íntegra. Último hash: abc")).toBe(true);
});

test("verificar muestra el primer registro roto", async () => {
  const core = fakeCore({ auditVerify: vi.fn(async () => ({ intact: false, firstBroken: 42, head: "" })) });
  render(<AuditView core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Verificar cadena" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Cadena rota a partir del registro 42.");
});

test("la insignia dice íntegra o rota con el número de registro, y el hash se copia", async () => {
  const core = fakeCore();
  render(<CoreContext.Provider value={core}><AuditView core={core} /></CoreContext.Provider>);
  expect(screen.queryByRole("region", { name: "Integridad de la cadena" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Verificar cadena" }));
  const reg = await screen.findByRole("region", { name: "Integridad de la cadena" });
  expect(within(reg).getByText("Íntegra")).toBeInTheDocument();
  await userEvent.click(within(reg).getByRole("button", { name: "Copiar último hash" }));
  expect(core.copyText).toHaveBeenCalledWith("abc");
});

test("rota: la insignia lleva el primer registro roto", async () => {
  const core = fakeCore({ auditVerify: vi.fn(async () => ({ intact: false, firstBroken: 42, head: "" })) });
  render(<AuditView core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Verificar cadena" }));
  expect(within(await screen.findByRole("region", { name: "Integridad de la cadena" })).getByText("Rota en el registro 42")).toBeInTheDocument();
});

test("la exportación sigue siendo por la CLI y el comando se copia", async () => {
  const core = fakeCore();
  render(<CoreContext.Provider value={core}><AuditView core={core} /></CoreContext.Provider>);
  await userEvent.click(screen.getByRole("button", { name: "Copiar comando de exportación" }));
  expect(core.copyText).toHaveBeenCalledWith("mctl audit export");
});

test("sin verificar muestra el estado vacío y lo quita al verificar", async () => {
  const core = fakeCore();
  render(<AuditView core={core} />);
  expect(screen.getByText("Aún no se ha verificado la cadena")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Verificar cadena" }));
  await screen.findByRole("region", { name: "Integridad de la cadena" });
  expect(screen.queryByText("Aún no se ha verificado la cadena")).not.toBeInTheDocument();
});
