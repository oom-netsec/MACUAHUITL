import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CleanerView } from "./CleanerView";
import { fakeCore } from "../../lib/fake";

const result = {
  report: { changes: [{ rule: "linea-vacia", line: 3, text: "" }], orphans: [{ line: 12, text: "ip access-group IN-FALTA in", why: "ACL IN-FALTA no existe (ip access-group)" }] },
  text: "1 líneas vacías quitadas (líneas de origen: 3)\n\n1 HUÉRFANAS",
  output: "hostname R1\n! HUERFANA: ACL IN-FALTA no existe (ip access-group)\n ip access-group IN-FALTA in\n",
};

test("limpia, muestra el informe, las huérfanas y el resultado", async () => {
  const core = fakeCore({ cleanerRun: vi.fn(async () => result) });
  render(<CleanerView core={core} />);
  expect(screen.getByRole("button", { name: "Limpiar" })).toBeDisabled();
  await userEvent.type(screen.getByLabelText("Configuración"), "hostname R1");
  await userEvent.click(screen.getByLabelText(/Ordenar interfaces/));
  await userEvent.click(screen.getByRole("button", { name: "Limpiar" }));
  expect(core.cleanerRun).toHaveBeenCalledWith("hostname R1", true);
  expect(await screen.findByText(/1 líneas vacías quitadas/)).toBeInTheDocument();
  expect(screen.getByText("ACL IN-FALTA no existe (ip access-group)", { selector: "td" })).toBeInTheDocument();
  // El resultado va en una terminal (solo lectura): el texto completo, sin recortar.
  expect(screen.getByRole("log", { name: "Resultado" }).textContent).toBe(result.output);
  await userEvent.click(screen.getByRole("button", { name: "Copiar" }));
  expect(core.copyText).toHaveBeenCalledWith(result.output);
});

test("el error del núcleo se muestra como alerta", async () => {
  const core = fakeCore({ cleanerRun: vi.fn(async () => { throw new Error("rpc error: code = InvalidArgument desc = falta la configuración"); }) });
  render(<CleanerView core={core} />);
  await userEvent.type(screen.getByLabelText("Configuración"), "x");
  await userEvent.click(screen.getByRole("button", { name: "Limpiar" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("falta la configuración");
  expect(screen.queryByRole("log", { name: "Resultado" })).not.toBeInTheDocument();
});
