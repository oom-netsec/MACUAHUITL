import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CleanerView } from "./CleanerView";
import { fakeCore } from "../../lib/fake";

const input = "hostname R1\n\n\n!\n!\ninterface Gi1\n shutdown\n";
const output = "hostname R1\n!\ninterface Gi1\n shutdown\n";

async function run() {
  const core = fakeCore({ cleanerRun: vi.fn(async () => ({ report: { changes: [], orphans: [] }, text: "informe", output })) });
  render(<CleanerView core={core} />);
  await userEvent.click(screen.getByLabelText("Configuración"));
  await userEvent.paste(input);
  await userEvent.click(screen.getByRole("button", { name: "Limpiar" }));
  return screen.findByRole("region", { name: "Antes y después" });
}

test("antes y después compara lo pegado con el resultado en un DiffView", async () => {
  const diff = await run();
  expect(diff).toHaveTextContent("3 quitadas");
  expect(diff).toHaveTextContent("0 líneas agregadas");
});

test("si cambia la entrada después de limpiar, el diff sigue siendo contra lo que se limpió", async () => {
  await run();
  await userEvent.type(screen.getByLabelText("Configuración"), "zzz");
  expect(screen.getByRole("region", { name: "Antes y después" })).toHaveTextContent("3 quitadas");
});
