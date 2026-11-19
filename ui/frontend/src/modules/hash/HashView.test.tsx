import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HashView } from "./HashView";
import { fakeCore } from "../../lib/fake";
import { modules } from "../index";

test("el hash avisa si no coincide con el publicado", async () => {
  const core = fakeCore({ fieldHash: vi.fn(async () => ({ text: "MD5 abc  NO COINCIDE", ok: false })) });
  render(<HashView core={core} />);
  await userEvent.type(screen.getByLabelText("Ruta de la imagen"), "/img/c9300.bin");
  await userEvent.type(screen.getByLabelText("MD5 publicado (opcional)"), "abc");
  await userEvent.click(screen.getByRole("button", { name: "Calcular" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/no instales esta imagen/);
  expect(screen.getByText(/NO COINCIDE/)).toBeInTheDocument();
  expect(core.fieldHash).toHaveBeenCalledWith("/img/c9300.bin", "abc", "");
});

test("la vista no tiene subpestañas ni servidor", () => {
  render(<HashView core={fakeCore()} />);
  expect(screen.getByRole("heading", { level: 2, name: "Hash de imagen" })).toBeInTheDocument();
  expect(screen.queryByRole("tab")).toBeNull();
  expect(screen.queryByRole("button", { name: "Servir" })).toBeNull();
});

test("el manifiesto reemplaza Campo por «Hash de imagen» en Utilidades", () => {
  expect(modules.find((m) => m.id === "field")).toBeUndefined();
  expect(modules.find((m) => m.id === "hash")).toMatchObject({ label: "nav.hash", group: "utils" });
});
