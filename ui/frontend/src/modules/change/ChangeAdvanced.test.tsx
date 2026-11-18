import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ChangeView } from "./ChangeView";
import { fakeCore } from "../../lib/fake";

const creds = [{ id: "c1", label: "lab", username: "admin", hasEnable: true, hasSshKey: false }];
const sum = (d: HTMLElement) => d.querySelector("summary")!;

test("Pre/Post: la carpeta de salida va plegada, cuenta y se sigue enviando; nombre, equipos y credencial quedan fuera", async () => {
  const core = fakeCore({ listCredentials: vi.fn(async () => creds), changeCreate: vi.fn(async () => "id1") });
  render(<ChangeView core={core} />);
  const d = screen.getByLabelText(/^Carpeta de salida/).closest("details")!;
  expect(d.open).toBe(false);
  expect(d).not.toContainElement(screen.getByLabelText("Nombre del cambio"));
  expect(d).not.toContainElement(screen.getByLabelText(/Equipos/));
  expect(d).not.toContainElement(screen.getByRole("button", { name: /^Crear/ }));
  await userEvent.type(screen.getByLabelText("Nombre del cambio"), "CRQ-1");
  await userEvent.type(screen.getByLabelText(/Equipos/), "192.0.2.1");
  await screen.findByRole("option", { name: /lab/ });
  await userEvent.selectOptions(screen.getByLabelText(/Credencial/), "c1");
  await userEvent.type(screen.getByLabelText(/^Carpeta de salida/), "/o/x");
  expect(sum(d)).toHaveTextContent("cambiadas: 1");
  await userEvent.click(screen.getByRole("button", { name: /^Crear/ }));
  expect(core.changeCreate).toHaveBeenCalledWith(expect.objectContaining({ outputDir: "/o/x" }));
});

test("Upgrade: tamaño, MD5 y salida de verify van en «Verificar integridad (opcional)» y se siguen enviando", async () => {
  const core = fakeCore({ upgradeCheck: vi.fn(async () => ({ json: "{}", text: "ok" })) });
  render(<ChangeView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: "Upgrade" }));
  const d = screen.getByLabelText("Tamaño (bytes)").closest("details")!;
  expect(d.open).toBe(false);
  expect(sum(d)).toHaveTextContent("Verificar integridad (opcional)");
  expect(d).toContainElement(screen.getByLabelText("MD5 esperado"));
  expect(d).toContainElement(screen.getByLabelText(/^Salida de verify/));
  expect(d).not.toContainElement(screen.getByLabelText("Imagen destino"));
  expect(d).not.toContainElement(screen.getByLabelText(/Salidas recolectadas/));
  await userEvent.type(screen.getByLabelText(/Salidas recolectadas/), "x");
  await userEvent.type(screen.getByLabelText("Imagen destino"), "x.bin");
  await userEvent.type(screen.getByLabelText("Tamaño (bytes)"), "100");
  await userEvent.type(screen.getByLabelText("MD5 esperado"), "abc");
  expect(sum(d)).toHaveTextContent("Verificar integridad (opcional) · cambiadas: 2");
  await userEvent.click(screen.getByRole("button", { name: "Verificar" }));
  expect(core.upgradeCheck).toHaveBeenCalledWith({ outputs: "x", image: "x.bin", size: 100, md5: "abc", verify: "" });
});
