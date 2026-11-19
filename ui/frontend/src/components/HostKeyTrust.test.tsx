import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { HostKeyTrust } from "./HostKeyTrust";
import { setOSForTests } from "../lib/platform";

const one = { fp: "SHA256:aaa", changed: false, host: "10.0.0.1:22", keyType: "ssh-ed25519" };
const two = { fp: "SHA256:bbb", changed: true, host: "10.0.0.2:22", keyType: "ssh-rsa" };
afterEach(() => setOSForTests(undefined));

test("muestra equipo, huella, tipo y la orden de la plataforma actual; la otra queda cerrada", () => {
  render(<HostKeyTrust items={[one]} onTrust={() => {}} />);
  expect(screen.getByText("10.0.0.1:22")).toBeInTheDocument();
  expect(screen.getByText("SHA256:aaa")).toBeInTheDocument();
  expect(screen.getByText("ssh-ed25519")).toBeInTheDocument();
  const linux = screen.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub");
  expect(linux.closest("details")).toBeNull();
  const win = screen.getByText("ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub");
  expect(win.closest("details")).not.toHaveAttribute("open");
});

test("en Windows la orden de Windows va a la vista y la de Linux queda cerrada", () => {
  setOSForTests("windows");
  render(<HostKeyTrust items={[one]} onTrust={() => {}} />);
  expect(screen.getByText("ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub").closest("details")).toBeNull();
  expect(screen.getByText("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub").closest("details")).not.toHaveAttribute("open");
});

test("sin clic no se acepta nada; con un equipo, el botón acepta solo esa huella", async () => {
  const onTrust = vi.fn();
  render(<HostKeyTrust items={[one]} onTrust={onTrust} />);
  expect(onTrust).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  expect(onTrust).toHaveBeenCalledWith([{ host: "10.0.0.1:22", fingerprint: "SHA256:aaa" }]);
});

test("una llave cambiada lleva un aviso de peligro (alerta) y una nueva no", () => {
  const { rerender } = render(<HostKeyTrust items={[one]} onTrust={() => {}} />);
  expect(screen.queryByRole("alert")).toBeNull();
  rerender(<HostKeyTrust items={[{ ...one, changed: true }]} onTrust={() => {}} />);
  expect(screen.getByRole("alert")).toHaveTextContent("CAMBIÓ");
});

test("con varios equipos hay una casilla por equipo, sin marcar, y el botón no acepta hasta marcar", async () => {
  const onTrust = vi.fn();
  render(<HostKeyTrust items={[one, two]} onTrust={onTrust} />);
  const boxes = screen.getAllByRole("checkbox");
  expect(boxes).toHaveLength(2);
  boxes.forEach((b) => expect(b).not.toBeChecked());
  const btn = screen.getByRole("button", { name: "Confiar y reintentar" });
  expect(btn).toBeDisabled();
  await userEvent.click(within(screen.getByRole("group", { name: "10.0.0.2:22" })).getByRole("checkbox"));
  expect(btn).toBeDisabled(); // la llave de .2 cambió: falta marcar que se entiende
  await userEvent.click(screen.getByRole("checkbox", { name: /Entiendo que la llave de este equipo cambió/ }));
  expect(btn).toBeEnabled();
  await userEvent.click(btn);
  expect(onTrust).toHaveBeenCalledWith([{ host: "10.0.0.2:22", fingerprint: "SHA256:bbb" }]);
});

// B1: la aceptación del núcleo es por huella (vale para todo el trabajo), no por equipo.
test("dos equipos con la misma huella, uno nuevo y otro cambiado: marcar uno marca los dos y el aviso rojo sigue a la vista", async () => {
  const onTrust = vi.fn();
  const nuevo = { fp: "SHA256:zzz", changed: false, host: "10.0.0.1:22" };
  const cambiado = { fp: "SHA256:zzz", changed: true, host: "10.0.0.2:22" };
  render(<HostKeyTrust items={[nuevo, cambiado]} onTrust={onTrust} />);
  await userEvent.click(within(screen.getByRole("group", { name: "10.0.0.1:22" })).getByRole("checkbox"));
  screen.getAllByRole("checkbox", { name: /Confiar en la llave de/ }).forEach((b) => expect(b).toBeChecked());
  expect(screen.getByRole("alert")).toHaveTextContent("CAMBIÓ");
  await userEvent.click(screen.getByRole("checkbox", { name: /Entiendo que la llave de este equipo cambió/ }));
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  expect(onTrust).toHaveBeenCalledWith([{ host: "10.0.0.1:22", fingerprint: "SHA256:zzz" }, { host: "10.0.0.2:22", fingerprint: "SHA256:zzz" }]) // un par por equipo marcado a la vista;
});

test("la selección no se reinicia si llega un arreglo nuevo con las mismas huellas", async () => {
  const { rerender } = render(<HostKeyTrust items={[one, two]} onTrust={() => {}} />);
  await userEvent.click(within(screen.getByRole("group", { name: "10.0.0.1:22" })).getByRole("checkbox"));
  rerender(<HostKeyTrust items={[{ ...one }, { ...two }]} onTrust={() => {}} />);
  expect(within(screen.getByRole("group", { name: "10.0.0.1:22" })).getByRole("checkbox")).toBeChecked();
});

test("una llave cambiada, aunque sea un solo equipo, exige marcar que se entiende antes de confiar", async () => {
  const onTrust = vi.fn();
  render(<HostKeyTrust items={[{ ...one, changed: true }]} onTrust={onTrust} />);
  const btn = screen.getByRole("button", { name: "Confiar y reintentar" });
  expect(btn).toBeDisabled();
  await userEvent.click(screen.getByRole("checkbox", { name: /Entiendo que la llave de este equipo cambió/ }));
  await userEvent.click(btn);
  expect(onTrust).toHaveBeenCalledWith([{ host: "10.0.0.1:22", fingerprint: "SHA256:aaa" }]);
});

test("una llave nueva sigue con un solo clic y sin casilla de entendimiento", () => {
  render(<HostKeyTrust items={[one]} onTrust={() => {}} />);
  expect(screen.queryByRole("checkbox")).toBeNull();
  expect(screen.getByRole("button", { name: "Confiar y reintentar" })).toBeEnabled();
});

test("el equipo se muestra sin caracteres invisibles", () => {
  render(<HostKeyTrust items={[{ ...one, host: "sw‮1" }]} onTrust={() => {}} />);
  expect(screen.getByText("sw⟦U+202E⟧1")).toBeInTheDocument();
});

test("al aparecer el foco va al aviso, nunca al botón; tras el clic vuelve a quien lanzó la operación", async () => {
  function Host() {
    const [open, setOpen] = useState(false);
    return <><button onClick={() => setOpen(true)}>lanzar</button>{open && <HostKeyTrust items={[one]} onTrust={() => {}} />}</>;
  }
  render(<Host />);
  const launch = screen.getByRole("button", { name: "lanzar" });
  await userEvent.click(launch);
  expect(screen.getByRole("button", { name: "Confiar y reintentar" })).not.toHaveFocus();
  expect(document.activeElement?.className).toContain("hostkey-trust");
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  expect(launch).toHaveFocus();
});

test("con varios equipos solo salen los pares de lo marcado: cada huella atada a su equipo, nunca una lista suelta", async () => {
  const onTrust = vi.fn();
  const a = { fp: "SHA256:aaa", changed: false, host: "10.0.0.1:22" };
  const b = { fp: "SHA256:bbb", changed: false, host: "10.0.0.2:22" };
  render(<HostKeyTrust items={[a, b]} onTrust={onTrust} />);
  await userEvent.click(within(screen.getByRole("group", { name: "10.0.0.2:22" })).getByRole("checkbox"));
  await userEvent.click(screen.getByRole("button", { name: "Confiar y reintentar" }));
  expect(onTrust).toHaveBeenCalledTimes(1);
  expect(onTrust).toHaveBeenCalledWith([{ host: "10.0.0.2:22", fingerprint: "SHA256:bbb" }]);
});

test("una fila sin equipo no se puede atar: no genera par y el botón no acepta", () => {
  render(<HostKeyTrust items={[{ fp: "SHA256:aaa", changed: false }]} onTrust={() => {}} />);
  expect(screen.getByRole("button", { name: "Confiar y reintentar" })).toBeDisabled();
});
