import { useState } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TargetField, TargetsField, useBookCredential } from "./TargetField";
import { fakeCore } from "../../lib/fake";
import { fakeInventory, sampleHosts, telnetHost } from "./fake";

const hosts = sampleHosts; // LAB-CORE 10.9.0.1 (con credencial), LAB-AP ap1.lab:2222, OFI-SW 10.8.0.1
const pick = async (name: string) => {
  const open = await screen.findByRole("button", { name: "Elegir de la libreta" });
  if (open.getAttribute("aria-expanded") !== "true") await userEvent.click(open); // el selector queda abierto tras elegir
  await userEvent.selectOptions(await screen.findByLabelText("Host de la libreta"), hosts.find((h) => h.name === name)!.id);
};

function One({ onCred }: { onCred?: (id: string) => void }) {
  const [v, setV] = useState("");
  return <TargetField core={fakeCore()} value={v} onChange={setV} onPickCredential={onCred} />;
}
function Many({ start = "" }: { start?: string }) {
  const [v, setV] = useState(start);
  return <TargetsField core={fakeCore()} value={v} onChange={setV} />;
}

test("un equipo: etiqueta común, escribir a mano y elegir de la libreta (con puerto y credencial)", async () => {
  const onCred = vi.fn();
  render(<One onCred={onCred} />);
  const input = screen.getByLabelText("Equipo (IP o nombre, con :puerto opcional)");
  await userEvent.type(input, "1.1.1.1");
  expect(input).toHaveValue("1.1.1.1");
  await pick("LAB-CORE");
  expect(input).toHaveValue("10.9.0.1");
  expect(onCred).toHaveBeenLastCalledWith(hosts[0].credentialId);
  onCred.mockClear();
  await pick("LAB-AP"); // sin credencial: no se llama
  expect(input).toHaveValue("ap1.lab:2222");
  expect(onCred).not.toHaveBeenCalled();
});

test("varios equipos: etiqueta común, agrega sin duplicar y respeta lo escrito", async () => {
  render(<Many start="sw9" />);
  const area = screen.getByLabelText("Equipos (IP o nombre, con :puerto opcional)");
  await pick("LAB-CORE");
  await pick("LAB-AP");
  await pick("LAB-CORE"); // ya estaba
  expect(area).toHaveValue("sw9\n10.9.0.1\nap1.lab:2222");
});

test("libreta vacía: no hay botón", async () => {
  const listHosts = vi.fn(async () => []);
  render(<TargetField core={fakeCore({ listHosts })} value="" onChange={() => {}} />);
  await waitFor(() => expect(listHosts).toHaveBeenCalled());
  expect(screen.getByLabelText("Equipo (IP o nombre, con :puerto opcional)")).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Elegir de la libreta" })).toBeNull();
});

const linux = { ...sampleHosts[2], id: "e".repeat(32), name: "SRV-LINUX", address: "10.5.0.1", platform: "linux" as const };

test("teclado: elegir no cierra el selector; «Listo» lo cierra y devuelve el foco al botón (aria-controls)", async () => {
  render(<One />);
  const btn = await screen.findByRole("button", { name: "Elegir de la libreta" });
  await userEvent.click(btn);
  expect(document.getElementById(btn.getAttribute("aria-controls")!)).toBeInTheDocument();
  await userEvent.selectOptions(await screen.findByLabelText("Host de la libreta"), hosts[0].id);
  expect(screen.getByLabelText("Host de la libreta")).toBeInTheDocument(); // sigue abierto: con flechas el primer change no puede cerrarlo
  await userEvent.selectOptions(screen.getByLabelText("Host de la libreta"), hosts[1].id);
  await userEvent.click(screen.getByRole("button", { name: "Listo" }));
  expect(screen.queryByLabelText("Host de la libreta")).toBeNull();
  expect(btn).toHaveFocus();
  expect(btn).not.toHaveAttribute("aria-controls", "");
});

test("sin equipos de inicio (linux/windows): no se ofrecen, y sin otros hosts no hay botón; la terminal ve todos", async () => {
  const listHosts = vi.fn(async () => [...hosts, linux]);
  const { unmount } = render(<TargetField core={fakeCore({ listHosts })} value="" onChange={() => {}} />);
  await userEvent.click(await screen.findByRole("button", { name: "Elegir de la libreta" }));
  expect(screen.queryByRole("option", { name: /SRV-LINUX/ })).toBeNull();
  expect(screen.getByRole("option", { name: /LAB-CORE/ })).toBeInTheDocument();
  expect(listHosts).toHaveBeenCalledTimes(1); // Pick pasa la lista: el selector no la vuelve a pedir
  unmount();
  render(<TargetField core={fakeCore({ listHosts: vi.fn(async () => [linux]) })} value="" onChange={() => {}} />);
  await waitFor(() => expect(screen.getByLabelText("Equipo (IP o nombre, con :puerto opcional)")).toBeInTheDocument());
  expect(screen.queryByRole("button", { name: "Elegir de la libreta" })).toBeNull();
});

test("credencial de la libreta: otro host de la libreta la reemplaza; una elegida a mano no se pisa", async () => {
  const creds = [{ id: "x1", label: "", username: "", hasEnable: false, hasSshKey: false }, { id: "x2", label: "", username: "", hasEnable: false, hasSshKey: false }, { id: "m", label: "", username: "", hasEnable: false, hasSshKey: false }] as never[];
  const withCred = [{ ...hosts[0], credentialId: "x1" }, { ...hosts[1], credentialId: "x2" }];
  function V() {
    const [v, setV] = useState("");
    const [cred, setCred] = useState("");
    const bc = useBookCredential(creds, cred, setCred);
    return <><TargetField core={fakeCore({ listHosts: vi.fn(async () => withCred) })} value={v} onChange={setV} onPickCredential={bc.onPickCredential} /><button onClick={() => bc.onChange("m")}>manual</button><output>{cred}</output></>;
  }
  render(<V />);
  await pick("LAB-CORE");
  expect(screen.getByRole("status")).toHaveTextContent("x1");
  await pick("LAB-AP");
  expect(screen.getByRole("status")).toHaveTextContent("x2"); // venía de la libreta
  await userEvent.click(screen.getByRole("button", { name: "manual" }));
  await pick("LAB-CORE");
  expect(screen.getByRole("status")).toHaveTextContent("m"); // elegida a mano
});

test("el selector de la libreta no ofrece hosts telnet (esas tareas conectan por SSH)", async () => {
  const inv = fakeInventory([...sampleHosts, telnetHost]);
  render(<TargetField core={fakeCore({ ...inv })} value="" onChange={() => {}} />);
  await userEvent.click(await screen.findByRole("button", { name: "Elegir de la libreta" }));
  const sel = await screen.findByLabelText("Host de la libreta");
  expect(within(sel).getByRole("option", { name: /OFI-SW/ })).toBeInTheDocument();
  expect(within(sel).queryByRole("option", { name: /OLD-SW/ })).toBeNull();
});
