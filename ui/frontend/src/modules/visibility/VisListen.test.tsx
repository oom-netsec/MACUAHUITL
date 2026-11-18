import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { VisibilityView } from "./VisibilityView";
import { fakeCore } from "../../lib/fake";

const ifaces = [{ name: "eth0", up: true, loopback: false, addresses: ["192.0.2.10/24"], hardwareAddr: "" }, { name: "eth1", up: false, loopback: false, addresses: ["198.51.100.1/24"], hardwareAddr: "" }];
async function setup(tab: "Traps" | "Flujos") {
  const core = fakeCore({ listInterfaces: vi.fn(async () => ifaces), trapsStart: vi.fn(async () => "t1"), flowsStart: vi.fn(async () => "f1") });
  render(<VisibilityView core={core} />);
  await userEvent.click(screen.getByRole("tab", { name: tab }));
  await screen.findByRole("option", { name: /192.0.2.10/ });
  return core;
}
const listen = () => userEvent.click(screen.getByRole("button", { name: "Escuchar" }));

test.each([["Traps", "trapsStart", "1162"], ["Flujos", "flowsStart", "2055"]] as const)("%s: «Dirección de escucha» es un select con las IP de interfaces arriba y «Todas» al final; la casilla ya no existe", async (tab) => {
  await setup(tab);
  const o = within(screen.getByLabelText("Dirección de escucha")).getAllByRole("option").map((x) => x.textContent);
  expect(o).toContain("192.0.2.10 · eth0");
  expect(o).not.toContain("198.51.100.1 · eth1"); // interfaz caída
  expect(o.at(-1)).toBe("Todas las interfaces (0.0.0.0)");
  expect(screen.getByLabelText("Dirección de escucha").tagName).toBe("SELECT");
  expect(screen.queryByLabelText(/Escuchar en todas las interfaces/)).toBeNull();
});

const cases = [["Traps", "trapsStart", "1162"], ["Flujos", "flowsStart", "2055"]] as const;
const sent = (core: Awaited<ReturnType<typeof setup>>, fn: "trapsStart" | "flowsStart") => core[fn].mock.calls.at(-1)!.slice(0, 2);

test.each(cases)("%s: sin tocar nada se envía lo mismo que antes (127.0.0.1 con su puerto, sin «todas»)", async (tab, fn, port) => {
  const core = await setup(tab);
  await listen();
  expect(sent(core, fn)).toEqual([`127.0.0.1:${port}`, false]);
});

test.each(cases)("%s: una IP elegida y un puerto editado se envían como host:puerto", async (tab, fn) => {
  const core = await setup(tab);
  await userEvent.selectOptions(screen.getByLabelText("Dirección de escucha"), "192.0.2.10");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "9999");
  await listen();
  expect(sent(core, fn)).toEqual(["192.0.2.10:9999", false]);
});

test.each(cases)("%s: con «Todas» no se envía la IP elegida: va 0.0.0.0 con el puerto y any", async (tab, fn, port) => {
  const core = await setup(tab);
  await userEvent.selectOptions(screen.getByLabelText("Dirección de escucha"), "192.0.2.10");
  await userEvent.selectOptions(screen.getByLabelText("Dirección de escucha"), "Todas las interfaces (0.0.0.0)");
  await listen();
  expect(sent(core, fn)).toEqual([`0.0.0.0:${port}`, true]);
  expect(JSON.stringify(core[fn].mock.calls.at(-1))).not.toContain("192.0.2.10");
});
