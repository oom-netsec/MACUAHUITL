import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SyslogPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";

const ifaces = [{ name: "eth0", up: true, loopback: false, addresses: ["192.0.2.10/24"], hardwareAddr: "" }];
async function setup() {
  const core = fakeCore({ listInterfaces: vi.fn(async () => ifaces), syslogStart: vi.fn(async () => "s1") });
  render(<SyslogPanel core={core} />);
  await screen.findByRole("option", { name: /192.0.2.10/ });
  return core;
}
const listen = () => userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
const sel = () => screen.getByLabelText("Dirección de escucha");

test("syslog: «Dirección de escucha» es un select con las IP locales y «Todas» al final; la casilla ya no existe", async () => {
  await setup();
  expect(sel().tagName).toBe("SELECT");
  expect(screen.getAllByRole("option").map((o) => o.textContent)).toEqual(expect.arrayContaining(["192.0.2.10 · eth0", "Todas las interfaces (0.0.0.0)"]));
  expect(screen.queryByLabelText(/Escuchar en todas las interfaces/)).toBeNull();
});

test("syslog: sin tocar nada se envía lo mismo que antes", async () => {
  const core = await setup();
  await listen();
  expect(core.syslogStart).toHaveBeenLastCalledWith("127.0.0.1:5514", "udp", false, false, {});
});

test("syslog: con IP y puerto elegidos se envía host:puerto", async () => {
  const core = await setup();
  await userEvent.selectOptions(sel(), "192.0.2.10");
  await userEvent.clear(screen.getByLabelText("Puerto"));
  await userEvent.type(screen.getByLabelText("Puerto"), "6000");
  await listen();
  expect(core.syslogStart).toHaveBeenLastCalledWith("192.0.2.10:6000", "udp", false, false, {});
});

test("syslog: con «Todas» no se envía la IP elegida: va 0.0.0.0 con el puerto y any", async () => {
  const core = await setup();
  await userEvent.selectOptions(sel(), "192.0.2.10");
  await userEvent.selectOptions(sel(), "Todas las interfaces (0.0.0.0)");
  await listen();
  expect(core.syslogStart).toHaveBeenLastCalledWith("0.0.0.0:5514", "udp", true, false, {});
});
