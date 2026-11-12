import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SyslogPanel } from "./ToolsView";
import { fakeCore } from "../../lib/fake";

const msg = (n: number, sev: number, mn = "LINK-3-UPDOWN") => JSON.stringify({ Time: `2026-11-06T18:0${n % 10}:00Z`, From: `10.0.0.${n}:514`, Severity: sev, Mnemonic: mn, Text: `evento ${n}`, Raw: `<1>%${mn}: evento ${n}` });

async function listening() {
  const core = fakeCore({ syslogStart: vi.fn(async () => "s1") });
  render(<SyslogPanel core={core} />);
  await userEvent.click(screen.getByRole("button", { name: "Escuchar" }));
  return core;
}

test("los mensajes llegan a una tabla con hora, origen, severidad, mnemónico y mensaje", async () => {
  const core = await listening();
  act(() => core.emitSyslog({ runId: "s1", json: msg(2, 3) }));
  const table = await screen.findByRole("table", { name: "Mensajes recibidos" });
  expect(within(table).getAllByRole("columnheader").map((h) => h.textContent)).toEqual(["Hora", "Origen", "Severidad", "Mnemónico", "Mensaje"]);
  const cells = within(within(table).getAllByRole("row")[1]).getAllByRole("cell");
  expect(cells[1]).toHaveTextContent("10.0.0.2:514");
  expect(cells[2]).toHaveTextContent("3 · Error");
  expect(cells[3]).toHaveTextContent("LINK-3-UPDOWN");
  expect(cells[4]).toHaveTextContent("evento 2");
});

test("el filtro rápido por severidad deja solo el grupo elegido y cuenta cada grupo", async () => {
  const core = await listening();
  act(() => {
    core.emitSyslog({ runId: "s1", json: msg(1, 3) });
    core.emitSyslog({ runId: "s1", json: msg(2, 4, "SYS-4-X") });
    core.emitSyslog({ runId: "s1", json: msg(3, 6, "SYS-6-Y") });
  });
  await screen.findByRole("table", { name: "Mensajes recibidos" });
  expect(screen.getByLabelText("Todas (3)")).toBeChecked();
  await userEvent.click(screen.getByLabelText("Error o peor (1)"));
  const table = screen.getByRole("table", { name: "Mensajes recibidos" });
  expect(within(table).getAllByRole("row")).toHaveLength(2);
  expect(within(table).getByRole("cell", { name: "evento 1" })).toBeInTheDocument();
});

test("pausar congela la tabla y avisa cuántos mensajes llegaron; reanudar los muestra", async () => {
  const core = await listening();
  act(() => core.emitSyslog({ runId: "s1", json: msg(1, 3) }));
  await screen.findByRole("table", { name: "Mensajes recibidos" });
  await userEvent.click(screen.getByRole("button", { name: "Pausar" }));
  act(() => { core.emitSyslog({ runId: "s1", json: msg(2, 3) }); core.emitSyslog({ runId: "s1", json: msg(3, 3) }); });
  await act(async () => { await new Promise((r) => setTimeout(r, 160)); }); // los mensajes se vuelcan a la lista cada ~100 ms
  expect(screen.getByText("En pausa: 2 mensajes nuevos sin mostrar")).toBeInTheDocument();
  expect(within(screen.getByRole("table", { name: "Mensajes recibidos" })).getAllByRole("row")).toHaveLength(2);
  await userEvent.click(screen.getByRole("button", { name: "Reanudar" }));
  expect(within(screen.getByRole("table", { name: "Mensajes recibidos" })).getAllByRole("row")).toHaveLength(4);
});

test("muestra los mensajes por minuto como minigráfica con su descripción", async () => {
  const core = await listening();
  act(() => core.emitSyslog({ runId: "s1", json: msg(1, 3) }));
  expect(await screen.findByRole("img", { name: /Mensajes por minuto/ })).toBeInTheDocument();
});

test("con miles de mensajes solo se pintan las filas visibles", async () => {
  const core = await listening();
  act(() => { for (let i = 0; i < 3000; i++) core.emitSyslog({ runId: "s1", json: msg(i, 6, "SYS-6-Z") }); });
  const table = await screen.findByRole("table", { name: "Mensajes recibidos" });
  expect(within(table).getAllByRole("row").length).toBeLessThan(80);
  expect(screen.getByText("3000 mensajes")).toBeInTheDocument();
});
