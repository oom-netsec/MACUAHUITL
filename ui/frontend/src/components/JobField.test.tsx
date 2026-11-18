import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { JobField } from "./JobField";
import { fakeCore } from "../lib/fake";
import type { Job } from "../lib/core";

const jobs: Job[] = [
  { id: "old", name: "Viejo", state: "completed", finishedAt: "2026-11-10T10:00:00Z", past: true },
  { id: "new", name: "Nuevo", state: "armed", armedAt: "2026-11-17T10:00:00Z" },
  { id: "mid", name: "Medio", state: "failed", finishedAt: "2026-11-15T10:00:00Z" },
  { id: "draft", name: "Borrador", state: "created" },
];
function Host({ core, spy }: { core: ReturnType<typeof fakeCore>; spy?: (v: string) => void }) {
  const [v, setV] = useState("");
  spy?.(v);
  return <JobField core={core} label="Trabajo o carpeta" value={v} onChange={setV} />;
}
const sel = () => screen.getByLabelText("Trabajo o carpeta");

test("lista los trabajos del más reciente al más viejo, con nombre, fecha y estado, y «Otra carpeta…» al final", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs) });
  render(<Host core={core} />);
  await screen.findByRole("option", { name: /Nuevo/ });
  expect(core.listJobs).toHaveBeenCalledWith({ includePast: true });
  const o = within(sel()).getAllByRole("option").map((x) => x.textContent ?? "");
  expect(o.map((x) => x.split(" · ")[0])).toEqual(["Seleccionar…", "Nuevo", "Medio", "Viejo", "Borrador", "Otra carpeta…"]);
  expect(o[1]).toMatch(/Nuevo · .+ · Armado/);
  expect(o[2]).toMatch(/Medio · .+ · Con error/);
  expect(o[4]).toBe("Borrador · Creado"); // sin fecha
});

test("elegir un trabajo envía su ID; «Otra carpeta…» muestra el campo de texto y lo escrito se envía tal cual", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs) });
  const seen: string[] = [];
  render(<Host core={core} spy={(v) => seen.push(v)} />);
  await screen.findByRole("option", { name: /Nuevo/ });
  expect(screen.queryByLabelText("ID o ruta del trabajo")).toBeNull();
  await userEvent.selectOptions(sel(), "new");
  expect(seen.at(-1)).toBe("new");
  await userEvent.selectOptions(sel(), "Otra carpeta…");
  await userEvent.type(screen.getByLabelText("ID o ruta del trabajo"), "/o/lab");
  expect(seen.at(-1)).toBe("/o/lab");
});

test("sin trabajos o sin núcleo queda el campo de texto con la misma etiqueta", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => []) });
  render(<Host core={core} />);
  await userEvent.type(await screen.findByRole("textbox", { name: "Trabajo o carpeta" }), "/o/lab");
  expect(screen.getByRole("textbox", { name: "Trabajo o carpeta" })).toHaveValue("/o/lab");
});

test("un valor que no es de la lista (una ruta) abre el campo de texto con ese valor", async () => {
  const core = fakeCore({ listJobs: vi.fn(async () => jobs) });
  function Pre() { const [v, setV] = useState("/o/previo"); return <JobField core={core} label="Trabajo o carpeta" value={v} onChange={setV} />; }
  render(<Pre />);
  await screen.findByRole("option", { name: /Nuevo/ });
  expect(sel()).toHaveValue("__other__");
  expect(screen.getByLabelText("ID o ruta del trabajo")).toHaveValue("/o/previo");
});
