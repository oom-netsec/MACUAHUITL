import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { EmptyState, Page, ResultPanel, Section, Tabs, useResult } from "./Page";

test("Page tiene un encabezado con título y descripción y lo usa como nombre de la región", () => {
  render(<Page title="Ping" description="Alcance y latencia." actions={<button>Historial</button>}><p>cuerpo</p></Page>);
  const region = screen.getByRole("region", { name: "Ping" });
  expect(region).toHaveAccessibleDescription("Alcance y latencia.");
  expect(screen.getByRole("heading", { level: 2, name: "Ping" })).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Historial" })).toBeInTheDocument();
});

test("Section agrupa con su título de nivel 3", () => {
  render(<Section title="Destino"><p>x</p></Section>);
  expect(screen.getByRole("region", { name: "Destino" })).toBeInTheDocument();
  expect(screen.getByRole("heading", { level: 3, name: "Destino" })).toBeInTheDocument();
});

test("Tabs: un solo patrón de pestañas, navegable con flechas", async () => {
  function Host() {
    const [v, setV] = useState("a");
    return <Tabs label="Herramientas" value={v} onChange={setV} tabs={[["a", "Subred"], ["b", "VLSM"], ["c", "IPv6"]]} />;
  }
  render(<Host />);
  const list = screen.getByRole("tablist", { name: "Herramientas" });
  expect(list).toBeInTheDocument();
  const [a, b, c] = screen.getAllByRole("tab");
  expect(a).toHaveAttribute("aria-selected", "true");
  expect(b).toHaveAttribute("tabindex", "-1");
  act(() => a.focus());
  await userEvent.keyboard("{ArrowRight}");
  expect(b).toHaveFocus();
  expect(b).toHaveAttribute("aria-selected", "true");
  await userEvent.keyboard("{ArrowLeft}{ArrowLeft}");
  expect(c).toHaveFocus();
  expect(c).toHaveAttribute("aria-selected", "true");
});

test("useResult guarda el resultado o el error de la última ejecución y avisa que está ocupado", async () => {
  const { result } = renderHook(() => useResult<string>());
  let release!: (v: string) => void;
  act(() => { void result.current.run(() => new Promise<string>((r) => { release = r; })); });
  expect(result.current.busy).toBe(true);
  await act(async () => release("listo"));
  expect(result.current).toMatchObject({ busy: false, data: "listo", error: "" });
  await act(async () => { await result.current.run(async () => { throw new Error("rpc error: code = Unavailable desc = sin conexión"); }); });
  expect(result.current).toMatchObject({ busy: false, data: null, error: "sin conexión" });
});

test("ResultPanel muestra estado y acciones; el error se anuncia como alerta", async () => {
  const { rerender } = render(<ResultPanel title="Resultado" status={{ tone: "ok", label: "Completado" }} meta="99 s" actions={<button>Copiar</button>}><pre>salida</pre></ResultPanel>);
  expect(screen.getByRole("region", { name: "Resultado" })).toHaveTextContent("Completado");
  expect(screen.getByText("99 s")).toBeInTheDocument();
  rerender(<ResultPanel title="Resultado" error="sin conexión" />);
  await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("sin conexión"));
});

test("EmptyState dice qué hacer primero y ofrece la acción", () => {
  render(<EmptyState title="Sin corridas" action={<button>Ir a Patrol</button>}>Las corridas aparecen al terminar un trabajo.</EmptyState>);
  expect(screen.getByText("Sin corridas")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Ir a Patrol" })).toBeInTheDocument();
});
