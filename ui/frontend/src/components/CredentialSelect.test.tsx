import { act, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { NavContext } from "../app/activity";
import { vaultChanged } from "../lib/vaultSignal";
import type { Credential, VaultState } from "../modules/vault/api";
import { CredentialSelect, useCredentials } from "./CredentialSelect";

const cred = (id: string, kind?: "key"): Credential => ({ id, label: id, username: `u-${id}`, kind, hasEnable: false, hasSshKey: false });
const ALL = [cred("a"), cred("k", "key"), cred("b")];

function core(state: VaultState, list = ALL) {
  return {
    vaultStatus: vi.fn(async () => ({ state, armedJobs: [] })),
    listCredentials: vi.fn(async () => { if (state !== "unlocked") throw new Error("vault locked"); return list; }),
  } as never;
}

test("el hook ofrece solo contraseñas, y con keys también las llaves", async () => {
  const c = core("unlocked");
  const pw = renderHook(() => useCredentials(c));
  await waitFor(() => expect(pw.result.current.vault).toBe("open"));
  expect(pw.result.current.creds.map((x) => x.id)).toEqual(["a", "b"]);
  const all = renderHook(() => useCredentials(c, { keys: true }));
  await waitFor(() => expect(all.result.current.creds.map((x) => x.id)).toEqual(["a", "k", "b"]));
});

test("el hook distingue bóveda inexistente, cerrada y abierta pero vacía", async () => {
  for (const [state, want] of [["absent", "absent"], ["locked", "locked"], ["unlocked", "open"]] as const) {
    const { result } = renderHook(() => useCredentials(core(state, [])));
    await waitFor(() => expect(result.current.vault).toBe(want));
    expect(result.current.creds).toEqual([]);
  }
});

test("si el núcleo no responde, el hook dice error con el texto y no aparenta bóveda cerrada", async () => {
  const c = { vaultStatus: vi.fn(async () => { throw new Error("sin núcleo"); }), listCredentials: vi.fn() } as never;
  const { result } = renderHook(() => useCredentials(c));
  await waitFor(() => expect(result.current.vault).toBe("error"));
  expect(result.current.error).toContain("sin núcleo");
});

test("el hook vuelve a listar cuando la bóveda cambia", async () => {
  const c = core("unlocked");
  renderHook(() => useCredentials(c));
  await waitFor(() => expect((c as { listCredentials: { mock: { calls: unknown[] } } }).listCredentials.mock.calls.length).toBe(1));
  act(() => vaultChanged());
  await waitFor(() => expect((c as { listCredentials: { mock: { calls: unknown[] } } }).listCredentials.mock.calls.length).toBe(2));
});

function Host({ creds, initial = "", ...p }: { creds: Credential[]; initial?: string } & Partial<React.ComponentProps<typeof CredentialSelect>>) {
  const [v, setV] = useState(initial);
  return <><CredentialSelect creds={creds} vault="open" value={v} onChange={setV} {...p} /><span data-testid="v">{v}</span></>;
}

test("etiqueta «Credencial» por omisión, opciones «etiqueta (usuario)» y ayuda como descripción", () => {
  render(<Host creds={[cred("a")]} hint="ayuda" />);
  expect(screen.getByLabelText("Credencial")).toHaveAccessibleDescription("ayuda");
  expect(screen.getByRole("option", { name: "a (u-a)" })).toBeInTheDocument();
});

test("regla de valor por defecto: se conserva el actual si sigue en la lista; si no, la primera", async () => {
  const { unmount } = render(<Host creds={[cred("a"), cred("b")]} initial="b" />);
  await waitFor(() => expect(screen.getByTestId("v")).toHaveTextContent("b"));
  unmount();
  render(<Host creds={[cred("a"), cred("b")]} initial="borrada" />);
  await waitFor(() => expect(screen.getByTestId("v")).toHaveTextContent("a"));
});

test("sin credenciales el valor queda vacío", async () => {
  render(<Host creds={[]} initial="vieja" />);
  await waitFor(() => expect(screen.getByTestId("v")).toHaveTextContent(/^$/));
});

test("optional: primera opción «ninguna» y el valor vacío se respeta", async () => {
  render(<Host creds={[cred("a")]} optional />);
  expect(screen.getAllByRole("option")[0]).toHaveTextContent("(ninguna)");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "a");
  expect(screen.getByTestId("v")).toHaveTextContent("a");
  await userEvent.selectOptions(screen.getByLabelText("Credencial"), "");
  expect(screen.getByTestId("v")).toHaveTextContent(/^$/);
});

test("extra: un valor fuera de la lista (credencial oculta) se conserva", async () => {
  render(<Host creds={[]} initial="oculta" optional extra={["oculta", "No visible"]} />);
  await waitFor(() => expect(screen.getByRole("option", { name: "No visible" })).toBeInTheDocument());
  expect(screen.getByTestId("v")).toHaveTextContent("oculta");
});

test("bóveda cerrada o inexistente: aviso con botón que abre el módulo bóveda", async () => {
  const go = vi.fn();
  render(<NavContext.Provider value={{ go, inbox: {} }}><Host creds={[]} vault="locked" /></NavContext.Provider>);
  expect(screen.getByRole("status")).toHaveTextContent("cerrada");
  await userEvent.click(screen.getByRole("button", { name: "Abrir bóveda" }));
  expect(go).toHaveBeenCalledWith("vault");
});

test("bóveda inexistente ofrece crearla; abierta y vacía no muestra aviso", () => {
  const { rerender } = render(<Host creds={[]} vault="absent" />);
  expect(screen.getByRole("button", { name: "Crear bóveda" })).toBeInTheDocument();
  rerender(<Host creds={[]} vault="open" />);
  expect(screen.queryByRole("status")).toBeNull();
});

test("mientras carga, o con la bóveda cerrada, el valor elegido no se toca (editar un host no pierde su credencial)", async () => {
  const { rerender } = render(<Host creds={[]} initial="c9" vault="loading" />);
  rerender(<Host creds={[]} initial="c9" vault="locked" />);
  await act(async () => {});
  expect(screen.getByTestId("v")).toHaveTextContent("c9");
  rerender(<Host creds={[cred("a"), cred("c9")]} initial="c9" vault="open" />);
  await act(async () => {});
  expect(screen.getByTestId("v")).toHaveTextContent("c9");
});

test("si el núcleo no responde se ve el error; notice={false} lo calla junto con el de bóveda cerrada", () => {
  const { rerender } = render(<Host creds={[]} vault="error" vaultError="sin núcleo" />);
  expect(screen.getByRole("alert")).toHaveTextContent("No se pudo leer la bóveda: sin núcleo");
  rerender(<Host creds={[]} vault="error" vaultError="sin núcleo" notice={false} />);
  expect(screen.queryByRole("alert")).toBeNull();
  rerender(<Host creds={[]} vault="locked" notice={false} />);
  expect(screen.queryByRole("status")).toBeNull();
});

test("con la bóveda cerrada el valor conservado se ve como tal, no como «ninguna»", () => {
  render(<Host creds={[]} initial="x9" vault="locked" optional notice={false} />);
  expect(screen.getByLabelText("Credencial")).toHaveDisplayValue("Credencial guardada (bóveda cerrada)");
});

test("si la lista falla con la bóveda todavía abierta, el hook dice error y no «cerrada»", async () => {
  const c = { vaultStatus: vi.fn(async () => ({ state: "unlocked", armedJobs: [] })), listCredentials: vi.fn(async () => { throw new Error("corte"); }) } as never;
  const { result } = renderHook(() => useCredentials(c));
  await waitFor(() => expect(result.current.vault).toBe("error"));
  expect(result.current.error).toContain("corte");
});
