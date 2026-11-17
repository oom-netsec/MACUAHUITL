import { act, renderHook } from "@testing-library/react";
import { useAction } from "./useAction";

const defer = <T,>() => { let ok!: (v: T) => void; let ko!: (e: unknown) => void; const p = new Promise<T>((a, b) => { ok = a; ko = b; }); return { p, ok, ko }; };

test("éxito: busy durante la espera y resultado devuelto", async () => {
  const d = defer<number>();
  const { result } = renderHook(() => useAction((n: number) => d.p.then((v) => v + n)));
  let r: Promise<number | undefined>;
  act(() => { r = result.current.run(1); });
  expect(result.current.busy).toBe(true);
  await act(async () => { d.ok(41); await r; });
  expect(result.current.busy).toBe(false);
  expect(result.current.error).toBe("");
  await expect(r!).resolves.toBe(42);
});

test("error: guarda el texto sin el prefijo rpc, run resuelve a undefined, y clearError lo limpia; el siguiente run lo borra", async () => {
  const fn = vi.fn().mockRejectedValueOnce(new Error("rpc error: code = Internal desc = falló")).mockResolvedValue("ok");
  const { result } = renderHook(() => useAction(fn));
  await act(async () => { expect(await result.current.run()).toBeUndefined(); });
  expect(result.current.error).toBe("falló");
  expect(result.current.busy).toBe(false);
  let r: Promise<unknown>;
  act(() => { r = result.current.run(); }); // un run nuevo borra el error viejo desde que arranca
  expect(result.current.error).toBe("");
  await act(async () => { await r; });
  expect(result.current.error).toBe("");
  fn.mockRejectedValueOnce(new Error("otra"));
  await act(async () => { await result.current.run(); });
  expect(result.current.error).toBe("otra");
  act(() => result.current.clearError());
  expect(result.current.error).toBe("");
});

test("desmontado: no hay setState ni aviso al resolver", async () => {
  const err = vi.spyOn(console, "error").mockImplementation(() => {});
  const d = defer<void>();
  const { result, unmount } = renderHook(() => useAction(() => d.p));
  let r: Promise<unknown>;
  act(() => { r = result.current.run(); });
  unmount();
  await act(async () => { d.ko(new Error("tarde")); await r; });
  expect(err).not.toHaveBeenCalled();
  err.mockRestore();
});

test("llamadas que se pisan: solo la última fija el estado final", async () => {
  const a = defer<void>(); const b = defer<void>();
  const ds = [a, b];
  let i = 0;
  const { result } = renderHook(() => useAction(() => ds[i++].p));
  let r1: Promise<unknown>; let r2: Promise<unknown>;
  act(() => { r1 = result.current.run(); r2 = result.current.run(); });
  await act(async () => { b.ok(); await r2; });
  expect(result.current.busy).toBe(false);
  await act(async () => { a.ko(new Error("vieja")); await r1; }); // la primera llega tarde y falla: no pisa
  expect(result.current.error).toBe("");
  expect(result.current.busy).toBe(false);
});
