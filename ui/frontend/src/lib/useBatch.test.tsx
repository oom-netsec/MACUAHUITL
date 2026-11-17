import { act, renderHook } from "@testing-library/react";
import { useBatch } from "./useBatch";

afterEach(() => vi.useRealTimers());

test("junta los eventos y los entrega en orden en un solo apply por lote", () => {
  vi.useFakeTimers();
  const apply = vi.fn();
  const { result } = renderHook(() => useBatch<number>(apply));
  act(() => { for (let i = 0; i < 500; i++) result.current.push(i); });
  expect(apply).not.toHaveBeenCalled();
  act(() => { vi.advanceTimersByTime(100); });
  expect(apply).toHaveBeenCalledTimes(1);
  expect(apply.mock.calls[0][0]).toEqual(Array.from({ length: 500 }, (_, i) => i));
});

test("flush entrega lo pendiente de inmediato y reset lo descarta", () => {
  vi.useFakeTimers();
  const apply = vi.fn();
  const { result } = renderHook(() => useBatch<string>(apply));
  act(() => { result.current.push("a"); result.current.flush(); });
  expect(apply).toHaveBeenCalledWith(["a"], 1);
  act(() => { result.current.push("b"); result.current.reset(); vi.advanceTimersByTime(500); });
  expect(apply).toHaveBeenCalledTimes(1);
});
