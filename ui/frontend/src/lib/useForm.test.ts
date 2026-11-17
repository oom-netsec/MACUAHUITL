import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { useForm } from "./useForm";

describe("useForm", () => {
  it("cambia solo el campo pedido y set no cambia entre renders", () => {
    const { result } = renderHook(() => useForm({ host: "", port: "1812" }));
    const set0 = result.current[1];
    act(() => result.current[1]("host")("10.0.0.1"));
    expect(result.current[0]).toEqual({ host: "10.0.0.1", port: "1812" });
    expect(result.current[1]).toBe(set0);
  });
});
