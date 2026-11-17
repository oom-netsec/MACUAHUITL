import { cleanTerminal } from "./stream";

test("limpia secuencias de terminal, retornos y retrocesos", () => {
  expect(cleanTerminal("", "a\x1b[2Kb\r\nc\x1b[0;1mX")).toBe("ab\ncX");
  expect(cleanTerminal("Switch>", "\b\b#")).toBe("Switc#");
  expect(cleanTerminal("x", "\x07--More--")).toBe("x--More--");
});

test("retrocesos: varios seguidos, desde prev y más allá del inicio", () => {
  expect(cleanTerminal("abc", "\b\b\bx")).toBe("x");
  expect(cleanTerminal("ab", "\b\b\b\bz")).toBe("z");
  expect(cleanTerminal("", "ab\bc\b\bd")).toBe("d");
  expect(cleanTerminal("abc", "xy\b\b\bq")).toBe("abq");
  expect(cleanTerminal("a", "\b")).toBe("");
});

test("un chunk de 1 MB se limpia rápido", () => {
  const chunk = "linea de salida con \x1b[1mcolor\x1b[0m y retroceso\b\r\n".repeat(20000).slice(0, 1_000_000);
  const t0 = performance.now();
  cleanTerminal("", chunk, 10_000_000);
  expect(performance.now() - t0).toBeLessThan(500);
});
