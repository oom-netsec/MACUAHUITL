import { cleanTerminal } from "./stream";

test("limpia secuencias de terminal, retornos y retrocesos", () => {
  expect(cleanTerminal("", "a\x1b[2Kb\r\nc\x1b[0;1mX")).toBe("ab\ncX");
  expect(cleanTerminal("Switch>", "\b\b#")).toBe("Switc#");
  expect(cleanTerminal("x", "\x07--More--")).toBe("x--More--");
});
