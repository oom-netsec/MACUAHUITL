import { pasteNeedsConfirm, safeFileName, showHidden } from "./safeText";

test("pegar pide confirmación con saltos de línea y con controles, no con texto normal ni tabulador", () => {
  expect(pasteNeedsConfirm("show version")).toBe(false);
  expect(pasteNeedsConfirm("show\tversion")).toBe(false);
  expect(pasteNeedsConfirm("a\nb")).toBe(true);
  expect(pasteNeedsConfirm("a\rb")).toBe(true);
  expect(pasteNeedsConfirm("shutdown\x1a")).toBe(true); // Ctrl+Z ejecuta la línea en IOS
  expect(pasteNeedsConfirm("x\x1b[201~rm -rf ~\x0f")).toBe(true);
  expect(pasteNeedsConfirm("x\x9b")).toBe(true); // CSI de 8 bits
  expect(pasteNeedsConfirm("x\x7f")).toBe(true);
});

test("showHidden marca controles y bidi, y deja el texto normal y el tabulador", () => {
  expect(showHidden("description a‮b")).toBe("description a⟦U+202E⟧b");
  expect(showHidden("x​y")).toBe("x⟦U+200B⟧y");
  expect(showHidden("shutdown\x1a")).toBe("shutdown⟦U+001A⟧");
  expect(showHidden("a\tb ñ")).toBe("a\tb ñ");
});

test("safeFileName quita carpetas, controles e invisibles y el punto inicial", () => {
  expect(safeFileName("../../.config/x‮vsc.csv")).toBe("__.._.config_x_vsc.csv");
  expect(safeFileName("a\\b")).toBe("a_b");
  expect(safeFileName(".bashrc")).toBe("_bashrc");
  expect(safeFileName("SW1-cpu.csv")).toBe("SW1-cpu.csv");
  expect(safeFileName("a\x00b\nc")).toBe("a_b_c");
});
