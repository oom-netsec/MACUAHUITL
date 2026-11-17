import { pasteNeedsConfirm, pastePreview, safeFileName, showHidden, stripAnsi } from "./safeText";

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

test("showHidden también marca guion suave, separador de línea, etiquetas Unicode y surrogates sueltos", () => {
  expect(showHidden("a\u00adb")).toBe("a⟦U+00AD⟧b");
  expect(showHidden("a\u2028b")).toBe("a⟦U+2028⟧b");
  expect(showHidden("ok\u{E0063}")).toBe("ok⟦U+E0063⟧");
  expect(showHidden("x\ud800")).toBe("x⟦U+D800⟧");
});

test("la vista previa de pegar lista los códigos ocultos aunque queden fuera de las 80 columnas", () => {
  const p = pastePreview(`show version${" ".repeat(90)}\x15\x10\x1a`);
  expect(p.n).toBe(1);
  expect(p.preview).not.toMatch(/U\+/);
  expect(p.controls).toBe("⟦U+0015⟧ ⟦U+0010⟧ ⟦U+001A⟧");
  expect(pastePreview("a\nb").controls).toBe("");
});

describe("stripAnsi", () => {
  const E = "\u001b";
  test.each([
    ["CSI con parámetros", `${E}[1;31mrojo${E}[0m`, "rojo"],
    ["CSI con «?» y «<=>» como parámetros privados", `${E}[?25lx${E}[>4;2mx${E}[=1h`, "xx"],
    ["CSI con intermedios", `a${E}[2 qb`, "ab"],
    ["CSI de 8 bits (\\x9b)", "a\u009b31mb\u009b?25lc", "abc"],
    ["OSC terminado en BEL", `a${E}]0;titulo\u0007b`, "ab"],
    ["OSC terminado en ESC \\", `a${E}]8;;http://x${E}\\enlace${E}]8;;${E}\\`, "aenlace"],
    ["OSC de 8 bits terminado en ST", "a\u009d0;titulo\u009cb", "ab"],
    ["DCS", `a${E}Pq#0;2;0;0;0${E}\\b`, "ab"],
    ["DCS, SOS, PM y APC de 8 bits", "a\u0090x\u009cb\u0098y\u009cc\u009ez\u009cd\u009fw\u009ce", "abcde"],
    ["SOS, PM y APC de 7 bits", `a${E}Xx${E}\\b${E}^y${E}\\c${E}_z${E}\\d`, "abcd"],
    ["2 bytes: ESC 7 y ESC 8", `a${E}7b${E}8c`, "abc"],
    ["3 bytes: ESC ( B", `a${E}(Bb${E})0c`, "abc"],
    ["OSC sin terminar se lleva hasta el final", `ok${E}]0;sin fin`, "ok"],
  ])("%s", (_n, inp, out) => expect(stripAnsi(inp)).toBe(out));

  test("el texto sin ESC ni C1 no cambia (acentos, bidi y controles de texto incluidos)", () => {
    const s = "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.5 ms [x] ñ é ‮\t\n\r <b>";
    expect(stripAnsi(s)).toBe(s);
  });
});
