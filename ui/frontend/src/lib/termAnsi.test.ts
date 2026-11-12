import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { PALETTES } from "./termHighlight";
import { ansiHighlight, ansiPrompt, createLiveWriter } from "./termAnsi";

const p = PALETTES.find((x) => x.id === "classic")!;
const sgr = (c: string) => `\x1b[${c}m`; // el color va por índice: lo resuelve el tema de xterm
const RST = "\x1b[39m";
const plain = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

test("colorea por índice ANSI solo el primer plano de las palabras clave de líneas completas", () => {
  const out = ansiHighlight("Vlan10 is up, line protocol is up\r\n", p);
  expect(out).toContain(`${sgr("32")}up${RST}`);
  expect(out.endsWith("\r\n")).toBe(true);
  // sin fondo ni otros atributos: solo primer plano (3x/9x) y 39
  expect(out.match(/\x1b\[[0-9;]*m/g)!.every((s) => /^\x1b\[(3[0-7]|9[0-7])m$/.test(s) || s === RST)).toBe(true);
});

test("quitando los códigos queda exactamente el texto original", () => {
  const src = "GigabitEthernet1/0/24 is down\r\nIP 10.20.7.1 %SYS-3-ERROR: fail\r\nSW1#";
  const out = ansiHighlight(src, p);
  expect(out).not.toBe(src);
  expect(plain(out)).toBe(src);
});

test("la línea parcial del final no se toca", () => {
  const out = ansiHighlight("a is up\nSW1# show ip 10.1.1.1", p);
  expect(out.endsWith("\nSW1# show ip 10.1.1.1")).toBe(true);
});

test("una línea con ESC pasa intacta, aunque tenga palabras clave; las demás sí se colorean", () => {
  const out = ansiHighlight("\x1b[31mInterface is down\x1b[0m\r\nVlan1 is down\r\n", p);
  expect(out.startsWith("\x1b[31mInterface is down\x1b[0m\r\n")).toBe(true);
  expect(out).toContain(`${sgr("31")}down${RST}`);
});

const rgb = (hex: string) => `38;2;${parseInt(hex.slice(1, 3), 16)};${parseInt(hex.slice(3, 5), 16)};${parseInt(hex.slice(5, 7), 16)}`;

test("los roles con ranura ANSI se escriben por índice y el resto con el RGB de la paleta (uprompt, en la ranura blanca)", () => {
  const roles: [string, string][] = [
    ["x is down\n", "31"], ["x is up\n", "32"], ["10.20.7.1\n", "35"], ["GigabitEthernet1/0/1\n", "36"],
    ["router ospf 1\n", rgb(p.ospf)], ["bgp 65000\n", rgb(p.bgp)],
  ];
  for (const [line, code] of roles) expect(ansiHighlight(line, p), line).toContain(sgr(code));
  expect(ansiPrompt("SW1#", p)).toBe(`\x1b[1m${sgr("97")}SW1#${RST}\x1b[22m`);
  expect(ansiPrompt("SW1>", p)).toBe(`\x1b[1m${sgr("37")}SW1>${RST}\x1b[22m`); // el fg del tema: legible en claro y en oscuro
});

test("cambiar de paleta no cambia el texto de los roles por índice; no se usa la paleta extendida de xterm", () => {
  const light = PALETTES.find((x) => x.id === "light")!;
  const src = "x is up\n10.1.1.1 down\n";
  expect(ansiHighlight(src, light)).toBe(ansiHighlight(src, p));
  expect(ansiHighlight("router ospf 1\n", light)).toContain(sgr(rgb(light.ospf)));
  expect(ansiHighlight("router ospf 1\n bgp 1\n", p)).not.toMatch(/38;5;/);
});

// ---- Escritor en vivo ----
beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

const live = (on = true) => {
  const w = vi.fn();
  return { w, lw: createLiveWriter(w, () => (on ? p : null)) };
};

test("un chunk sin salto de línea se escribe al instante y sin cambios", () => {
  const { w, lw } = live();
  lw.push("s");
  expect(w).toHaveBeenCalledWith("s");
  lw.push("SW1#");
  expect(w).toHaveBeenLastCalledWith("SW1#");
});

test("con salto de línea escribe las líneas completas ya y retiene la parcial hasta 40 ms", () => {
  const { w, lw } = live();
  lw.push("Vlan1 is up\r\nSW1#");
  expect(w).toHaveBeenCalledTimes(1);
  expect(w.mock.calls[0][0]).toContain(sgr("32"));
  expect(plain(w.mock.calls[0][0])).toBe("Vlan1 is up\r\n");
  vi.advanceTimersByTime(39);
  expect(w).toHaveBeenCalledTimes(1);
  vi.advanceTimersByTime(1);
  expect(plain(w.mock.lastCall![0])).toBe("SW1#");
  expect(w.mock.lastCall![0]).toContain(`\x1b[1m${sgr("97")}SW1#`);
});

test("una línea partida entre chunks se resalta completa", () => {
  const { w, lw } = live();
  lw.push("ok\r\nGigabitEthernet1/0/1 is up, line prot");
  lw.push("ocol is down\r\nSW1#");
  const all = w.mock.calls.map((c) => c[0]).join("");
  expect(plain(all)).toBe("ok\r\nGigabitEthernet1/0/1 is up, line protocol is down\r\n");
  expect(all).toContain(`${sgr("31")}down${RST}`);
  vi.advanceTimersByTime(40);
  expect(plain(w.mock.lastCall![0])).toBe("SW1#");
  expect(w.mock.lastCall![0]).toContain(`\x1b[1m${sgr("97")}SW1#`);
});

test("sin resaltado todo pasa tal cual y al instante", () => {
  const { w, lw } = live(false);
  lw.push("Vlan1 is up\r\nSW1#");
  expect(w).toHaveBeenCalledWith("Vlan1 is up\r\nSW1#");
});

test("flush y dispose sueltan lo retenido sin perder texto", () => {
  const { w, lw } = live();
  lw.push("a\r\nresto");
  lw.flush();
  expect(w).toHaveBeenLastCalledWith("resto");
  lw.push("b\r\ncola");
  lw.dispose();
  vi.advanceTimersByTime(100);
  expect(w.mock.calls.map((c) => c[0]).join("")).toBe("a\r\nrestob\r\ncola");
});

// ---- Cisco: prompt, --More--, contadores ----
const SLOT = { bad: "31", ok: "32", warn: "33", kw: "34", addr: "35", iface: "36", dim: "90" } as const;
const col = (text: string, cat: keyof typeof SLOT) => `${sgr(SLOT[cat])}${text}${RST}`;

test("el prompt completo va en negrita y con el color del prompt, el eco que sigue no", () => {
  const out = ansiHighlight("SW1(config-if)#shutdown\r\n", p);
  expect(out).toContain(`\x1b[1m${sgr("97")}SW1(config-if)#${RST}\x1b[22m`);
  expect(out).toContain(col("shutdown", "warn"));
});

test("un prompt que espera tecleo (línea parcial) se pinta en negrita, y lo que se teclea después queda igual", () => {
  expect(ansiPrompt("SW1#", p)).toBe(`\x1b[1m${sgr("97")}SW1#${RST}\x1b[22m`);
  expect(ansiPrompt("SW1>", p)).toContain(sgr("37"));
  expect(ansiPrompt("show ip", p)).toBe("show ip");
  expect(ansiPrompt("\x1b[31mSW1#", p)).toBe("\x1b[31mSW1#");
  const w = vi.fn();
  const lw = createLiveWriter(w, () => p);
  lw.push("x\r\n"); lw.push("SW1#"); lw.push("sh"); // prompt en su chunk, eco aparte
  vi.advanceTimersByTime(40);
  expect(w.mock.calls.filter((c) => c[0] === "sh")).toHaveLength(1);
  expect(w.mock.calls.some((c) => c[0].includes(sgr("97")))).toBe(true);
});

test("--More-- se pinta como prompt aunque llegue solo y sin salto de línea", () => {
  const w = vi.fn();
  const lw = createLiveWriter(w, () => p);
  lw.push("Vlan1 is up\r\n --More-- ");
  vi.advanceTimersByTime(40);
  expect(w.mock.lastCall![0]).toContain(`\x1b[1m${sgr("97")} --More--`);
  expect(plain(w.mock.lastCall![0])).toBe(" --More-- ");
});

test("contadores de error: en cero atenuados, distintos de cero en el color de error", () => {
  const out = ansiHighlight("     5 input errors, 0 CRC, 0 frame\r\n", p);
  expect(out).toContain(col("5 input errors", "bad"));
  expect(out).toContain(col("0 CRC", "dim"));
  expect(out).toContain(col("0 frame", "dim"));
});

test("show run: palabras clave de configuración, no/shutdown y comentarios", () => {
  const cfg = "!\r\ninterface GigabitEthernet0/1\r\n description uplink\r\n switchport mode trunk\r\n no shutdown\r\n ip address 10.1.1.1 255.255.255.0\r\n no ip address\r\n";
  const out = ansiHighlight(cfg, p);
  for (const [w, c] of [["!", "dim"], ["interface", "kw"], ["GigabitEthernet0/1", "iface"], ["description", "kw"], ["switchport", "kw"], ["trunk", "kw"], ["ip address", "kw"], ["10.1.1.1", "addr"]] as const) expect(out, w).toContain(col(w, c));
  expect(out).toContain(col(" no shutdown", "ok"));
  expect(out).toContain(col(" no", "kw"));
  expect(plain(out)).toBe(cfg);
});

test("rendimiento: un show tech de 20 000 líneas se resalta en pocos segundos y sin perder texto", () => {
  vi.useRealTimers();
  const line = "GigabitEthernet1/0/24 is up, line protocol is up (connected) 10.20.7.1 aaaa.bbbb.cccc 5 input errors\r\n";
  const big = line.repeat(20_000);
  const t0 = performance.now();
  const out = ansiHighlight(big, p);
  const ms = performance.now() - t0;
  expect(ms).toBeLessThan(5000);
  expect(plain(out)).toBe(big);
});
