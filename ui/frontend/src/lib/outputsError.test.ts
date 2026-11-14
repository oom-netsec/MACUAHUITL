import { expect, test } from "vitest";
import { chmodCommand, outputsErrorText, parseOutputsError } from "./outputsError";

const t = (k: string) => `[${k}]`;
const text = (p: string) => `prefs.outputs.permisos: la carpeta ${p} tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 ${p}`;
// Error del puente con cause: el texto puede venir en cualquier idioma, lo que manda es reason y metadata.
const msg = (p: string) => Object.assign(new Error("fix it with something else"), { cause: { code: "FailedPrecondition", reason: "prefs.outputs.permisos", metadata: { code: "permisos", path: p } } });

test("la orden chmod cita lo raro y no se genera con \\, ' o control", () => {
  expect(chmodCommand("/home/u/salidas")).toBe("chmod 700 /home/u/salidas");
  expect(chmodCommand("/home/u/$(id)")).toBe("chmod 700 '/home/u/$(id)'");
  expect(chmodCommand("/x\\';echo pwned;#")).toBe("");
  expect(chmodCommand("/x'y")).toBe("");
  expect(chmodCommand("/x\ny")).toBe("");
  expect(chmodCommand("")).toBe("");
  // Un C1 o un bidi no se ejecuta entre comillas, pero puede hacer que la orden se vea distinta de lo que se pega.
  expect(chmodCommand("/x\u0085y")).toBe("");
  expect(chmodCommand("/x\u202ey")).toBe("");
  for (const inv of ["\u200b", "\u200e", "\u200f", "\u2028", "\u2060", "\ufeff"]) expect(chmodCommand(`/x${inv}y`)).toBe("");
  expect(chmodCommand("/home/u/Música/salidas")).toBe("chmod 700 '/home/u/Música/salidas'");
});

test("el texto de un rechazo de permisos lleva la orden solo si es segura", () => {
  expect(outputsErrorText(msg("/home/u/salidas"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 /home/u/salidas");
  expect(outputsErrorText(msg("/home/u/$(id)"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 '/home/u/$(id)'");
  expect(outputsErrorText(msg("/x\\';echo pwned;#"), t as never)).toBe("[settings.storage.err.permisos]");
  expect(outputsErrorText(new Error("otra cosa"), t as never)).toBe("otra cosa");
});

test("la ruta es lo que sigue al sufijo «corrígelo con: chmod 700 », no una mención anterior", () => {
  const m = "prefs.outputs.permisos: la carpeta /a/chmod 700 /b tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 /a/chmod 700 /b";
  expect(parseOutputsError(new Error(m))).toEqual({ code: "permisos", path: "/a/chmod 700 /b" });
});

test("con reason, el código y la ruta salen de cause y no del texto", () => {
  expect(parseOutputsError(msg("/a b"))).toEqual({ code: "permisos", path: "/a b" });
  const noExiste = Object.assign(new Error("folder missing"), { cause: { code: "NotFound", reason: "prefs.outputs.no_existe", metadata: { code: "no_existe", path: "/x" } } });
  expect(parseOutputsError(noExiste)).toEqual({ code: "no_existe", path: "/x" });
  expect(outputsErrorText(noExiste, t as never)).toBe("[settings.storage.err.no_existe]");
  // Un reason ajeno no es un rechazo de carpeta, aunque el texto lo parezca.
  const otro = Object.assign(new Error(text("/x")), { cause: { code: "Internal", reason: "otra.cosa", metadata: {} } });
  expect(parseOutputsError(otro)).toBeNull();
  expect(outputsErrorText(otro, t as never)).toBe(text("/x"));
  // El respaldo por texto sigue sirviendo sin reason.
  expect(parseOutputsError(new Error(text("/x")))).toEqual({ code: "permisos", path: "/x" });
});

test("los textos sirven en Ajustes, Job, Cambio y Diagnóstico", async () => {
  const { es } = await import("./i18n/es");
  const { en } = await import("./i18n/en");
  expect(es["settings.storage.err.permisos"]).not.toMatch(/guardar/);
  expect(en["settings.storage.err.permisos"]).not.toMatch(/save/i);
  // Sin orden (ruta que no se puede citar segura), el texto no debe pedir "esta orden".
  expect(es["settings.storage.err.permisos"]).not.toMatch(/esta orden/);
  expect(en["settings.storage.err.permisos"]).not.toMatch(/this command/);
  expect(es["change.outDir"]).toMatch(/subcarpeta/);
  expect(en["change.outDir"]).toMatch(/subfolder/);
});
