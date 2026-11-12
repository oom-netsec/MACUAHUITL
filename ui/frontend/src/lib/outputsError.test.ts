import { expect, test } from "vitest";
import { chmodCommand, outputsErrorText, parseOutputsError } from "./outputsError";

const t = (k: string) => `[${k}]`;
const msg = (p: string) => `prefs.outputs.permisos: la carpeta ${p} tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 ${p}`;

test("la orden chmod cita lo raro y no se genera con \\, ' o control", () => {
  expect(chmodCommand("/home/u/salidas")).toBe("chmod 700 /home/u/salidas");
  expect(chmodCommand("/home/u/$(id)")).toBe("chmod 700 '/home/u/$(id)'");
  expect(chmodCommand("/x\\';echo pwned;#")).toBe("");
  expect(chmodCommand("/x'y")).toBe("");
  expect(chmodCommand("/x\ny")).toBe("");
  expect(chmodCommand("")).toBe("");
});

test("el texto de un rechazo de permisos lleva la orden solo si es segura", () => {
  expect(outputsErrorText(msg("/home/u/salidas"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 /home/u/salidas");
  expect(outputsErrorText(msg("/home/u/$(id)"), t as never)).toBe("[settings.storage.err.permisos] chmod 700 '/home/u/$(id)'");
  expect(outputsErrorText(msg("/x\\';echo pwned;#"), t as never)).toBe("[settings.storage.err.permisos]");
  expect(outputsErrorText("otra cosa", t as never)).toBe("otra cosa");
});

test("la ruta es lo que sigue al sufijo «corrígelo con: chmod 700 », no una mención anterior", () => {
  const m = "prefs.outputs.permisos: la carpeta /a/chmod 700 /b tiene modo 0755 y debe ser 0700; corrígelo con: chmod 700 /a/chmod 700 /b";
  expect(parseOutputsError(m)).toEqual({ code: "permisos", path: "/a/chmod 700 /b" });
});

test("los textos sirven en Ajustes, Job, Cambio y Diagnóstico", async () => {
  const { es } = await import("./i18n/es");
  const { en } = await import("./i18n/en");
  expect(es["settings.storage.err.permisos"]).not.toMatch(/guardar/);
  expect(en["settings.storage.err.permisos"]).not.toMatch(/save/i);
  expect(es["change.outDir"]).toMatch(/subcarpeta/);
  expect(en["change.outDir"]).toMatch(/subfolder/);
});
