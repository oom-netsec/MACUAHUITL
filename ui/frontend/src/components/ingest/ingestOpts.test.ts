import { buildOpts, coreFieldError, emptyForm, mapStartError, previewName, rangeOf, validateOpts, type OptForm } from "./ingestOpts";

const form = (p: Partial<OptForm>): OptForm => ({ ...emptyForm, ...p });

test("buildOpts manda solo lo que la persona escribió; vacío son los defaults", () => {
  expect(buildOpts(emptyForm, true)).toEqual({});
  expect(buildOpts(form({ ratePerSource: "50", queueSize: " 8192 " }), false)).toEqual({ ratePerSource: 50, queueSize: 8192 });
});

test("buildOpts omite las opciones de archivo si no se guarda", () => {
  const f = form({ rotateMb: "10", rotateMinutes: "30", nameTemplate: "cap_{fecha}", maxFiles: "5", format: "jsonl", rateGlobal: "200" });
  expect(buildOpts(f, false)).toEqual({ rateGlobal: 200 });
  expect(buildOpts(f, true)).toEqual({ rateGlobal: 200, rotateMb: 10, rotateMinutes: 30, nameTemplate: "cap_{fecha}", maxFiles: 5, format: "jsonl" });
});

test("validateOpts acepta vacío y rechaza no enteros, cero y fuera de rango", () => {
  expect(validateOpts(emptyForm, true)).toEqual({});
  expect(validateOpts(form({ ratePerSource: "abc", rateGlobal: "1.5", queueSize: "10", burstGlobal: "0", maxFiles: "1001" }), true)).toEqual({
    ratePerSource: "int", rateGlobal: "int", queueSize: "range", burstGlobal: "range", maxFiles: "range",
  });
  expect(validateOpts(form({ ratePerSource: "10000", queueSize: "64" }), true)).toEqual({});
});

test("validateOpts ignora los campos de archivo cuando no se guarda", () => {
  expect(validateOpts(form({ rotateMb: "0", nameTemplate: "../x" }), false)).toEqual({});
  expect(validateOpts(form({ rotateMb: "2000", rotateMinutes: "10081" }), true)).toEqual({ rotateMb: "range", rotateMinutes: "range" });
});

test("validateOpts aplica la regla de la plantilla del núcleo", () => {
  const e = (nameTemplate: string) => validateOpts(form({ nameTemplate }), true).nameTemplate;
  expect(e("")).toBeUndefined();
  expect(e("syslog_{fecha}_{hora}")).toBeUndefined();
  expect(e("{origen}-{hora}.v1")).toBeUndefined();
  expect(e("solo_texto")).toBe("tplNeed");
  expect(e("a/{fecha}")).toBe("tplChars");
  expect(e("a b{fecha}")).toBe("tplChars");
  expect(e("{fecha}..x")).toBe("tplDots");
  expect(e("{fecha}{otro}")).toBe("tplTokens");
  expect(e("{fecha}{hora")).toBe("tplTokens");
  expect(e("x".repeat(65) + "{fecha}")).toBe("tplLen");
});

test("previewName arma el nombre con fecha, hora, origen y la extensión del formato", () => {
  const now = new Date(2026, 10, 7, 9, 5, 3);
  expect(previewName("", "texto", now)).toBe("syslog_20261107_090503.log");
  expect(previewName("cap_{origen}_{fecha}", "jsonl", now)).toBe("cap_10.0.0.9_20261107.jsonl");
  expect(previewName("{hora}", "crudo", now)).toBe("090503.log");
});

test("mapStartError reconoce el campo que nombra el núcleo", () => {
  const m = (s: string) => mapStartError(s);
  expect(m("syslogd: la tasa por origen debe estar entre 1 y 10000 (0 = default), no 20000")).toBe("ratePerSource");
  expect(m("syslogd: la ráfaga por origen debe estar entre 1 y 1000000 (0 = default), no 9999999")).toBe("burstPerSource");
  expect(m("syslogd: la tasa global debe estar entre 1 y 100000")).toBe("rateGlobal");
  expect(m("syslogd: la ráfaga global debe estar entre 1 y 1000000")).toBe("burstGlobal");
  expect(m("syslogd: la cola debe estar entre 64 y 65536")).toBe("queueSize");
  expect(m("syslogd: el tamaño de rotación debe estar entre 1 y 1024 MB")).toBe("rotateMb");
  expect(m("syslogd: la rotación por tiempo debe estar entre 1 minuto y 7 días")).toBe("rotateMinutes");
  expect(m("syslogd: el máximo de archivos debe estar entre 1 y 1000")).toBe("maxFiles");
  expect(m("syslogd: la plantilla debe llevar {fecha} o {hora}")).toBe("nameTemplate");
  expect(m("syslogd: formato \"x\" no soportado (texto, crudo o jsonl)")).toBe("format");
  expect(m("syslogd: puerto inválido \"x\"")).toBe("addr");
  expect(m("syslogd: el host debe ser una IP local, no \"8.8.8.8\"")).toBe("addr");
  expect(m("flows: dirección de escucha inválida \"x\": address x: missing port in address")).toBe("addr"); // texto real de internal/diag/listen
  expect(m("syslogd: archivo de salida: permiso denegado")).toBeNull();
});

test("coreFieldError mapea metadata.field de ingest.invalid al campo y arma el texto con i18n", () => {
  const t = (k: string, v?: Record<string, string | number>) => `${k}${v ? JSON.stringify(v) : ""}`;
  const inv = (metadata: Record<string, string>) => ({ code: "InvalidArgument", reason: "ingest.invalid", metadata });
  expect(coreFieldError(inv({ field: "rate_per_source", min: "1", max: "10000", value: "20000" }), t)).toEqual(["ratePerSource", 'syslog.err.range{"lo":"1","hi":"10000"}']);
  expect(coreFieldError(inv({ field: "queue_size", min: "64", max: "65536" }), t)?.[0]).toBe("queueSize");
  expect(coreFieldError(inv({ field: "name_template", template_problem: "chars", ch: "'/'" }), t)).toEqual(["nameTemplate", `syslog.err.tplCh{"ch":"'/'"}`]); // el núcleo cita el carácter (strconv.QuoteRune)
  expect(coreFieldError(inv({ field: "name_template", template_problem: "need" }), t)).toEqual(["nameTemplate", "syslog.err.tplNeed"]);
  expect(coreFieldError(inv({ field: "format", value: "x" }), t)).toEqual(["format", 'syslog.err.coreValue{"value":"x"}']);
  expect(coreFieldError(inv({ field: "addr" }), t)).toEqual(["addr", ""]); // se muestra el texto del núcleo
  expect(coreFieldError(inv({ field: "protocol", value: "x" }), t)).toBeNull(); // no es campo del formulario
  expect(coreFieldError({ code: "InvalidArgument", reason: "otro", metadata: { field: "addr" } }, t)).toBeNull();
});

test("flujos: defaults de tasa propios, plantilla propia y sin topes cuando no se guarda", () => {
  expect(rangeOf("flows", "ratePerSource").def).toBe("1000");
  expect(rangeOf("flows", "rateGlobal").def).toBe("5000");
  expect(rangeOf("traps", "rateGlobal").def).toBe("1000");
  const now = new Date(2026, 10, 7, 9, 5, 3);
  expect(previewName("", "texto", now, "flows")).toBe("flujos_20261107_090503.log");
  expect(previewName("", "jsonl", now, "traps")).toBe("traps_20261107_090503.jsonl");
  const f = form({ rateGlobal: "9000", queueSize: "128", rotateMb: "10" });
  expect(buildOpts(f, false, "flows")).toEqual({});
  expect(buildOpts(f, true, "flows")).toEqual({ rateGlobal: 9000, queueSize: 128, rotateMb: 10 });
  expect(buildOpts(f, false, "traps")).toEqual({ rateGlobal: 9000, queueSize: 128 });
  expect(validateOpts(form({ rateGlobal: "0" }), false, "flows")).toEqual({});
});
