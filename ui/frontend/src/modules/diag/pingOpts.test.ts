import { PING_FORM0, ipFamily, mtuEstimate, patchForm, pingOptions, type PingForm } from "./pingOpts";

const f = (o: Partial<PingForm>): PingForm => ({ ...PING_FORM0, ...o });
const run = (o: Partial<PingForm>, win = false) => pingOptions(f(o), win);

test("por omisión solo manda count y no hay opciones activas", () => {
  const r = run({});
  expect(r.options).toEqual({ count: "4" });
  expect(r.errors).toEqual({});
  expect(r.active).toBe(0);
});

test("continuo ignora count; nunca manda claves vacías", () => {
  const r = run({ continuous: true, ttl: " ", size: "" });
  expect(r.options).toEqual({ continuous: "true" });
  expect(r.active).toBe(1);
});

test("rangos de cada opción", () => {
  const bad: Partial<PingForm>[] = [{ interval: "0.1" }, { interval: "61" }, { size: "65501" }, { size: "-1" }, { ttl: "0" }, { ttl: "256" },
    { timeout: "0" }, { timeout: "61" }, { duration: "3601" }, { dscp: "64" }, { sourceIP: "no es ip" }, { count: "x", sweepStart: "0", sweepEnd: "10", sweepStep: "5" },
    { sourceIP: "999.1.1.1" }, { sourceIP: "1.2.3" }, { sourceIP: ":::::" }, { sourceIP: "10.0.0.1", family: "6" }, { sourceIP: "fe80::1", family: "4" }, { sourceSel: "10.0.0.1", family: "6" }];
  for (const b of bad) expect(Object.keys(run(b).errors).length, JSON.stringify(b)).toBeGreaterThan(0);
  const good = run({ interval: "0.2", size: "65500", ttl: "255", timeout: "60", duration: "3600", dscp: "63", sourceIP: "10.0.0.1", df: true, family: "4" });
  expect(good.errors).toEqual({});
  expect(good.options).toEqual({ count: "4", interval: "0.2", size: "65500", ttl: "255", timeout: "60", duration: "3600", source: "10.0.0.1", df: "true", family: "4", tos: "252" });
});

test("el origen escrito gana sobre el elegido", () => {
  expect(run({ sourceSel: "eth0" }).options.source).toBe("eth0");
  expect(run({ sourceSel: "eth0", sourceIP: "10.0.0.1" }).options.source).toBe("10.0.0.1");
});

test("barrido: los tres o ninguno, máximo 100 puntos, sin continuo ni size", () => {
  expect(run({ sweepStart: "0", sweepEnd: "1400", sweepStep: "100", count: "2" }).options).toEqual({ count: "2", sweep_start: "0", sweep_end: "1400", sweep_step: "100" });
  expect(run({ sweepStart: "0" }).errors.sweepEnd).toBeDefined();
  expect(run({ sweepStart: "0", sweepEnd: "99", sweepStep: "1" }).errors).toEqual({}); // 100 puntos
  expect(run({ sweepStart: "0", sweepEnd: "100", sweepStep: "1" }).errors.sweepStep).toBeDefined(); // 101
  expect(run({ sweepStart: "10", sweepEnd: "5", sweepStep: "1" }).errors.sweepEnd).toBeDefined();
  expect(run({ sweepStart: "0", sweepEnd: "10", sweepStep: "0" }).errors.sweepStep).toBeDefined();
  expect(run({ sweepStart: "0", sweepEnd: "10", sweepStep: "5", continuous: true }).errors.sweepStart).toBeDefined();
  expect(run({ sweepStart: "0", sweepEnd: "10", sweepStep: "5", size: "64" }).errors.size).toBeDefined();
  expect(run({ sweepStart: "0", sweepEnd: "10", sweepStep: "5", count: "6" }).errors.count).toBeDefined();
});

test("Windows: sin interval, tos ni interfaz; df solo con IPv4", () => {
  const w = run({ interval: "1", dscp: "10", sourceSel: "eth0", df: true, family: "6" }, true);
  expect(w.options).toEqual({ count: "4", family: "6" });
  expect(run({ df: true, family: "4" }, true).options.df).toBe("true");
  expect(run({ df: true }, true).options.df).toBe("true"); // Auto: el núcleo rechaza si resuelve a v6
  expect(run({ df: true, family: "6" }, false).options.df).toBe("true"); // en Linux DF con v6 es válido
  expect(run({ df: true, family: "6" }, true).options.df).toBeUndefined();
  expect(run({ sourceIP: "10.0.0.1" }, true).options.source).toBe("10.0.0.1");
});

test("MTU estimada: mayor ok antes del primer frag, +28 en IPv4 y +48 en IPv6", () => {
  const p = (size: number, result: "ok" | "loss" | "frag") => ({ size, sent: 1, received: result === "ok" ? 1 : 0, result });
  const pts = [p(1472, "frag"), p(1400, "ok"), p(1450, "ok"), p(1500, "frag")];
  expect(mtuEstimate(pts, false)).toEqual({ size: 1450, mtu: 1478 });
  expect(mtuEstimate(pts, true)).toEqual({ size: 1450, mtu: 1498 });
  expect(mtuEstimate([p(1400, "ok"), p(1450, "ok")], false)).toBeNull(); // sin frag no hay estimación
  expect(mtuEstimate([p(0, "frag")], false)).toBeNull();
  expect(mtuEstimate([p(1400, "ok"), p(1450, "frag"), p(1500, "ok")], false)).toEqual({ size: 1400, mtu: 1428 });
});

test("cuenta las opciones activas: el barrido es una sola, count no cuenta", () => {
  expect(run({ count: "9", ttl: "5", sweepStart: "0", sweepEnd: "10", sweepStep: "5", sourceIP: "10.0.0.1" }).active).toBe(3);
  expect(run({ interval: "1", dscp: "4" }, true).active).toBe(0);
});

test("count se valida siempre: entero 1-100 (1-5 con barrido), nunca vacío ni raro", () => {
  for (const c of ["", " ", "0", "-5", "1000", "101", "1e3", "2.5", "x"]) {
    const r = run({ count: c });
    expect(r.errors.count, c).toBe("diag.ping.err.count");
    expect(r.options.count).toBeUndefined();
  }
  expect(run({ count: "100" }).options.count).toBe("100");
  expect(run({ count: "", continuous: true }).errors).toEqual({}); // continuo ignora count
});

test("los errores del barrido caen en el campo que falla", () => {
  expect(run({ sweepStart: "x", sweepEnd: "10", sweepStep: "5", count: "1" }).errors).toEqual({ sweepStart: "diag.ping.err.sweepRange" });
  expect(run({ sweepStart: "0", sweepEnd: "70000", sweepStep: "5", count: "1" }).errors).toEqual({ sweepEnd: "diag.ping.err.sweepRange" });
  expect(run({ sweepStart: "0", sweepEnd: "10", sweepStep: "x", count: "1" }).errors).toEqual({ sweepStep: "diag.ping.err.sweepRange" });
  expect(run({ sweepStart: "0", sweepEnd: "10" }).errors).toEqual({ sweepStep: "diag.ping.err.sweepAll" });
  expect(run({ sweepEnd: "10" }).errors).toEqual({ sweepStart: "diag.ping.err.sweepAll" });
});

test("el origen valida octetos y familia", () => {
  expect(ipFamily("10.0.0.1")).toBe(4);
  expect(ipFamily("256.0.0.1")).toBe(0);
  expect(ipFamily("fe80::1")).toBe(6);
  expect(ipFamily("2001:db8::1")).toBe(6);
  expect(ipFamily("::")).toBe(6);
  expect(ipFamily("host.example")).toBe(0);
  expect(run({ sourceIP: "10.0.0.1", family: "4" }).options.source).toBe("10.0.0.1");
});

test("con barrido count arranca en 1 si el usuario no lo tocó, y vuelve a 4 al vaciarlo", () => {
  let x = patchForm(PING_FORM0, { sweepStart: "0" });
  expect(x.count).toBe("1");
  x = patchForm(x, { sweepStart: "" });
  expect(x.count).toBe("4");
  x = patchForm(patchForm(x, { count: "3" }), { sweepStart: "0" });
  expect(x.count).toBe("3");
});

test("activas cuenta lo que se manda: df bloqueado en Windows con v6 no cuenta", () => {
  expect(run({ df: true, family: "6" }, true).active).toBe(1); // solo family
  expect(run({ df: true }).active).toBe(1);
});
