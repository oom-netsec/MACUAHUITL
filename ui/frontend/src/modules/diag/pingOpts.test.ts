import { PING_FORM0, mtuEstimate, pingOptions, type PingForm } from "./pingOpts";

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
    { timeout: "0" }, { timeout: "61" }, { duration: "3601" }, { dscp: "64" }, { sourceIP: "no es ip" }, { count: "x", sweepStart: "0", sweepEnd: "10", sweepStep: "5" }];
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
  expect(run({ sweepStart: "0" }).errors.sweepStart).toBeDefined();
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
  expect(run({ df: true }, true).options.df).toBeUndefined(); // en Windows solo con family=4
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
