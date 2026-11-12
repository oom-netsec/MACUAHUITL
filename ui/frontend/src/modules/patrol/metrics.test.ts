import { sampleMetrics } from "./fake";
import { cpuPeak, fromJob, growing, ifaceNames, perRound, roundTimes, topInterfaces } from "./metrics";
import { sampleDevice } from "../metrics/fake";

const m = fromJob(sampleMetrics(Date.UTC(2026, 10, 6, 18, 0)));
const sw1 = m.devices[0];

test("roundTimes da segundos Unix, uno por ronda", () => {
  expect(roundTimes(m)).toHaveLength(6);
  expect(roundTimes(m)[1] - roundTimes(m)[0]).toBe(900);
});

test("perRound alinea con las rondas y deja null lo que falta", () => {
  expect(perRound(sw1, m, (s) => s.cpu?.fiveSec)[3]).toBe(97);
  const sparse = { ...sw1, samples: sw1.samples.filter((s) => s.round !== 2) };
  expect(perRound(sparse, m, (s) => s.cpu?.oneMin)[1]).toBeNull();
  expect(perRound({ ...sw1, samples: sw1.samples.map((s) => ({ ...s, cpu: undefined })) }, m, (s) => s.cpu?.oneMin)).toEqual(Array(6).fill(null));
});

test("fromJob: una muestra por ronda, hora de la ronda, diferencias solo si valen y reinicios", () => {
  const f = fromJob({ devices: [sampleDevice], warnings: ["aviso"] });
  expect(f.rounds.map((r) => r.round)).toEqual([1, 2, 3]);
  expect(f.rounds[0].at).toBe(new Date(sampleDevice.cpu[0].atMs).toISOString());
  const d = f.devices[0];
  expect([d.deviceId, d.name]).toEqual(["10.0.0.1", "SW1"]);
  expect(d.reboots).toEqual([3]);
  const gi = (r: number) => d.samples.find((s) => s.round === r)!.interfaces!.find((i) => i.name === "Gi1/0/1")!;
  expect(gi(1)).toMatchObject({ avg5min: true, bandwidthBps: 1e9 });
  expect(gi(1).crc).toBeUndefined(); // deltaOk false: no es un cero
  expect(gi(2).crc).toBe(4);
  expect(d.samples[0].interfaces?.some((i) => i.name === "Gi1/0/2")).toBe(false); // sin puntos: no aparece
  expect(d.samples[1].memory?.map((x) => x.pool)).toEqual(["Processor", "I/O"]);
  expect(f.warnings).toEqual(["aviso"]);
});

test("topInterfaces ordena por pico de tráfico y limita a n", () => {
  expect(topInterfaces(sw1, 2)).toEqual(["Te1/1/1", "Gi1/0/2"]);
  expect(topInterfaces(sw1)).toHaveLength(4);
  expect(ifaceNames(sw1)).toEqual(["Te1/1/1", "Gi1/0/2", "Gi1/0/14", "Gi1/0/24"]);
});

test("growing lista las interfaces cuyo contador creció, de más a menos", () => {
  expect(growing(sw1, m, (i) => i.crc)).toEqual(["Gi1/0/2"]);
  expect(growing(sw1, m, (i) => i.outDrops)).toEqual(["Te1/1/1"]);
  expect(growing(sw1, m, (i) => i.resets)).toEqual([]); // constante: sin crecimiento
  expect(growing(m.devices[1], m, (i) => i.crc)).toEqual([]);
});

test("cpuPeak devuelve el pico y la ronda donde ocurrió", () => {
  expect(cpuPeak(sw1)).toEqual({ value: 97, round: 4 });
  expect(cpuPeak({ ...sw1, samples: [] })).toBeNull();
});

test("fromJob: dos equipos con el mismo nombre no se pisan, el tope de interfaces se informa y sin tasa se conservan las diferencias", () => {
  const twin = { ...sampleDevice, address: "10.0.0.2" };
  const noRate = { ...sampleDevice, interfaceTotal: 48, interfaces: [{ ...sampleDevice.interfaces[0], points: [{ ...sampleDevice.interfaces[0].points[1], source: "" as const }] }] };
  const f = fromJob({ devices: [sampleDevice, twin, { ...noRate, address: "10.0.0.3" }], warnings: [] });
  expect(f.devices.map((d) => [d.deviceId, d.name])).toEqual([["10.0.0.1", "SW1"], ["10.0.0.2", "SW1"], ["10.0.0.3", "SW1"]]);
  const d3 = f.devices[2];
  expect([d3.ifaceShown, d3.ifaceTotal]).toEqual([1, 48]);
  const gi = d3.samples.find((s) => s.round === 2)!.interfaces![0];
  expect(gi.crc).toBe(4);
  expect(gi.inBps).toBeUndefined(); // sin tasa no se inventa un cero
});
