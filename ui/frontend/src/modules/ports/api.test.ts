import { parsePendingRollbacks } from "./api";

test("reversas pendientes: listas ausentes son [] y ageSeconds/endedUnix pasan de cadena a número", () => {
  const r = parsePendingRollbacks(JSON.stringify({ rollbacks: [
    { runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["no shutdown"] }], endedUnix: "1700000000", ageSeconds: "90000", writeMemory: true },
    { runId: "b", unreadable: true },
  ] }));
  expect(r[0]).toEqual({ runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["no shutdown"] }], endedUnix: 1700000000, ageSeconds: 90000, writeMemory: true, unreadable: false });
  expect(r[1]).toEqual({ runId: "b", kind: "", devices: [], endedUnix: 0, ageSeconds: 0, writeMemory: false, unreadable: true });
  expect(parsePendingRollbacks("{}")).toEqual([]);
  expect(parsePendingRollbacks(JSON.stringify({ rollbacks: [{ runId: "c", devices: [{ device: "X" }] }] }))[0].devices).toEqual([{ device: "X", rollbackLines: [] }]);
});
