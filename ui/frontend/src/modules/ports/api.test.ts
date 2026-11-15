import { parsePendingRollbacks } from "./api";

test("reversas pendientes: listas ausentes son [] y ageSeconds/endedUnix pasan de cadena a número", () => {
  const r = parsePendingRollbacks(JSON.stringify({ rollbacks: [
    { runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["no shutdown"] }], endedUnix: "1700000000", ageSeconds: "90000", writeMemory: true },
    { runId: "b", unreadable: true },
  ] }));
  expect(r[0]).toEqual({ runId: "a", kind: "ports", devices: [{ device: "SW1", rollbackLines: ["no shutdown"], provisional: false }], endedUnix: 1700000000, ageSeconds: 90000, writeMemory: true, unreadable: false, generatedSecret: false, rotatedUser: "", updateCredentialId: "" });
  expect(r[1]).toEqual({ runId: "b", kind: "", devices: [], endedUnix: 0, ageSeconds: 0, writeMemory: false, unreadable: true, generatedSecret: false, rotatedUser: "", updateCredentialId: "" });
  expect(parsePendingRollbacks("{}")).toEqual([]);
  expect(parsePendingRollbacks(JSON.stringify({ rollbacks: [{ runId: "c", devices: [{ device: "X" }] }] }))[0].devices).toEqual([{ device: "X", rollbackLines: [], provisional: false }]);
});

test("reversas pendientes: usuario rotado, credencial asociada y equipo provisional (campos 9, 10 y provisional)", () => {
  const [r] = parsePendingRollbacks(JSON.stringify({ rollbacks: [{ runId: "a", kind: "credrotate", rotatedUser: "netops", updateCredentialId: "c1", devices: [{ device: "SW1", provisional: true }] }] }));
  expect([r.rotatedUser, r.updateCredentialId, r.devices[0].provisional]).toEqual(["netops", "c1", true]);
});
