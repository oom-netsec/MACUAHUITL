import { parseTrace } from "./dnsTrace";
import { dnsTraceSample } from "./samples";

test("convierte la traza en niveles raíz, TLD y autoritativo con RTT en ms", () => {
  const t = parseTrace(dnsTraceSample)!;
  expect(t.name).toBe("www.example.com.");
  expect(t.rcode).toBe("NOERROR");
  expect(t.steps.map((s) => s.depth)).toEqual([0, 1, 2]);
  expect(t.steps[0]).toMatchObject({ zone: ".", server: "a.root-servers.net.", ip: "198.41.0.4", rttMs: 18, referral: "com.", answers: [] });
  expect(t.steps[2]).toMatchObject({ aa: true, answers: ["www.example.com.\t300\tIN\tA\t93.184.216.34"] });
  expect(t.final).toHaveLength(1);
});

test("un CNAME reinicia la zona en la raíz y la sangría vuelve a 0", () => {
  const j = JSON.stringify({ Name: "a.", Type: "A", CNAMEs: ["a. → b."], Steps: [{ Zone: "." }, { Zone: "com." }, { Zone: "." }] });
  expect(parseTrace(j)!.steps.map((s) => s.depth)).toEqual([0, 1, 0]);
  expect(parseTrace(j)!.cnames).toEqual(["a. → b."]);
});

test("un paso con error conserva el mensaje", () => {
  const t = parseTrace(JSON.stringify({ Steps: [{ Zone: "com.", Server: "x.", Error: "tiempo agotado" }] }))!;
  expect(t.steps[0].error).toBe("tiempo agotado");
});

test("lo que no es una traza devuelve null", () => {
  expect(parseTrace("{}")).toBeNull();
  expect(parseTrace("no es json")).toBeNull();
  expect(parseTrace(JSON.stringify({ Steps: "x" }))).toBeNull();
  expect(parseTrace("[]")).toBeNull();
});
