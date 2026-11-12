import { certTone, parseTls } from "./tlsChain";
import { tlsSample } from "./samples";

test("ordena la cadena del servidor a la raíz con su rol y los días restantes", () => {
  const r = parseTls(tlsSample)!;
  expect(r.target).toBe("ise.lab:443");
  expect(r.chain.map((c) => c.role)).toEqual(["leaf", "intermediate", "root"]);
  expect(r.chain[0]).toMatchObject({ subject: "CN=ise.lab", issuer: "CN=Lab Issuing CA", daysLeft: 19, isCA: false });
  expect(r.chain[0].sha256).toMatch(/^9f:86/);
  expect(r.findings[0].code).toBe("vence-pronto");
});

test("sin raíz en la cadena el último queda como intermedio; un solo certificado es el del servidor", () => {
  const c = (s: string, i: string) => ({ Subject: s, Issuer: i, NotAfter: new Date(Date.now() + 90 * 864e5).toISOString() });
  expect(parseTls(JSON.stringify({ Chain: [c("a", "b"), c("b", "c")] }))!.chain.map((x) => x.role)).toEqual(["leaf", "intermediate"]);
  expect(parseTls(JSON.stringify({ Chain: [c("a", "a")] }))!.chain.map((x) => x.role)).toEqual(["leaf"]);
});

test("días vencidos salen negativos", () => {
  const r = parseTls(JSON.stringify({ Chain: [{ Subject: "a", Issuer: "b", NotAfter: new Date(Date.now() - 3 * 864e5 - 1000).toISOString() }] }))!;
  expect(r.chain[0].daysLeft).toBe(-4);
});

test("umbrales: aviso por debajo de 30 días, malo por debajo de 7 o vencido", () => {
  expect(certTone(90)).toBe("ok");
  expect(certTone(30)).toBe("ok");
  expect(certTone(29)).toBe("warn");
  expect(certTone(7)).toBe("warn");
  expect(certTone(6)).toBe("bad");
  expect(certTone(-1)).toBe("bad");
});

test("lo que no es un informe TLS devuelve null", () => {
  expect(parseTls("TLS 1.3")).toBeNull();
  expect(parseTls("{}")).toBeNull();
  expect(parseTls(JSON.stringify({ Chain: [] }))).toBeNull();
});

test("una fecha de vencimiento ilegible no se pinta como vigente", () => {
  expect(certTone(Number.NaN)).toBe("");
});
