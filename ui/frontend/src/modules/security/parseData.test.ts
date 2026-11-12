import { expect, it } from "vitest";
import type { Certificate, PkiReportData, RadiusReportData, TacacsReportData } from "./api";
import { parsePki, parseRadius, parseTacacs, pkiFromData, radiusFromData, tacacsFromData } from "./parse";

// Fase 30b: el informe estructurado produce la misma forma que el parseo del texto, con los códigos cerrados en inglés.
it("radius: del informe estructurado a las tarjetas", () => {
  const d: RadiusReportData = {
    text: "", server: "10.0.0.20:1812", method: "PAP",
    exchanges: [
      { kind: "access-request", code: "Access-Reject", rttMs: 3.1, attempts: 2, messageAuthenticator: "valid", attrs: [{ name: "Reply-Message", value: "x" }] },
      { kind: "status-server", rttMs: 0, attempts: 0, error: { key: "security.radius.err.no_response", text: "no response after 3 attempts" }, attrs: [] },
    ],
    findings: [{ code: "ma-invalido", severity: "warning", message: "msg" }],
  };
  const r = radiusFromData(d);
  expect(r.method).toBe("PAP");
  expect(r.exchanges[0]).toMatchObject({ code: "Access-Reject", messageAuthenticator: "valid", error: "", attrs: [{ name: "Reply-Message", value: "x" }] });
  expect(r.exchanges[1]).toMatchObject({ code: "", error: "no response after 3 attempts" });
  expect(r.findings).toEqual([{ severity: "warning", detail: "msg" }]);
});

it("el parseo del texto usa los mismos códigos que el estructurado", () => {
  const r = parseRadius("Servidor RADIUS h:1812\n\naccess-request: Access-Accept en 1.0 ms (intento 1, Message-Authenticator ausente)\n\nHallazgos:\n  [aviso] algo\n")!;
  expect(r.exchanges[0].messageAuthenticator).toBe("absent");
  expect(r.findings[0].severity).toBe("warning");
  expect(parseRadius("Servidor RADIUS h\n\nx: Access-Accept en 1.0 ms (intento 1, Message-Authenticator inválido)\n")!.exchanges[0].messageAuthenticator).toBe("invalid");
  expect(parseRadius("Servidor RADIUS h\n\nx: Access-Accept en 1.0 ms (intento 1, Message-Authenticator válido)\n")!.exchanges[0].messageAuthenticator).toBe("valid");
});

it("tacacs: pares enviados y recibidos en orden", () => {
  const d: TacacsReportData = {
    text: "", server: "h:49",
    steps: [{ kind: "authorization", status: "PASS_ADD", rttMs: 8, prompts: ["Password: "], message: "ok", data: "d", avPairs: [{ direction: "sent", value: "service=shell" }, { direction: "received", value: "priv-lvl=15" }] }],
    findings: [{ code: "estado", severity: "info", message: "m" }],
  };
  expect(tacacsFromData(d).steps[0]).toMatchObject({ status: "PASS_ADD", error: "", prompts: ["Password: "], message: "ok", data: "d", sent: ["service=shell"], received: ["priv-lvl=15"] });
  expect(parseTacacs("Servidor TACACS+ h:49\n\nx: PASS en 1.0 ms\n")!.steps[0].status).toBe("PASS");
});

const cert = (o: Partial<Certificate>): Certificate => ({ kind: "certificate", subject: "CN=a", key: { algorithm: "RSA", bits: 2048, description: "RSA 2048" }, signature: { algorithm: "SHA256-RSA" },
  san: [], keyUsage: [], extKeyUsage: [], isCa: false, selfSigned: false, warnings: [], ...o });

it("pki: certificado y CSR del informe estructurado", () => {
  const d: PkiReportData = { text: "", certificates: [
    cert({ issuer: "CN=ca", serial: "01", notBefore: "2026-01-01T00:00:00Z", notAfter: "2027-01-01T00:00:00Z", daysLeft: 50, san: ["a.lab", "b.lab"], keyUsage: ["digitalSignature"], extKeyUsage: ["serverAuth"],
      isCa: true, selfSigned: true, sha256: "AB", warnings: [{ code: "no_san", message: "sin SAN" }] }),
    cert({ kind: "csr", signature: { algorithm: "ECDSA", valid: false } }),
  ] };
  const [c, csr] = pkiFromData(d);
  expect(c).toMatchObject({ kind: "certificate", issuer: "CN=ca", notBefore: "2026-01-01", notAfter: "2027-01-01", daysLeft: 50, keyType: "RSA 2048", sigAlg: "SHA256-RSA", san: "a.lab, b.lab",
    usage: "digitalSignature, serverAuth", isCA: true, selfSigned: true, sha256: "AB", warnings: ["sin SAN"] });
  expect(csr).toMatchObject({ kind: "csr", daysLeft: null, sigValid: false });
  expect(parsePki("CSR: CN=x\n")![0].kind).toBe("csr");
  expect(parsePki("certificado: CN=x\n")![0].kind).toBe("certificate");
});
