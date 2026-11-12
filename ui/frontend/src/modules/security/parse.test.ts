import { daysState, parsePki, parseRadius, parseTacacs } from "./parse";

const radius = `Servidor RADIUS 10.0.0.20:1812 (método PAP)

access-request: Access-Reject en 3.1 ms (intento 2, Message-Authenticator válido)
  Reply-Message              Usuario desconocido
  Tunnel-Private-Group-ID    10

status-server: sin respuesta
  ! sin respuesta tras 3 intentos de 5s

Hallazgos:
  [aviso] access-request: la respuesta no trae Message-Authenticator
  [error] status-server: el servidor no respondió
`;

test("radius: separa servidor, intercambios, atributos y hallazgos", () => {
  const r = parseRadius(radius)!;
  expect(r.server).toBe("10.0.0.20:1812");
  expect(r.method).toBe("PAP");
  expect(r.exchanges).toHaveLength(2);
  expect(r.exchanges[0]).toMatchObject({ kind: "access-request", code: "Access-Reject", rttMs: 3.1, attempts: 2, messageAuthenticator: "valid", error: "" });
  expect(r.exchanges[0].attrs).toEqual([{ name: "Reply-Message", value: "Usuario desconocido" }, { name: "Tunnel-Private-Group-ID", value: "10" }]);
  expect(r.exchanges[1]).toMatchObject({ kind: "status-server", code: "", error: "sin respuesta tras 3 intentos de 5s" });
  expect(r.findings).toEqual([{ severity: "warning", detail: "access-request: la respuesta no trae Message-Authenticator" }, { severity: "error", detail: "status-server: el servidor no respondió" }]);
});

test("radius: un texto que no es el informe del núcleo no se interpreta", () => {
  expect(parseRadius("Access-Accept en 3.1 ms")).toBeNull();
  expect(parseRadius("")).toBeNull();
});

const tacacs = `Servidor TACACS+ 10.0.0.21:49

authentication: PASS en 12.4 ms

authorization: PASS_ADD en 8.0 ms
  mensaje: ok
  enviado  service=shell
  enviado  cmd=show running-config
  recibido priv-lvl=15

accounting-start: sin respuesta
  ! tiempo agotado

Hallazgos:
  [aviso] authorization: el servidor devolvió PASS_ADD
`;

test("tacacs: pasos con estado, pares enviados y recibidos", () => {
  const r = parseTacacs(tacacs)!;
  expect(r.server).toBe("10.0.0.21:49");
  expect(r.steps.map((s) => [s.kind, s.status])).toEqual([["authentication", "PASS"], ["authorization", "PASS_ADD"], ["accounting-start", ""]]);
  expect(r.steps[1]).toMatchObject({ rttMs: 8, message: "ok", sent: ["service=shell", "cmd=show running-config"], received: ["priv-lvl=15"] });
  expect(r.steps[2].error).toBe("tiempo agotado");
  expect(r.findings).toHaveLength(1);
  expect(parseTacacs("PASS_ADD")).toBeNull();
});

const pki = `certificado: CN=ise01.lab,O=Lab
  Emisor           CN=Lab CA
  Serie            0A1B
  Validez          2026-01-01T00:00:00Z → 2027-01-01T00:00:00Z (55 días)
  Llave            ECDSA P-256
  SAN              ise01.lab, 10.0.0.10
  SHA-1            AA:BB
  SHA-256          CC:DD
  ! vence en 55 días

certificado: CN=Lab CA
  Emisor           CN=Lab CA
  Validez          2020-01-01T00:00:00Z → 2026-10-01T00:00:00Z (-36 días)
  CA               sí
  SHA-256          EE:FF
`;

test("pki: cadena de certificados con vigencia, huellas y avisos", () => {
  const c = parsePki(pki)!;
  expect(c).toHaveLength(2);
  expect(c[0]).toMatchObject({ kind: "certificate", subject: "CN=ise01.lab,O=Lab", issuer: "CN=Lab CA", daysLeft: 55, sha256: "CC:DD", sha1: "AA:BB", san: "ise01.lab, 10.0.0.10", warnings: ["vence en 55 días"] });
  expect(c[0].notBefore).toBe("2026-01-01T00:00:00Z");
  expect(c[1]).toMatchObject({ daysLeft: -36, isCA: true });
  expect(parsePki("SHA-256 ABC")).toBeNull();
});

test("vigencia: aviso a menos de 30 días, mal a menos de 7 o vencido", () => {
  expect([100, 30, 29, 7, 6, 0, -1].map(daysState)).toEqual(["ok", "ok", "warn", "warn", "bad", "bad", "expired"]);
});
