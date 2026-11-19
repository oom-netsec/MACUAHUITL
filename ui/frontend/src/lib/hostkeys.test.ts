import { hostKeyFromError, hostKeysFromLogin, keygenCommands, parseFingerprints, resolveAccepted } from "./hostkeys";

const b64 = "pNHDf6UtoRxP6cpwKx8lTIgynz79VhQDMyc6PwSU8OU";

test("parseFingerprints acepta la huella con o sin prefijo y descarta lo que no es SHA-256", () => {
  expect(parseFingerprints(`${b64}, SHA256:${b64}\nsha256:abc${b64.slice(3)} MD5:aa:bb`)).toEqual([`SHA256:${b64}`, `SHA256:abc${b64.slice(3)}`]);
  expect(parseFingerprints("")).toEqual([]);
});

test("hostKeyFromError lee la huella de una llave nueva o cambiada", () => {
  expect(hostKeyFromError(`transport: llave de host desconocida de 192.168.3.2:22: SHA256:${b64}`)).toEqual({ fp: `SHA256:${b64}`, changed: false });
  expect(hostKeyFromError("transport: llave de host cambiada de x: SHA256:AbC+/=")).toEqual({ fp: "SHA256:AbC+/=", changed: true });
  expect(hostKeyFromError("tiempo agotado")).toBeNull();
});

// Con la interfaz en inglés el núcleo manda el texto en inglés: la huella se lee igual, y del reason si viene.
test("hostKeyFromError lee el texto en inglés y el reason del núcleo", () => {
  expect(hostKeyFromError(`transport: unknown host key from 192.168.3.2:22: SHA256:${b64}`)).toEqual({ fp: `SHA256:${b64}`, changed: false });
  expect(hostKeyFromError("transport: changed host key from x: SHA256:AbC+/=")).toEqual({ fp: "SHA256:AbC+/=", changed: true });
  const info = (reason: string) => ({ code: "FailedPrecondition", reason, metadata: { host: "x", fingerprint: `SHA256:${b64}` } });
  expect(hostKeyFromError("cualquier texto", info("transport.hostkey.changed"))).toEqual({ fp: `SHA256:${b64}`, changed: true, host: "x" });
  expect(hostKeyFromError("cualquier texto", info("transport.hostkey.unknown"))).toEqual({ fp: `SHA256:${b64}`, changed: false, host: "x" });
  expect(hostKeyFromError("cualquier texto", info("transport.hostkey.known"))).toBeNull();
  expect(hostKeyFromError("x", { code: "", reason: "patrol.svc.login", metadata: { cause_reason: "transport.hostkey.unknown", fingerprint: `SHA256:${b64}` } })).toEqual({ fp: `SHA256:${b64}`, changed: false });
  expect(hostKeyFromError("x", { code: "", reason: "transport.hostkey.unknown", metadata: {} })).toBeNull(); // sin huella no hay qué aceptar
  expect(hostKeyFromError("transport: known host key from x: SHA256:AbC")).toBeNull();
});

test("hostKeyFromError trae el tipo de llave y keygenCommands arma la orden de Linux y de Windows según el tipo", () => {
  const info = (key_type: string) => ({ code: "FailedPrecondition", reason: "transport.hostkey.unknown", metadata: { host: "10.0.0.5:22", fingerprint: `SHA256:${b64}`, key_type } });
  expect(hostKeyFromError("x", info("ssh-ed25519"))).toEqual({ fp: `SHA256:${b64}`, changed: false, host: "10.0.0.5:22", keyType: "ssh-ed25519" });
  expect(keygenCommands("ssh-ed25519")).toEqual({ linux: "ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub", windows: "ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_ed25519_key.pub" });
  expect(keygenCommands("ecdsa-sha2-nistp256")?.linux).toBe("ssh-keygen -lf /etc/ssh/ssh_host_ecdsa_key.pub");
  expect(keygenCommands("rsa-sha2-512")?.linux).toBe("ssh-keygen -lf /etc/ssh/ssh_host_rsa_key.pub");
  expect(keygenCommands("ssh-rsa")?.windows).toBe("ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_rsa_key.pub");
  expect(keygenCommands("ssh-dss")).toBeNull();
});

test("resolveAccepted: una huella sola se empareja con el único equipo; con varios no se manda y avisa", () => {
  const one = [{ address: "10.0.0.1", port: 0 }];
  expect(resolveAccepted(`SHA256:${b64}`, one)).toEqual({ keys: [{ host: "10.0.0.1", fingerprint: `SHA256:${b64}` }], ambiguous: false });
  expect(resolveAccepted(b64, [{ address: "sw1.lab", port: 2222 }]).keys).toEqual([{ host: "sw1.lab:2222", fingerprint: `SHA256:${b64}` }]);
  expect(resolveAccepted(b64, [{ address: "2001:db8::1", port: 22 }]).keys[0].host).toBe("[2001:db8::1]");
  const two = [{ address: "10.0.0.1", port: 0 }, { address: "10.0.0.2", port: 0 }];
  expect(resolveAccepted(`SHA256:${b64}`, two)).toEqual({ keys: [], ambiguous: true });
  expect(resolveAccepted("", [])).toEqual({ keys: [], ambiguous: false });
});

test("resolveAccepted: EQUIPO=HUELLA y EQUIPO:PUERTO=HUELLA, repetibles, valen con varios equipos", () => {
  const two = [{ address: "10.0.0.1", port: 0 }, { address: "10.0.0.2", port: 2222 }];
  const r = resolveAccepted(`10.0.0.1=${b64}, 10.0.0.2:2222=sha256:${b64.slice(0, 42)}A\n[2001:db8::1]:22=SHA256:${b64}`, two);
  expect(r.ambiguous).toBe(false);
  expect(r.keys).toEqual([
    { host: "10.0.0.1", fingerprint: `SHA256:${b64}` },
    { host: "10.0.0.2:2222", fingerprint: `SHA256:${b64.slice(0, 42)}A` },
    { host: "[2001:db8::1]:22", fingerprint: `SHA256:${b64}` },
  ]);
  // Una suelta mezclada con pares sigue siendo ambigua; una huella que no es SHA-256 se descarta.
  expect(resolveAccepted(`10.0.0.1=${b64} ${b64}`, two)).toMatchObject({ ambiguous: true });
  expect(resolveAccepted("10.0.0.1=MD5:aa:bb =SHA256:x", two)).toEqual({ keys: [], ambiguous: false });
});

test("hostKeysFromLogin toma solo los equipos rechazados por llave de host, con tipo y cambio por reason", () => {
  const row = (o: object) => ({ target: "10.0.0.1:22", passed: false, failedStep: "LOGIN_TEST_STEP_HOST_KEY", detail: "", platform: "", fingerprint: "SHA256:aaa", ...o });
  expect(hostKeysFromLogin([
    row({}),
    row({ target: "10.0.0.2:22", fingerprint: "SHA256:bbb", reason: "transport.hostkey.changed", args: { key_type: "ssh-ed25519", host: "10.0.0.2:22" } }),
    row({ target: "10.0.0.3:22", fingerprint: "", failedStep: "LOGIN_TEST_STEP_AUTH" }),
    row({ target: "10.0.0.4:22", passed: true, failedStep: "LOGIN_TEST_STEP_UNSPECIFIED", fingerprint: "SHA256:ccc" }),
    row({ target: "10.0.0.5:22", failedStep: "LOGIN_TEST_STEP_AUTH", fingerprint: "SHA256:ddd" }),
  ])).toEqual([
    { fp: "SHA256:aaa", changed: true, host: "10.0.0.1:22" }, // paso HOST_KEY sin reason: se trata como cambiada (pide la casilla)
    { fp: "SHA256:bbb", changed: true, host: "10.0.0.2:22", keyType: "ssh-ed25519" },
  ]);
});

test("hostKeysFromLogin lee el reason envuelto (args.cause_reason) igual que hostKeyFromError", () => {
  const row = { target: "10.0.0.2:22", passed: false, failedStep: "LOGIN_TEST_STEP_AUTH", detail: "", platform: "", fingerprint: "SHA256:bbb", reason: "login.failed", args: { cause_reason: "transport.hostkey.changed" } };
  expect(hostKeysFromLogin([row])).toEqual([{ fp: "SHA256:bbb", changed: true, host: "10.0.0.2:22" }]);
});
