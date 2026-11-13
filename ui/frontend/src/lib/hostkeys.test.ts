import { hostKeyFromError, parseFingerprints } from "./hostkeys";

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
  expect(hostKeyFromError("cualquier texto", info("transport.hostkey.changed"))).toEqual({ fp: `SHA256:${b64}`, changed: true });
  expect(hostKeyFromError("cualquier texto", info("transport.hostkey.unknown"))).toEqual({ fp: `SHA256:${b64}`, changed: false });
  expect(hostKeyFromError("cualquier texto", info("transport.hostkey.known"))).toBeNull();
  expect(hostKeyFromError("transport: known host key from x: SHA256:AbC")).toBeNull();
});
