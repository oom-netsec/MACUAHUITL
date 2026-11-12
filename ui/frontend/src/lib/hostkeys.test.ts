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
