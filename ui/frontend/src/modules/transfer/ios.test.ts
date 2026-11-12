import { iosCommands } from "./ios";
import { expectedHash, hostKeyFromError, parseURL, serveProblem } from "./validate";

const ph = { ip: "IP-X", file: "ARCH" };
const base = { user: "mac", password: "pw", files: ["c4.bin"] };

test("el comando de IOS cambia con el protocolo", () => {
  const cmd = (protocol: "tftp" | "ftp" | "scp" | "sftp" | "http", listening = "192.0.2.10:6969", write = false) => iosCommands({ ...base, protocol, listening }, write, ph);
  expect(cmd("tftp")).toEqual(["copy tftp://192.0.2.10/c4.bin flash:"]);
  expect(cmd("tftp", "192.0.2.10:6969", true)).toEqual(["copy tftp://192.0.2.10/c4.bin flash:", "copy running-config tftp://192.0.2.10/r1-config.txt"]);
  expect(cmd("ftp")).toEqual(["copy ftp://mac:pw@192.0.2.10/c4.bin flash:"]);
  expect(cmd("scp")).toEqual(["copy scp://mac@192.0.2.10/c4.bin flash:"]);
  expect(cmd("sftp")).toEqual(["copy sftp://mac@192.0.2.10/c4.bin flash:"]);
  expect(cmd("http", "192.0.2.10:8080")).toEqual(["copy http://192.0.2.10:8080/c4.bin flash:"]);
  expect(cmd("http", "192.0.2.10:8080", true)).toHaveLength(1); // HTTP no recibe
});

test("sin archivos o en 0.0.0.0 usa los marcadores, y IPv6 va entre corchetes", () => {
  expect(iosCommands({ ...base, files: null, protocol: "tftp", listening: "0.0.0.0:6969" }, false, ph)).toEqual(["copy tftp://IP-X/ARCH flash:"]);
  expect(iosCommands({ ...base, protocol: "scp", listening: "[2001:db8::1]:2222" }, false, ph)).toEqual(["copy scp://mac@[2001:db8::1]/c4.bin flash:"]);
});

const form = { proto: "tftp" as const, any: false, listen: "192.0.2.10", port: "6969", write: false, recvDir: "", fromDir: "/srv/img", files: "", allow: "", minutes: "30" };
test("validación del servidor", () => {
  expect(serveProblem(form)).toBeNull();
  expect(serveProblem({ ...form, listen: "" })).toBe("transfer.err.listen");
  expect(serveProblem({ ...form, port: "69" })).toBe("transfer.err.port");
  expect(serveProblem({ ...form, fromDir: "" })).toBe("transfer.err.nothing");
  expect(serveProblem({ ...form, fromDir: "", write: true, proto: "scp" })).toBeNull();
  expect(serveProblem({ ...form, fromDir: "", write: true })).toBe("transfer.err.tftpAllow"); // en UDP el origen se falsifica: la lista es obligatoria
  expect(serveProblem({ ...form, fromDir: "", write: true, allow: "10.0.0.1" })).toBeNull();
  expect(serveProblem({ ...form, allow: "10.0.0.1, 999.1.1.1" })).toBe("transfer.err.allow");
  expect(serveProblem({ ...form, allow: "10.0.0.1 2001:db8::5" })).toBeNull();
  expect(serveProblem({ ...form, any: true, listen: "" })).toBe("transfer.err.anyAllow"); // todas las interfaces: siempre con lista
  expect(serveProblem({ ...form, any: true, listen: "", allow: "10.0.0.1" })).toBeNull();
  expect(serveProblem({ ...form, minutes: "0" })).toBe("transfer.err.minutes");
});

test("URL, hash esperado y llave de host", () => {
  expect(parseURL("scp://mac@10.0.0.1/ios.bin")).toMatchObject({ scheme: "scp", userinfo: "mac", host: "10.0.0.1" });
  expect(parseURL("ftp://mac:pw@10.0.0.1/x")).toBe("password");
  expect(parseURL("telnet://x/y")).toBeNull();
  expect(expectedHash("")).toBe("");
  expect(expectedHash("SHA256: " + "AB".repeat(32))).toEqual({ kind: "sha256", value: "ab".repeat(32) });
  expect(expectedHash("a".repeat(32))).toEqual({ kind: "md5", value: "a".repeat(32) });
  expect(expectedHash("zz")).toBeNull();
  expect(hostKeyFromError("transport: llave de host desconocida de 10.0.0.1:22: SHA256:abc+/=")).toEqual({ fp: "SHA256:abc+/=", changed: false });
  expect(hostKeyFromError("transport: llave de host cambiada de h: SHA256:xyz")?.changed).toBe(true);
  expect(hostKeyFromError("timeout")).toBeNull();
});
