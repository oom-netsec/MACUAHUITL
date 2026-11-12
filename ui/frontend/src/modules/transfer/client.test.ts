import { buildURL, clientErrors, defaultClientPort, getParams, parseClientURL, putParams, type ClientForm } from "./client";

const base: ClientForm = {
  dir: "get", proto: "tftp", host: "192.0.2.1", port: "", portTouched: false, path: "/c4.bin", cred: "", hash: "", name: "", destDir: "", src: "",
  accepted: "", maxMB: "", minutes: "", legacy: false, insecure: false,
};
const f = (o: Partial<ClientForm> = {}): ClientForm => ({ ...base, ...o });

test("la URL sale de los campos: puerto estándar se omite, el no estándar se pone", () => {
  expect(buildURL(f())).toBe("tftp://192.0.2.1/c4.bin");
  expect(buildURL(f({ proto: "scp", port: "2200", portTouched: true }))).toBe("scp://192.0.2.1:2200//c4.bin");
  expect(buildURL(f({ proto: "https", host: "srv.example", path: "dir/a b.bin" }))).toBe("https://srv.example/dir/a%20b.bin");
});

test("IPv6 va entre corchetes, con o sin puerto, y no se duplican", () => {
  expect(buildURL(f({ proto: "sftp", host: "2001:db8::1", port: "2222", portTouched: true }))).toBe("sftp://[2001:db8::1]:2222//c4.bin");
  expect(buildURL(f({ proto: "ftp", host: "[2001:db8::1]" }))).toBe("ftp://[2001:db8::1]//c4.bin");
});

test("la query de HTTP(S) no se codifica; en otros protocolos sí", () => {
  expect(buildURL(f({ proto: "http", host: "h", path: "/f.bin?token=a&b=1" }))).toBe("http://h/f.bin?token=a&b=1");
  expect(buildURL(f({ proto: "ftp", path: "/f?x" }))).toBe("ftp://192.0.2.1//f%3Fx");
});

test("sin equipo no hay URL", () => {
  expect(buildURL(f({ host: " " }))).toBe("");
});

test("una URL pegada llena los campos, con IPv6 y sin contraseña", () => {
  expect(parseClientURL("scp://admin@[2001:db8::1]:2200/ios/c4.bin", "get")).toEqual({ proto: "scp", host: "2001:db8::1", port: "2200", path: "ios/c4.bin" });
  expect(parseClientURL("tftp://192.0.2.1/c4.bin", "get")).toEqual({ proto: "tftp", host: "192.0.2.1", port: "", path: "/c4.bin" });
  expect(parseClientURL("https://h.example:443/a%20b.bin?t=1", "get")).toEqual({ proto: "https", host: "h.example", port: "", path: "/a b.bin?t=1" });
  expect(parseClientURL("ftp://mac:pw@h/x", "get")).toBe("password");
  expect(parseClientURL("ftp://h//x/y", "get")).toMatchObject({ proto: "ftp", path: "/x/y" });
  expect(parseClientURL("ftp://h/x/y", "get")).toMatchObject({ proto: "ftp", path: "x/y" });
  expect(parseClientURL("gopher://h/x", "get")).toBeNull();
  expect(parseClientURL("no es url", "get")).toBeNull();
});

test("HTTP y HTTPS no valen para enviar", () => {
  expect(parseClientURL("http://h/x", "put")).toBeNull();
  expect(parseClientURL("https://h/x", "put")).toBeNull();
  expect(parseClientURL("sftp://h/x", "put")).not.toBeNull();
});

test("puertos por omisión estándar", () => {
  expect(defaultClientPort).toEqual({ tftp: "69", ftp: "21", scp: "22", sftp: "22", http: "80", https: "443" });
});

test("errores por campo: equipo, puerto, ruta y credencial de SCP/SFTP", () => {
  expect(clientErrors(f())).toEqual({});
  expect(clientErrors(f({ host: "" })).host).toBe("transfer.err.host");
  expect(clientErrors(f({ host: "a b" })).host).toBe("transfer.err.host");
  expect(clientErrors(f({ port: "0", portTouched: true })).port).toBe("transfer.err.cport");
  expect(clientErrors(f({ port: "65536", portTouched: true })).port).toBe("transfer.err.cport");
  expect(clientErrors(f({ port: "", portTouched: true })).port).toBe("transfer.err.cport");
  expect(clientErrors(f({ path: " / " })).path).toBe("transfer.err.path");
  expect(clientErrors(f({ proto: "scp" })).cred).toBe("transfer.err.cred");
  expect(clientErrors(f({ proto: "sftp" })).cred).toBe("transfer.err.cred");
  expect(clientErrors(f({ proto: "sftp", cred: "c1" })).cred).toBeUndefined();
  expect(clientErrors(f({ proto: "ftp" })).cred).toBeUndefined();
  expect(clientErrors(f({ hash: "xyz" })).hash).toBe("transfer.err.hash");
  expect(clientErrors(f({ dir: "put" })).src).toBe("transfer.err.src");
  expect(clientErrors(f({ minutes: "241" })).minutes).toBe("transfer.err.cminutes");
  expect(clientErrors(f({ minutes: "0" })).minutes).toBe("transfer.err.cminutes");
  expect(clientErrors(f({ maxMB: "-1" })).maxMB).toBe("transfer.err.maxmb");
});

test("el puerto por omisión sigue al protocolo hasta que el usuario lo edita", () => {
  expect(buildURL(f({ proto: "scp", cred: "c" }))).toBe("scp://192.0.2.1//c4.bin");
  // editado: el 2200 se queda aunque cambie el protocolo
  expect(buildURL(f({ proto: "sftp", port: "2200", portTouched: true }))).toBe("sftp://192.0.2.1:2200//c4.bin");
  // editado a mano al estándar de otro protocolo: ahora es no estándar y se escribe
  expect(buildURL(f({ proto: "ftp", port: "69", portTouched: true }))).toBe("ftp://192.0.2.1:69//c4.bin");
});

test("la petición de descarga lleva credencial, huellas, segundos, bytes, hash por largo, SSH antiguo e insecure", () => {
  const sha = "b".repeat(64);
  const p = getParams(f({
    proto: "scp", cred: "c1", accepted: "SHA256:aaa SHA256:bbb", maxMB: "2", minutes: "3", hash: sha, legacy: true, name: "x.bin", destDir: "/d", insecure: true,
  }));
  expect(p).toEqual({
    url: "scp://192.0.2.1//c4.bin", destDir: "/d", credentialId: "c1", acceptedHostKeys: ["SHA256:aaa", "SHA256:bbb"], legacySsh: true, insecure: false,
    name: "x.bin", maxBytes: 2 * 1024 * 1024, seconds: 180, sha256: sha,
  });
  expect(getParams(f({ hash: "a".repeat(32) }))).toMatchObject({ md5: "a".repeat(32) });
  expect(getParams(f({ hash: "c".repeat(128) }))).toMatchObject({ sha512: "c".repeat(128) });
  expect(getParams(f({ proto: "https", insecure: true }))).toMatchObject({ insecure: true, legacySsh: false });
  expect(getParams(f({ proto: "https", insecure: false }))).toMatchObject({ insecure: false });
  expect(getParams(f())).not.toHaveProperty("seconds");
  expect(getParams(f())).not.toHaveProperty("maxBytes");
});

test("las huellas se normalizan antes de salir", () => {
  const bare = "A".repeat(43);
  expect(getParams(f({ proto: "sftp", cred: "c", accepted: `${bare} sha256:xyz` })).acceptedHostKeys).toEqual([`SHA256:${bare}`, "SHA256:xyz"]);
});

test("la petición de envío separa carpeta y archivo, y solo manda credencial si el protocolo la usa", () => {
  expect(putParams(f({ dir: "put", src: "/home/u/cfg/r1.txt", proto: "tftp", cred: "sobra", legacy: true }))).toEqual({
    url: "tftp://192.0.2.1/c4.bin", fromDir: "/home/u/cfg", name: "r1.txt", credentialId: "", acceptedHostKeys: [], legacySsh: false,
  });
  expect(putParams(f({ dir: "put", src: "/r1.txt", proto: "sftp", cred: "c1", legacy: true, minutes: "1", maxMB: "1" }))).toMatchObject({
    fromDir: "/", name: "r1.txt", credentialId: "c1", legacySsh: true, seconds: 60, maxBytes: 1048576,
  });
});

// El núcleo (remotePath) quita UNA "/" inicial: scp://h/tmp/x es "tmp/x" (relativa al home) y scp://h//tmp/x es "/tmp/x" (absoluta).
test("en SCP, SFTP y FTP una ruta con / inicial sale como absoluta (//) y sin / como relativa al home", () => {
  expect(buildURL(f({ proto: "scp", path: "/tmp/x.bin" }))).toBe("scp://192.0.2.1//tmp/x.bin");
  expect(buildURL(f({ proto: "sftp", path: "/tmp/x.bin", port: "2200", portTouched: true }))).toBe("sftp://192.0.2.1:2200//tmp/x.bin");
  expect(buildURL(f({ proto: "scp", path: "dir/x.bin" }))).toBe("scp://192.0.2.1/dir/x.bin");
  // FTP igual que SCP y SFTP (decisión del 2026-11-12): "/" inicial = absoluta, sin "/" = relativa a la carpeta de inicio.
  expect(buildURL(f({ proto: "ftp", path: "/x/y.bin" }))).toBe("ftp://192.0.2.1//x/y.bin");
  expect(buildURL(f({ proto: "ftp", path: "x/y.bin" }))).toBe("ftp://192.0.2.1/x/y.bin");
  expect(parseClientURL("ftp://h//x/y", "get")).toMatchObject({ path: "/x/y" });
  expect(parseClientURL("ftp://h/x/y", "get")).toMatchObject({ path: "x/y" });
  expect(buildURL(f({ proto: "tftp", path: "x.bin" }))).toBe("tftp://192.0.2.1/x.bin");
});

test("la URL pegada de SCP/SFTP devuelve a la ruta lo que se escribió", () => {
  expect(parseClientURL("scp://h//tmp/x", "get")).toMatchObject({ path: "/tmp/x" });
  expect(parseClientURL("sftp://h/x/y", "get")).toMatchObject({ path: "x/y" });
  for (const path of ["/tmp/x", "x/y"]) {
    expect(parseClientURL(buildURL(f({ proto: "sftp", path })), "get")).toMatchObject({ path });
  }
});

test("el equipo con puerto pegado o zona IPv6 se rechaza junto al campo", () => {
  expect(clientErrors(f({ host: "10.0.0.1:2222" })).host).toBe("transfer.err.hostPort");
  expect(clientErrors(f({ host: "srv.example:22" })).host).toBe("transfer.err.hostPort");
  expect(clientErrors(f({ host: "fe80::1%eth0" })).host).toBe("transfer.err.hostZone");
  expect(clientErrors(f({ host: "2001:db8::1" })).host).toBeUndefined();
  expect(clientErrors(f({ host: "[2001:db8::1]" })).host).toBeUndefined();
  expect(clientErrors(f({ host: "::1" })).host).toBeUndefined();
});

test("el tamaño máximo es un decimal finito positivo y con tope", () => {
  for (const bad of ["Infinity", "0x10", "1e3", "-1", "0", "1,5", "abc", ".", "1.", "2000000", "0.0000001"]) expect(clientErrors(f({ maxMB: bad })).maxMB, bad).toBe("transfer.err.maxmb");
  for (const ok of ["1", "0.5", "1.5", "2048", "1048576"]) expect(clientErrors(f({ maxMB: ok })).maxMB, ok).toBeUndefined();
});

test("el archivo de envío necesita carpeta y nombre", () => {
  expect(clientErrors(f({ dir: "put", src: "r1.txt" })).src).toBe("transfer.err.srcPath");
  expect(clientErrors(f({ dir: "put", src: "/home/u/" })).src).toBe("transfer.err.srcPath");
  expect(clientErrors(f({ dir: "put", src: "/r1.txt" })).src).toBeUndefined();
});
