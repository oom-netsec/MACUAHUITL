import { coreErrorField, coreErrorKey, parseTags, validateHost, type HostForm } from "./hostForm";

const ok: HostForm = { name: "SW1", address: "10.0.0.1", port: "22", platform: "ios-xe", folder: "Lab", tags: "core dc-1", credentialId: "", notes: "" };

test("un formulario correcto no tiene errores", () => {
  expect(validateHost(ok)).toEqual({});
  expect(validateHost({ ...ok, port: "", folder: "", tags: "" })).toEqual({});
});

test("cada campo inválido da su clave de error", () => {
  expect(validateHost({ ...ok, name: "  " })).toEqual({ name: "hosts.v.name" });
  expect(validateHost({ ...ok, name: "x".repeat(65) })).toEqual({ name: "hosts.v.name" });
  for (const address of ["", "a b", "admin@10.0.0.1", "ssh://h", "h/ruta", "10.0.0.1:22"]) expect(validateHost({ ...ok, address }), address).toEqual({ address: "hosts.v.address" });
  expect(validateHost({ ...ok, address: "fe80::1" })).toEqual({}); // IPv6 lleva ':' y es válida
  for (const port of ["0", "65536", "abc", "2.5", "-1"]) expect(validateHost({ ...ok, port }), port).toEqual({ port: "hosts.v.port" });
  expect(validateHost({ ...ok, folder: "a/b" })).toEqual({ folder: "hosts.v.folder" });
  expect(validateHost({ ...ok, folder: "x".repeat(49) })).toEqual({ folder: "hosts.v.folder" });
  expect(validateHost({ ...ok, tags: "Mayus" })).toEqual({ tags: "hosts.v.tags" });
  expect(validateHost({ ...ok, tags: "a a" })).toEqual({ tags: "hosts.v.tags" }); // repetida
  expect(validateHost({ ...ok, tags: Array.from({ length: 11 }, (_, i) => `t${i}`).join(",") })).toEqual({ tags: "hosts.v.tags" });
  expect(validateHost({ ...ok, notes: "n".repeat(2001) })).toEqual({ notes: "hosts.v.notes" });
});

test("las etiquetas se separan por coma o espacio", () => {
  expect(parseTags(" core, dc-1  acceso ")).toEqual(["core", "dc-1", "acceso"]);
  expect(parseTags("")).toEqual([]);
});

test("las duplicadas se reconocen antes que «credencial» aunque el nombre del host la mencione", () => {
  expect(coreErrorField('ya hay un host llamado "credencial lab"')).toBe("name");
  expect(coreErrorField('"10.0.0.1:22" ya está en la libreta como "credencial lab"')).toBe("address");
  expect(coreErrorKey('ya hay un host llamado "credencial lab"')).toBe("hosts.err.nameDup");
  expect(coreErrorKey('"10.0.0.1:22" ya está en la libreta como "x"')).toBe("hosts.err.addrDup");
  expect(coreErrorKey("la credencial no existe en la bóveda")).toBe("");
});

test("la longitud de nombre y notas se cuenta por caracteres, como el núcleo", () => {
  expect(validateHost({ ...ok, name: "🙂".repeat(64) })).toEqual({}); // 64 caracteres, 128 unidades UTF-16
  expect(validateHost({ ...ok, name: "🙂".repeat(65) })).toEqual({ name: "hosts.v.name" });
  expect(validateHost({ ...ok, notes: "🙂".repeat(2000) })).toEqual({});
  expect(validateHost({ ...ok, notes: "🙂".repeat(2001) })).toEqual({ notes: "hosts.v.notes" });
});

test("el error del núcleo se asigna al campo que nombra", () => {
  expect(coreErrorField('dirección "admin@x": use una IP o un nombre DNS')).toBe("address");
  expect(coreErrorField('ya hay un host llamado "SW1"')).toBe("name");
  expect(coreErrorField('"10.0.0.1:22" ya está en la libreta como "SW1"')).toBe("address");
  expect(coreErrorField("la credencial no existe en la bóveda (o es una entrada del sistema)")).toBe("credentialId");
  expect(coreErrorField("el núcleo no responde")).toBe("");
});
