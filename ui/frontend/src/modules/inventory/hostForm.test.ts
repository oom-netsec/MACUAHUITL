import { PLATFORMS, draftOf, formOf, coreErrorField, folderNotEmpty, hostPlatformOf, coreErrorKey, parseTags, validateHost, type HostForm } from "./hostForm";

const ok: HostForm = { name: "SW1", address: "10.0.0.1", port: "22", platform: "ios-xe", folder: "Lab", tags: "core dc-1", credentialId: "", notes: "", startCommand: "" };

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
  expect(coreErrorField(new Error('ya hay un host llamado "credencial lab"'))).toBe("name");
  expect(coreErrorField(new Error('"10.0.0.1:22" ya está en la libreta como "credencial lab"'))).toBe("address");
  expect(coreErrorKey(new Error('ya hay un host llamado "credencial lab"'))).toBe("hosts.err.nameDup");
  expect(coreErrorKey(new Error('"10.0.0.1:22" ya está en la libreta como "x"'))).toBe("hosts.err.addrDup");
  expect(coreErrorKey(new Error("la credencial no existe en la bóveda"))).toBe("");
});

test("la longitud de nombre y notas se cuenta por caracteres, como el núcleo", () => {
  expect(validateHost({ ...ok, name: "🙂".repeat(64) })).toEqual({}); // 64 caracteres, 128 unidades UTF-16
  expect(validateHost({ ...ok, name: "🙂".repeat(65) })).toEqual({ name: "hosts.v.name" });
  expect(validateHost({ ...ok, notes: "🙂".repeat(2000) })).toEqual({});
  expect(validateHost({ ...ok, notes: "🙂".repeat(2001) })).toEqual({ notes: "hosts.v.notes" });
});

test("el error del núcleo se asigna al campo que nombra", () => {
  expect(coreErrorField(new Error('dirección "admin@x": use una IP o un nombre DNS'))).toBe("address");
  expect(coreErrorField(new Error('ya hay un host llamado "SW1"'))).toBe("name");
  expect(coreErrorField(new Error('"10.0.0.1:22" ya está en la libreta como "SW1"'))).toBe("address");
  expect(coreErrorField(new Error("la credencial no existe en la bóveda (o es una entrada del sistema)"))).toBe("credentialId");
  expect(coreErrorField(new Error("el núcleo no responde"))).toBe("");
});

const bridge = (reason: string, metadata: Record<string, string>, text = "texto cualquiera") => Object.assign(new Error(text), { cause: { code: "InvalidArgument", reason, metadata } });

test("con reason el campo sale de metadata.field, sin leer el texto", () => {
  for (const f of ["name", "address", "port", "platform", "folder", "tags", "notes", "credentialId"] as const)
    expect(coreErrorField(bridge(`hosts.invalid_${f}`, { field: f }, "texto con nombre, puerto y credencial"))).toBe(f);
  expect(coreErrorField(bridge("hosts.unknown_credential", { field: "credentialId" }, "the name is wrong"))).toBe("credentialId");
});

test("los duplicados se reconocen por reason, también con metadata.id", () => {
  const n = bridge("hosts.duplicate_name", { field: "name", id: "h1", name: "SW1" }, "a host named SW1 exists");
  const a = bridge("hosts.duplicate_address", { field: "address", id: "h1", key: "10.0.0.1:22" }, "already in the book");
  expect(coreErrorKey(n)).toBe("hosts.err.nameDup");
  expect(coreErrorKey(a)).toBe("hosts.err.addrDup");
  expect(coreErrorField(n)).toBe("name");
  expect(coreErrorField(a)).toBe("address");
  expect(coreErrorKey(bridge("hosts.unknown_credential", { field: "credentialId" }))).toBe("");
});

test("un error con reason ajeno a hosts no se asigna a ningún campo aunque el texto diga «nombre»", () => {
  expect(coreErrorField(bridge("vault.locked", {}, "el nombre de la bóveda"))).toBe("");
});

test("ftd es una plataforma de host", () => {
  expect(PLATFORMS.map(([v]) => v)).toContain("ftd");
});

test("ise es una plataforma de host", () => {
  expect(PLATFORMS.map(([v]) => v)).toContain("ise");
});

test("la plataforma detectada pasa a la del inventario: variantes de WLC son wlc y lo desconocido queda sin definir", () => {
  expect(hostPlatformOf("wlc-aireos")).toBe("wlc");
  expect(hostPlatformOf("wlc-9800")).toBe("wlc");
  expect(hostPlatformOf("asa")).toBe("asa");
  expect(hostPlatformOf("cat9k")).toBe("");
  expect(hostPlatformOf("")).toBe("");
});

test("las plataformas linux y windows existen", () => {
  expect(PLATFORMS).toContainEqual(["linux", "Linux"]);
  expect(PLATFORMS).toContainEqual(["windows", "Windows"]);
  expect(hostPlatformOf("linux")).toBe("linux");
});

test("la orden de inicio: una línea, sin caracteres de control, hasta 256", () => {
  expect(validateHost({ ...ok, platform: "linux", startCommand: "tmux attach || tmux new" })).toEqual({});
  expect(validateHost({ ...ok, platform: "linux", startCommand: "x".repeat(256) })).toEqual({});
  expect(validateHost({ ...ok, platform: "linux", startCommand: "x".repeat(257) })).toEqual({ startCommand: "hosts.v.startCommand" });
  expect(validateHost({ ...ok, platform: "windows", startCommand: "a\nb" })).toEqual({ startCommand: "hosts.v.startCommand" });
  expect(validateHost({ ...ok, platform: "linux", startCommand: " tmux" })).toEqual({ startCommand: "hosts.v.startCommand" }); // espacios en los extremos
  expect(validateHost({ ...ok, platform: "linux", startCommand: "tmux " })).toEqual({ startCommand: "hosts.v.startCommand" });
  expect(validateHost({ ...ok, platform: "windows", startCommand: "a\u0007b" })).toEqual({ startCommand: "hosts.v.startCommand" });
});

test("la orden de inicio rechaza tab, U+2028 y caracteres invisibles (Trojan Source) y cuenta caracteres astrales como uno", () => {
  for (const bad of ["a\tb", "a\u2028b", "a\u2029b", "a\u202Eb", "a\u2066b", "a\u200Bb", "\uFEFFa"]) expect(validateHost({ ...ok, platform: "linux", startCommand: bad })).toEqual({ startCommand: "hosts.v.startCommand" });
  expect(validateHost({ ...ok, platform: "linux", startCommand: "🙂".repeat(256) })).toEqual({}); // 256 caracteres, 512 unidades UTF-16
  expect(validateHost({ ...ok, platform: "linux", startCommand: "🙂".repeat(257) })).toEqual({ startCommand: "hosts.v.startCommand" });
});

test("un error del núcleo de la orden de inicio cae en su campo", () => {
  expect(coreErrorField(bridge("hosts.invalid_startup_command", { field: "startup_command" }, "texto con nombre y credencial"))).toBe("startCommand");
  expect(coreErrorField(new Error("orden de inicio inválida: lleva un salto de línea"))).toBe("startCommand");
});

test("la orden de inicio solo viaja con linux o windows", () => {
  expect(draftOf({ ...ok, platform: "linux", startCommand: "ls" }).startCommand).toBe("ls");
  expect(draftOf({ ...ok, platform: "ios-xe", startCommand: "ls" }).startCommand).toBe("");
  expect(formOf({ ...ok, port: 22, tags: [], startCommand: "ls" }).startCommand).toBe("ls");
});

test("errores con nombre fijo del núcleo (fase 44): credencial de llave fuera de linux/windows y carpeta con hosts", () => {
  const err = (code: string, reason: string, metadata: Record<string, string>) => Object.assign(new Error("x"), { cause: { code, reason, metadata } });
  expect(coreErrorField(err("InvalidArgument", "hosts.err.key_credential_platform", { field: "credential_id" }))).toBe("credentialId");
  expect(coreErrorField(err("InvalidArgument", "hosts.err.x", { field: "startup_command" }))).toBe("startCommand");
  expect(folderNotEmpty(err("FailedPrecondition", "hosts.err.folder_not_empty", { host_count: "3", name: "Lab" }))).toEqual({ n: "3" });
  expect(folderNotEmpty(err("FailedPrecondition", "hosts.err.otra_cosa", { host_count: "3" }))).toBeNull(); // otro FailedPrecondition no pide confirmar
});
