import { errInfo, fileExists } from "./coreError";

test("fileExists usa el reason y solo cae al texto si no hay cause", () => {
  const con = (reason: string, message = "x") => Object.assign(new Error(message), { cause: { code: "A", reason, metadata: {} } });
  expect(fileExists(con("file.exists", "the file already exists"))).toBe(true);
  expect(fileExists(con("ingest.invalid", "el archivo ya existe"))).toBe(false);
  expect(fileExists(new Error("rpc error: code = AlreadyExists desc = el archivo ya existe"))).toBe(true);
  expect(fileExists(new Error("otra cosa"))).toBe(false);
});

test("errInfo lee el cause del error del puente", () => {
  const e = Object.assign(new Error("rpc error: code = AlreadyExists desc = el archivo ya existe"), {
    cause: { message: "x", code: "AlreadyExists", reason: "file.exists", metadata: { path: "/a" } },
  });
  expect(errInfo(e)).toEqual({ code: "AlreadyExists", reason: "file.exists", metadata: { path: "/a" } });
});

test("errInfo da undefined sin reason o sin cause", () => {
  expect(errInfo(new Error("boom"))).toBeUndefined();
  expect(errInfo("texto")).toBeUndefined();
  expect(errInfo(null)).toBeUndefined();
  expect(errInfo(Object.assign(new Error("x"), { cause: { code: "Unavailable", reason: "", metadata: {} } }))).toBeUndefined();
});

test("errInfo completa metadata ausente", () => {
  expect(errInfo(Object.assign(new Error("x"), { cause: { code: "A", reason: "r" } }))?.metadata).toEqual({});
});
