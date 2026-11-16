import { afterEach } from "vitest";
import { baseName, dirName, isAbsWindows } from "./paths";
import { setOSForTests } from "./platform";

afterEach(() => setOSForTests(undefined));

test("en Linux solo «/» separa: «\\» es un carácter válido de un nombre", () => {
  expect(baseName("/home/u/cfg/r1.txt")).toBe("r1.txt");
  expect(dirName("/home/u/cfg/r1.txt")).toBe("/home/u/cfg");
  expect(dirName("/r1.txt")).toBe("/");
  expect(baseName("/home/u/a\\b.txt")).toBe("a\\b.txt");
  expect(dirName("r1.txt")).toBe("");
  expect(baseName("/home/u/cfg/")).toBe("");
  expect(dirName("/")).toBe("/");
  expect(baseName("/")).toBe("");
});

test("en Windows separan «\\» y «/», y la raíz de una unidad conserva su separador", () => {
  setOSForTests("windows");
  expect(baseName("C:\\x\\f.bin")).toBe("f.bin");
  expect(dirName("C:\\x\\f.bin")).toBe("C:\\x");
  expect(dirName("C:\\f.bin")).toBe("C:\\"); // «C:» a secas sería la carpeta actual de la unidad
  expect(dirName("C:/x/f.bin")).toBe("C:/x");
  expect(dirName("\\\\srv\\share\\f.bin")).toBe("\\\\srv\\share");
  expect(baseName("C:\\x\\")).toBe("");
  expect(dirName("C:f.bin")).toBe("");
  expect(baseName("C:\\")).toBe("");
});

test("isAbsWindows: unidad con separador o UNC con servidor y recurso", () => {
  for (const p of ["C:\\x\\f.bin", "c:/f.bin", "\\\\srv\\share\\f.bin"]) expect(isAbsWindows(p), p).toBe(true);
  for (const p of ["\\f.bin", "C:f.bin", "\\\\srv\\f.bin", "\\\\srv", "f.bin", "/home/u/f.bin"]) expect(isAbsWindows(p), p).toBe(false);
});
