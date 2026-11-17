import { afterEach } from "vitest";
import { baseName, dirName, isAbsWindows, pathProblem } from "./paths";
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

test("isAbsWindows: solo unidad con separador (como winAbs del núcleo); ni UNC ni relativas a la raíz o a la unidad", () => {
  for (const p of ["C:\\x\\f.bin", "c:/f.bin", "C:\\"]) expect(isAbsWindows(p), p).toBe(true);
  for (const p of ["\\f.bin", "C:f.bin", "\\\\srv\\share\\f.bin", "\\\\srv", "f.bin", "/home/u/f.bin"]) expect(isAbsWindows(p), p).toBe(false);
});

type P = "paths.err.unc" | "paths.err.nt" | "paths.err.ads" | "paths.err.rel" | "paths.err.reserved";
const WIN_BAD: [string, P][] = [
  ["\\\\server\\share\\f.bin", "paths.err.unc"], ["//server/share/f.bin", "paths.err.unc"], ["\\\\?\\C:\\x\\f.bin", "paths.err.unc"],
  ["\\\\.\\PhysicalDrive0", "paths.err.unc"], ["//?/C:/x", "paths.err.unc"], ["\\\\?\\UNC\\srv\\s", "paths.err.unc"], ["\\\\?\\GLOBALROOT\\Device\\x", "paths.err.unc"],
  ["\\??\\C:\\x\\f", "paths.err.nt"], ["/??/C:/x", "paths.err.nt"], ["\\GLOBALROOT\\Device\\HarddiskVolume1", "paths.err.nt"], ["\\globalroot", "paths.err.nt"],
  ["C:\\x\\archivo.txt:stream", "paths.err.ads"], ["C:\\x\\a.txt:s:$DATA", "paths.err.ads"], ["archivo.txt:stream", "paths.err.ads"], ["C:\\x:y\\f", "paths.err.ads"],
  ["\\x\\f", "paths.err.rel"], ["C:x\\f", "paths.err.rel"], ["carpeta\\f.bin", "paths.err.rel"], ["..\\f", "paths.err.rel"], ["/x/f", "paths.err.rel"],
  ["C:\\CON", "paths.err.reserved"], ["C:\\x\\nul.txt", "paths.err.reserved"], ["C:\\x\\Aux.tar.gz", "paths.err.reserved"], ["C:\\PRN", "paths.err.reserved"], ["C:\\COM1", "paths.err.reserved"], ["c:/x/com9.log", "paths.err.reserved"],
  ["C:\\LPT1\\a", "paths.err.reserved"], ["C:\\a\\LPT9.x", "paths.err.reserved"], ["C:\\CONIN$", "paths.err.reserved"], ["C:\\x\\conout$.txt", "paths.err.reserved"], ["C:\\x\\CON .txt", "paths.err.reserved"],
];

test("en Windows se rechazan UNC, \\\\?\\, \\\\.\\, \\??\\, GLOBALROOT, relativas, ADS y nombres reservados; las absolutas con unidad pasan", () => {
  setOSForTests("windows");
  for (const [p, why] of WIN_BAD) expect(pathProblem(p), p).toBe(why);
  for (const ok of ["C:\\x\\f.bin", "c:/x/f.bin", "C:\\", "D:\\mi carpeta\\a.b.txt", "C:\\console\\f", "C:\\COM10", "C:\\com0", "C:\\x\\NULL.txt", "C:\\x\\a.con", ""]) expect(pathProblem(ok), ok).toBeNull();
});

test("en Linux no se rechaza nada: «\\» y «:» son parte de un nombre y «//» es una ruta común", () => {
  for (const [p] of WIN_BAD) expect(pathProblem(p), p).toBeNull();
});
