import { csvCell, tableCsv, tableMarkdown } from "./tableExport";

const head = ["Regla", "Texto"];
const rows = [["1", "permit tcp any any"], ["2", 'deny "ip", pipe | x']];

test("CSV entrecomilla comas, comillas y saltos de línea", () => {
  expect(tableCsv(head, rows)).toBe('Regla,Texto\n1,permit tcp any any\n2,"deny ""ip"", pipe | x"');
  expect(tableCsv(["a"], [["x\ny"]])).toBe('a\n"x\ny"');
});

test("Markdown escapa la barra vertical y los saltos de línea", () => {
  expect(tableMarkdown(head, rows)).toBe("| Regla | Texto |\n| --- | --- |\n| 1 | permit tcp any any |\n| 2 | deny \"ip\", pipe \\| x |");
  expect(tableMarkdown(["a"], [["x\ny"]])).toBe("| a |\n| --- |\n| x y |");
});

test("sin filas deja solo el encabezado", () => {
  expect(tableCsv(head, [])).toBe("Regla,Texto");
});

test("csvCell neutraliza fórmulas y entrecomilla CR; los números van tal cual", () => {
  expect(csvCell('=HYPERLINK("http://x","ver")')).toBe(`"'=HYPERLINK(""http://x"",""ver"")"`);
  expect(csvCell("@SUM(A1)")).toBe("'@SUM(A1)");
  expect(csvCell("+1")).toBe("'+1");
  expect(csvCell("a\rb")).toBe('"a\rb"');
  expect(csvCell(-5)).toBe("-5");
  expect(csvCell("Gi1/0/1")).toBe("Gi1/0/1");
});

test("csvCell neutraliza cada disparador de fórmula: = + - @ tab y CR (y no toca lo que no empieza con ellos)", () => {
  for (const c of ["=", "+", "-", "@", "\t"]) expect(csvCell(`${c}cmd|' /C calc'!A0`), JSON.stringify(c)).toMatch(/^"?'/);
  expect(csvCell("-1+1")).toBe("'-1+1");
  expect(csvCell("@x")).toBe("'@x");
  expect(csvCell("\tx")).toBe("'\tx");
  expect(csvCell("\rx")).toBe('"\'\rx"'); // CR además obliga a entrecomillar
  expect(csvCell("a-b=c@d+e")).toBe("a-b=c@d+e"); // solo importa el primer carácter
  expect(tableCsv(["=h"], [["-x", "@y"]])).toBe("'=h\n'-x,'@y"); // encabezado y celdas por el mismo camino
});
