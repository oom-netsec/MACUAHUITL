// Tablas simples a CSV y Markdown para el menú de exportar (ExportMenu).
// Un texto que empieza con = + - @ tab o CR se vuelve fórmula en Excel o LibreOffice (syslog, descripciones y nombres los
// controla el equipo): se antepone ' para que quede como texto. Los números se escriben tal cual.
export const csvCell = (v: string | number) => {
  if (typeof v === "number") return String(v);
  const s = /^[=+\-@\t\r]/.test(v) ? `'${v}` : v;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};
const mdCell = (s: string) => s.replace(/\|/g, "\\|").replace(/\s*\n\s*/g, " ");

export const tableCsv = (head: string[], rows: string[][]) => [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\n");

export const tableMarkdown = (head: string[], rows: string[][]) =>
  [`| ${head.map(mdCell).join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`, ...rows.map((r) => `| ${r.map(mdCell).join(" | ")} |`)].join("\n");
