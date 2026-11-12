// Tabla de datos (ADR 0009): búsqueda, filtro por columna, orden, columnas ocultables y redimensionables,
// encabezado fijo, selección múltiple con barra de acciones, exportar CSV, ir a la fila y filas virtualizadas.
// Usa roles de tabla sobre una cuadrícula CSS para poder virtualizar sin perder la semántica.
import { useContext, useMemo, useRef, useState, type ReactNode } from "react";
import { observeElementRect, useVirtualizer } from "@tanstack/react-virtual";
import { CoreContext } from "../app/activity";
import { useT } from "../lib/i18n";
import { Icon } from "./Icon";
import { csvCell } from "../lib/tableExport";

export interface Column<T> {
  id: string;
  header: string;
  value: (row: T) => string | number; // para buscar, ordenar, filtrar y exportar
  render?: (row: T) => ReactNode;      // cómo se muestra (por omisión, el valor)
  mono?: boolean;
  wrap?: boolean;                      // el texto envuelve (la tabla debe tener rowHeight para varias líneas)
  width?: number;                      // px inicial; sin él la columna reparte el espacio
}

interface Props<T> {
  label: string;
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string;
  selectable?: boolean;
  actions?: (selected: T[]) => ReactNode;
  exportName?: string;
  height?: number;
  rowHeight?: number;                  // alto de cada fila en px (32 por omisión)
}

const ROW = 32;
const norm = (s: string) => s.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase();
const cmp = (a: string | number, b: string | number) =>
  typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b), undefined, { numeric: true });

export function DataTable<T>({ label, columns, rows, rowKey, selectable, actions, exportName, height = 420, rowHeight = ROW }: Props<T>) {
  const t = useT();
  const core = useContext(CoreContext);
  const [q, setQ] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [showFilters, setShowFilters] = useState(false);
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const [colsMenu, setColsMenu] = useState(false);
  const [sort, setSort] = useState<{ id: string; dir: 1 | -1 } | null>(null);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [widths, setWidths] = useState<Record<string, number>>({});
  const scroll = useRef<HTMLDivElement>(null);

  const visible = columns.filter((c) => !hidden.has(c.id));
  const shown = useMemo(() => {
    const words = norm(q).split(/\s+/).filter(Boolean);
    let out = rows.filter((r) => {
      const all = norm(columns.map((c) => String(c.value(r))).join(" "));
      if (!words.every((w) => all.includes(w))) return false;
      return columns.every((c) => !filters[c.id] || norm(String(c.value(r))).includes(norm(filters[c.id])));
    });
    if (sort) {
      const c = columns.find((x) => x.id === sort.id);
      if (c) out = [...out].sort((a, b) => cmp(c.value(a), c.value(b)) * sort.dir);
    }
    return out;
  }, [rows, columns, q, filters, sort]);

  const v = useVirtualizer({
    count: shown.length, getScrollElement: () => scroll.current, estimateSize: () => rowHeight, overscan: 10,
    initialRect: { width: 900, height },
    // Un contenedor sin medir (oculto o en pruebas) mide 0: se usa su alto fijo.
    observeElementRect: (inst, cb) => observeElementRect(inst, (r) => cb(r.height ? r : { width: r.width || 900, height })),
  });

  const grid = [selectable ? "36px" : "", ...visible.map((c) => (widths[c.id] ?? c.width) ? `${widths[c.id] ?? c.width}px` : "minmax(96px, 1fr)")].filter(Boolean).join(" ");
  const selected = rows.filter((r) => sel.has(rowKey(r)));
  const toggle = (k: string) => setSel((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const allOn = shown.length > 0 && shown.every((r) => sel.has(rowKey(r)));
  const goTo = (n: number) => {
    const el = scroll.current;
    if (!el || !n) return;
    const i = Math.max(0, Math.min(shown.length - 1, n - 1));
    el.scrollTop = Math.max(0, i * rowHeight - height / 2);
    el.dispatchEvent(new Event("scroll"));
  };
  const exportCSV = () => core?.saveFile(`${exportName}.csv`,
    [visible.map((c) => csvCell(c.header)).join(","), ...shown.map((r) => visible.map((c) => csvCell(c.value(r))).join(","))].join("\n"), "utf8").catch(() => "");
  const startResize = (id: string, e: React.PointerEvent) => {
    const head = (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect();
    const x0 = e.clientX, w0 = head.width;
    const move = (ev: PointerEvent) => setWidths((w) => ({ ...w, [id]: Math.max(64, Math.round(w0 + ev.clientX - x0)) }));
    const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };

  return (
    <div className="data-table">
      <div className="dt-toolbar">
        <span className="dt-search"><Icon name="search" size={14} />
          <input aria-label={t("dt.search")} placeholder={t("dt.searchPh")} value={q} onChange={(e) => setQ(e.target.value)} spellCheck={false} />
        </span>
        <span className="meta">{shown.length === rows.length ? t("dt.rows", { n: rows.length }) : t("dt.count", { n: shown.length, total: rows.length })}</span>
        <span className="dt-tools">
          <button className="quiet sm" aria-pressed={showFilters} onClick={() => setShowFilters((f) => !f)}>{t("dt.filters")}</button>
          <span className="dt-menu">
            <button className="quiet sm" aria-expanded={colsMenu} onClick={() => setColsMenu((m) => !m)}>{t("dt.columns")}</button>
            {colsMenu && (
              <fieldset className="popover dt-cols">
                <legend className="sr">{t("dt.columns")}</legend>
                {columns.map((c) => (
                  <label key={c.id} className="check"><input type="checkbox" checked={!hidden.has(c.id)} disabled={!hidden.has(c.id) && visible.length === 1}
                    onChange={() => setHidden((h) => { const n = new Set(h); if (n.has(c.id)) n.delete(c.id); else n.add(c.id); return n; })} />{c.header}</label>
                ))}
              </fieldset>
            )}
          </span>
          {exportName && <button className="quiet sm" onClick={exportCSV}>{t("dt.csv")}</button>}
          <label className="dt-goto-l">{t("dt.goto")}
            <input className="dt-goto mono" type="number" min={1} placeholder="#"
              onKeyDown={(e) => { if (e.key === "Enter") goTo(Number((e.target as HTMLInputElement).value)); }} />
          </label>
        </span>
      </div>
      {selectable && sel.size > 0 && (
        <div className="dt-selection" role="toolbar" aria-label={t("dt.actions")}>
          <strong>{t("dt.selected", { n: sel.size })}</strong>
          {actions?.(selected)}
          <button className="quiet sm" onClick={() => setSel(new Set())}>{t("dt.clear")}</button>
        </div>
      )}
      <div className="dt" role="table" aria-label={label} aria-rowcount={shown.length + 1} ref={scroll} style={{ height }}>
        <div role="rowgroup" className="dt-head">
          <div role="row" className="dt-row" style={{ gridTemplateColumns: grid }}>
            {selectable && (
              <div role="columnheader" className="dt-cell">
                <input type="checkbox" aria-label={t("dt.selectAll")} checked={allOn}
                  onChange={() => setSel(allOn ? new Set() : new Set(shown.map(rowKey)))} />
              </div>
            )}
            {visible.map((c) => (
              <div key={c.id} role="columnheader" className="dt-cell" aria-sort={sort?.id === c.id ? (sort.dir === 1 ? "ascending" : "descending") : "none"}>
                <button className="dt-sort" onClick={() => setSort((s) => (s?.id === c.id ? { id: c.id, dir: s.dir === 1 ? -1 : 1 } : { id: c.id, dir: 1 }))}>
                  {c.header}{sort?.id === c.id && <span aria-hidden="true">{sort.dir === 1 ? " ↑" : " ↓"}</span>}
                </button>
                {showFilters && <input className="dt-filter" aria-label={t("dt.filter", { col: c.header })} value={filters[c.id] ?? ""}
                  onChange={(e) => setFilters((f) => ({ ...f, [c.id]: e.target.value }))} />}
                <span className="dt-resize" aria-hidden="true" onPointerDown={(e) => startResize(c.id, e)} />
              </div>
            ))}
          </div>
        </div>
        <div role="rowgroup" className="dt-body" style={{ height: v.getTotalSize() }}>
          {v.getVirtualItems().map((it) => {
            const r = shown[it.index];
            const k = rowKey(r);
            return (
              <div key={k} role="row" aria-rowindex={it.index + 2} aria-selected={selectable ? sel.has(k) : undefined} className="dt-row"
                style={{ gridTemplateColumns: grid, transform: `translateY(${it.start}px)`, height: rowHeight }}>
                {selectable && <div role="cell" className="dt-cell"><input type="checkbox" aria-label={t("dt.select", { row: String(visible[0]?.value(r) ?? k) })} checked={sel.has(k)} onChange={() => toggle(k)} /></div>}
                {visible.map((c) => <div key={c.id} role="cell" className={c.mono ? "dt-cell mono" : "dt-cell"} data-wrap={c.wrap || undefined}>{c.render ? c.render(r) : c.value(r)}</div>)}
              </div>
            );
          })}
        </div>
        {shown.length === 0 && <p className="empty dt-empty">{t("dt.empty")}</p>}
      </div>
    </div>
  );
}
