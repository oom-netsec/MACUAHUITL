import { StatusPill, CopyButton } from "../../components/Data";
import { ResultPanel, type Tone } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { AdhocRow } from "./api";

// Matriz equipo × comando: un estado por celda (correcto, error o vacío) y, al elegirla, su salida en la terminal.
export type Cell = "ok" | "error" | "empty";
export const cellKind = (r: AdhocRow): Cell => (!r.ok ? "error" : r.output.trim() ? "ok" : "empty");
const tone: Record<Cell, Tone> = { ok: "ok", error: "bad", empty: "warn" };
const label: Record<Cell, Key> = { ok: "adhoc.cell.ok", error: "adhoc.cell.error", empty: "adhoc.cell.empty" };
const idOf = (r: AdhocRow) => `${r.device}|${r.address}|${r.command}`;

export function AdhocMatrix({ rows, commands, picked, onPick }: { rows: AdhocRow[]; commands: string[]; picked: string; onPick: (id: string) => void }) {
  const t = useT();
  const cols = commands.length ? commands : [...new Set(rows.map((r) => r.command))];
  const devs = [...new Map(rows.map((r) => [`${r.device}|${r.address}`, r] as const)).values()];
  const cell = (d: AdhocRow, c: string) => rows.find((r) => r.device === d.device && r.address === d.address && r.command === c);
  const sel = rows.find((r) => idOf(r) === picked);
  const title = sel ? `${sel.device} · ${sel.command}` : "";
  const out = sel ? (sel.ok ? sel.output : sel.note ?? "") : "";
  return (
    <>
      <div className="table-wrap flat adhoc-matrix">
        <table aria-label={t("adhoc.matrix.label")}>
          <thead><tr><th scope="col">{t("adhoc.col.device")}</th>{cols.map((c) => <th key={c} scope="col" className="mono">{c}</th>)}</tr></thead>
          <tbody>
            {devs.map((d) => (
              <tr key={`${d.device}|${d.address}`}>
                <th scope="row"><span className="mono">{d.device}</span> <span className="meta mono">{d.address}</span></th>
                {cols.map((c) => {
                  const r = cell(d, c);
                  if (!r) return <td key={c}><span aria-label={t("adhoc.cell.none")}>—</span></td>;
                  const k = cellKind(r);
                  return (
                    <td key={c}>
                      <button className="quiet sm cell" aria-pressed={idOf(r) === picked} aria-label={`${r.device} ${r.command}: ${t(label[k])}`} onClick={() => onPick(idOf(r))}>
                        <StatusPill tone={tone[k]} label={t(label[k])} />
                      </button>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {sel ? (
        <div className="cell-out"><ResultPanel title={title} status={{ tone: tone[cellKind(sel)], label: t(label[cellKind(sel)]) }} actions={<CopyButton value={out} label={t("adhoc.cell.copy")} />}>
          <Terminal text={out} aria-label={t("adhoc.cell.output", { cell: title })} />
        </ResultPanel></div>
      ) : <p className="panel-body meta">{t("adhoc.cell.hint")}</p>}
    </>
  );
}
