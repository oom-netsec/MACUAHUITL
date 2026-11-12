// Diferencias de configuración (ADR 0009): unificada o lado a lado, con resaltado IOS, plegado de lo que
// no cambió y salto entre cambios. El diff es de Myers: O((N+M)·D), rápido con configs grandes y pocos cambios.
import { useId, useMemo, useRef, useState } from "react";
import { useT } from "../lib/i18n";
import { Hl } from "./Terminal";
import { Segmented } from "./Segmented";
import { Notice } from "./Field";

export interface DiffLine { op: " " | "-" | "+"; text: string; a?: number; b?: number }

// Con más de maxD cambios el camino exacto cuesta demasiado: el tramo distinto sale entero como quitado y luego agregado (coarse).
export function diffLines(a: string[], b: string[], maxD = 2000): DiffLine[] & { coarse?: boolean } {
  // Lo igual al principio y al final no entra a Myers: en configuraciones es casi todo.
  let pre = 0;
  while (pre < a.length && pre < b.length && a[pre] === b[pre]) pre++;
  let suf = 0;
  while (suf < a.length - pre && suf < b.length - pre && a[a.length - 1 - suf] === b[b.length - 1 - suf]) suf++;
  const A = a.slice(pre, a.length - suf), B = b.slice(pre, b.length - suf);
  const same = (i: number, j: number): DiffLine => ({ op: " ", text: a[i], a: i + 1, b: j + 1 });
  const head = a.slice(0, pre).map((_, i) => same(i, i));
  const tail = a.slice(a.length - suf).map((_, i) => same(a.length - suf + i, b.length - suf + i));
  const shift = (l: DiffLine): DiffLine => ({ ...l, a: l.a && l.a + pre, b: l.b && l.b + pre });
  const n = A.length, m = B.length, max = Math.min(n + m, maxD), off = max + 1;
  const v = new Int32Array(2 * max + 3);
  const trace: Int32Array[] = [];
  let found = n + m === 0;
  outer: for (let d = 0; d <= max && !found; d++) {
    trace.push(v.slice());
    for (let k = -d; k <= d; k += 2) {
      let x = k === -d || (k !== d && v[off + k - 1] < v[off + k + 1]) ? v[off + k + 1] : v[off + k - 1] + 1;
      let y = x - k;
      while (x < n && y < m && A[x] === B[y]) { x++; y++; }
      v[off + k] = x;
      if (x >= n && y >= m) { found = true; break outer; }
    }
  }
  if (!found) {
    const res: DiffLine[] & { coarse?: boolean } = [...head, ...A.map((text, i) => ({ op: "-" as const, text, a: pre + i + 1 })), ...B.map((text, j) => ({ op: "+" as const, text, b: pre + j + 1 })), ...tail];
    res.coarse = true;
    return res;
  }
  // Recorrido hacia atrás del camino más corto.
  const out: DiffLine[] = [];
  let x = n, y = m;
  for (let d = trace.length - 1; d >= 0 && (x > 0 || y > 0); d--) {
    const vd = trace[d], k = x - y;
    const prevK = k === -d || (k !== d && vd[off + k - 1] < vd[off + k + 1]) ? k + 1 : k - 1;
    const px = vd[off + prevK], py = px - prevK;
    while (x > px && y > py) { out.push({ op: " ", text: A[x - 1], a: x, b: y }); x--; y--; }
    if (d > 0) {
      if (x === px) out.push({ op: "+", text: B[y - 1], b: y });
      else out.push({ op: "-", text: A[x - 1], a: x });
    }
    x = px; y = py;
  }
  out.reverse();
  // Dentro de cada bloque de cambio, primero lo que se quita y luego lo que se agrega.
  const res: DiffLine[] = [];
  for (let i = 0; i < out.length;) {
    if (out[i].op === " ") { res.push(out[i++]); continue; }
    const block: DiffLine[] = [];
    while (i < out.length && out[i].op !== " ") block.push(out[i++]);
    res.push(...block.filter((l) => l.op === "-"), ...block.filter((l) => l.op === "+"));
  }
  return [...head, ...res.map(shift), ...tail];
}

const CONTEXT = 3;
type Item = { kind: "line"; l: DiffLine; change?: number } | { kind: "fold"; id: number; lines: DiffLine[] };

export function DiffView({ before, after, label }: { before: string; after: string; label: string }) {
  const t = useT();
  const h = useId();
  const [mode, setMode] = useState<"unified" | "split">("unified");
  const [open, setOpen] = useState<Set<number>>(new Set());
  const [cur, setCur] = useState(-1);
  const root = useRef<HTMLDivElement>(null);
  const lines = useMemo(() => diffLines(before.split("\n"), after.split("\n")), [before, after]);
  const [seen, setSeen] = useState(lines);
  if (seen !== lines) { setSeen(lines); setOpen(new Set()); setCur(-1); } // otro diff: pliegues y posición vuelven al inicio

  const { items, changes, added, removed } = useMemo(() => {
    const items: Item[] = [];
    let changes = 0, added = 0, removed = 0, fold = 0;
    for (let i = 0; i < lines.length;) {
      if (lines[i].op !== " ") {
        changes++;
        let first = true;
        while (i < lines.length && lines[i].op !== " ") {
          if (lines[i].op === "+") added++; else removed++;
          items.push({ kind: "line", l: lines[i++], change: first ? changes : undefined });
          first = false;
        }
        continue;
      }
      let j = i;
      while (j < lines.length && lines[j].op === " ") j++;
      const run = lines.slice(i, j);
      const head = i === 0 ? 0 : CONTEXT, tail = j === lines.length ? 0 : CONTEXT;
      if (run.length > head + tail + 2) {
        run.slice(0, head).forEach((l) => items.push({ kind: "line", l }));
        items.push({ kind: "fold", id: fold++, lines: run.slice(head, run.length - tail) });
        run.slice(run.length - tail).forEach((l) => items.push({ kind: "line", l }));
      } else run.forEach((l) => items.push({ kind: "line", l }));
      i = j;
    }
    return { items, changes, added, removed };
  }, [lines]);

  const jump = (dir: 1 | -1) => {
    if (!changes) return;
    const n = cur < 0 ? (dir === 1 ? 0 : changes - 1) : (cur + dir + changes) % changes;
    setCur(n);
    root.current?.querySelector(`[data-change="${n + 1}"]`)?.scrollIntoView?.({ block: "center" });
  };
  const expanded = items.flatMap((it): Item[] => (it.kind === "fold" && open.has(it.id) ? it.lines.map((l) => ({ kind: "line", l })) : [it]));

  return (
    <section className="panel flush diff-view" aria-labelledby={h} ref={root}>
      <header className="panel-head">
        <h3 id={h}>{label}</h3>
        {changes > 0 && <span className="meta">{[t("diff.changes", { n: changes }), t("diff.added", { n: added }), t("diff.removed", { n: removed })].join(" · ")}</span>}
        <div className="panel-actions">
          <Segmented legend={t("diff.mode")} value={mode} onChange={setMode} options={[["unified", t("diff.unified")], ["split", t("diff.split")]]} />
          <button className="quiet sm" disabled={!changes} onClick={() => jump(-1)}>{t("diff.prev")}</button>
          <button className="quiet sm" disabled={!changes} onClick={() => jump(1)}>{t("diff.next")}</button>
          <span role="status" className="meta">{cur >= 0 ? t("diff.pos", { i: cur + 1, n: changes }) : ""}</span>
        </div>
      </header>
      {lines.coarse && <div className="panel-body"><Notice kind="warn">{t("diff.coarse")}</Notice></div>}
      {!changes ? <p className="empty panel-body">{t("diff.none")}</p> : mode === "unified" ? (
        <div className="diff-lines">
          {expanded.map((it, i) => it.kind === "fold" ? (
            <button key={`f${it.id}`} className="diff-fold" onClick={() => setOpen((o) => new Set(o).add(it.id))}>{t("diff.fold", { n: it.lines.length })}</button>
          ) : (
            <div key={i} className="diff-row" data-op={it.l.op} data-change={it.change}>
              <span className="ln">{it.l.a ?? ""}</span><span className="ln">{it.l.b ?? ""}</span>
              <span className="mark" aria-hidden="true">{it.l.op}</span><code><Hl text={it.l.text} /></code>
            </div>
          ))}
        </div>
      ) : <Split items={expanded} open={(id) => setOpen((o) => new Set(o).add(id))} />}
    </section>
  );
}

// Lado a lado: cada bloque de cambio empareja lo quitado con lo agregado, fila por fila.
function Split({ items, open }: { items: Item[]; open: (id: number) => void }) {
  const t = useT();
  const rows: ({ fold: number; n: number } | { l?: DiffLine; r?: DiffLine; change?: number })[] = [];
  for (let i = 0; i < items.length;) {
    const it = items[i];
    if (it.kind === "fold") { rows.push({ fold: it.id, n: it.lines.length }); i++; continue; }
    if (it.l.op === " ") { rows.push({ l: it.l, r: it.l }); i++; continue; }
    const change = it.change;
    const del: DiffLine[] = [], add: DiffLine[] = [];
    while (i < items.length && items[i].kind === "line" && (items[i] as { l: DiffLine }).l.op !== " ") {
      const l = (items[i++] as { l: DiffLine }).l;
      (l.op === "-" ? del : add).push(l);
    }
    for (let j = 0; j < Math.max(del.length, add.length); j++) rows.push({ l: del[j], r: add[j], change: j === 0 ? change : undefined });
  }
  return (
    <table className="diff-split">
      <thead><tr><th scope="col">{t("diff.before")}</th><th scope="col">{t("diff.after")}</th></tr></thead>
      <tbody>
        {rows.map((r, i) => "fold" in r ? (
          <tr key={i}><td colSpan={2}><button className="diff-fold" onClick={() => open(r.fold)}>{t("diff.fold", { n: r.n })}</button></td></tr>
        ) : (
          <tr key={i} data-change={r.change}>
            <td data-op={r.l?.op === "-" ? "-" : r.l ? " " : ""}>{r.l && <code><Hl text={r.l.text} /></code>}</td>
            <td data-op={r.r?.op === "+" ? "+" : r.r ? " " : ""}>{r.r && <code><Hl text={r.r.text} /></code>}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
