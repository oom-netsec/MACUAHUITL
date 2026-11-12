import { useT } from "../../lib/i18n";
import type { CalcResult } from "./api";
import { subnetFacts, vlsmFacts } from "./bars";

// Barras de reparto de Subred y VLSM. Cada una tiene su equivalente en texto: la leyenda (subred) o el texto de
// cada franja junto con la tabla del resultado (VLSM).

interface Seg { key: string; name: string; detail: string; frac: number; tone: number | "free" }

const pct = (f: number) => { const s = (f * 100).toFixed(1); return s.endsWith(".0") ? s.slice(0, -2) : s; };
const v4 = (a: string) => { const p = a.split("/")[0].split("."); return p.length === 4 ? p.reduce((n, o) => n * 256 + Number(o), 0) : NaN; };

function Bar({ segs, label }: { segs: Seg[]; label?: string }) {
  // Sin label la barra es decorativa (la leyenda visible lleva los nombres): las franjas angostas no llevan texto.
  // Con leyenda visible (sin label) la barra es decorativa; si no, cada franja lleva su texto.
  return (
    <ol className="seg-bar" aria-hidden={label ? undefined : true} aria-label={label}>
      {segs.map((s) => (
        <li key={s.key} className="seg" data-tone={s.tone} style={{ flexBasis: `${pct(s.frac)}%` }} title={`${s.name} ${s.detail}`}>
          {label && <span className="seg-name">{s.name}</span>}
          <span className="sr">{s.detail}</span>
        </li>
      ))}
    </ol>
  );
}

function SubnetBar({ r }: { r: CalcResult }) {
  const t = useT();
  const f = subnetFacts(r);
  if (!f) return null;
  const range = f.first === f.last ? f.first : t("calc.bar.range", { a: f.first, b: f.last });
  const rows = f.broadcast
    ? [
      { key: "net", name: t("calc.bar.network"), at: f.network, n: 1, frac: 1 / f.total, tone: 0 },
      { key: "use", name: t("calc.bar.usable"), at: range, n: f.usable, frac: f.usable / f.total, tone: 1 },
      { key: "bc", name: t("calc.bar.broadcast"), at: f.broadcast, n: 1, frac: 1 / f.total, tone: 2 },
    ]
    : [{ key: "use", name: t("calc.bar.usable"), at: range, n: f.usable, frac: 1, tone: 1 }];
  // Red y broadcast son una dirección cada uno: se ensanchan hasta un mínimo para que se vean; la leyenda da las cifras reales.
  const ends = rows.map((x) => (x.key === "use" ? 0 : Math.max(x.frac, 0.03)));
  const rest = 1 - ends.reduce((a, b) => a + b, 0);
  const segs: Seg[] = rows.map((x, i) => ({ key: x.key, name: x.name, detail: x.at, frac: x.key === "use" ? rest : ends[i], tone: x.tone }));
  return (
    <div className="panel-body seg-wrap">
      <Bar segs={segs} />
      <ul className="seg-legend" aria-label={t("calc.bar.subnetLabel", { prefix: f.title })}>
        {rows.map((x) => <li key={x.key} data-tone={x.tone}>{`${x.name}: ${x.at} · ${t("calc.bar.addrs", { n: x.key === "use" ? (f.usableRaw === "1" ? 1 : f.usableRaw) : x.n })} (${pct(x.frac)} %)`}</li>)}
      </ul>
      {f.broadcast && <p className="meta">{t("calc.bar.note")}</p>}
    </div>
  );
}

function VlsmBar({ r }: { r: CalcResult }) {
  const t = useT();
  const f = vlsmFacts(r);
  if (!f) return null;
  const frac = (prefix: string) => Math.pow(2, f.parentLen - Number(prefix.split("/")[1]));
  const items = [
    ...f.allocations.map((a, i) => ({ ...a, tone: (i % 8) as number | "free" })),
    ...f.free.map((p) => ({ name: t("calc.bar.free"), prefix: p, tone: "free" as number | "free" })),
  ].filter((x) => x.prefix.includes("/"));
  if (!items.length) return null;
  if (items.every((x) => !Number.isNaN(v4(x.prefix)))) items.sort((a, b) => v4(a.prefix) - v4(b.prefix)); // por dirección
  const segs: Seg[] = items.map((x, i) => ({ key: String(i), name: x.name, detail: `${x.prefix} · ${pct(frac(x.prefix))} %`, frac: frac(x.prefix), tone: x.tone }));
  return <div className="panel-body seg-wrap"><Bar segs={segs} label={t("calc.bar.vlsmLabel", { parent: f.parent })} /></div>;
}

export function Bars({ kind, r }: { kind: string; r: CalcResult }) {
  return kind === "subnet" ? <SubnetBar r={r} /> : kind === "vlsm" ? <VlsmBar r={r} /> : null;
}
