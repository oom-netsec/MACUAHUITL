// Opciones extendidas del ping y su resultado (resumen, barrido y MTU estimada). Contrato provisional, #200.
import { Check, Field, Select } from "../../components/Field";
import { StatusPill } from "../../components/Data";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { isWindows } from "../../lib/platform";
import type { NetInterface, PingSummary, SweepPoint } from "./api";
import { mtuEstimate, sweepPoints, type PingErrors, type PingForm } from "./pingOpts";

const e = (errors: PingErrors, k: keyof PingForm, t: (k: Key) => string) => (errors[k] ? t(errors[k]!) : undefined);

export function PingOptions({ form, set, errors, active, ifaces, disabled }: {
  form: PingForm; set: (p: Partial<PingForm>) => void; errors: PingErrors; active: number; ifaces: NetInterface[]; disabled?: boolean;
}) {
  const t = useT();
  const win = isWindows();
  const ips = ifaces.flatMap((i) => i.addresses.map((a) => a.replace(/\/\d+$/, "").replace(/%.*$/, "")));
  const src: [string, string][] = [["", t("diag.ext.source.auto")],
    ...(win ? [] : ifaces.map((i) => [i.name, i.name] as [string, string])), ...[...new Set(ips)].map((a) => [a, a] as [string, string])];
  const num = (label: Key, k: keyof PingForm, w: "sm" | "md" = "sm", hint?: Key) =>
    <Field label={t(label)} hint={hint && t(hint)} value={form[k] as string} onChange={(v) => set({ [k]: v })} error={e(errors, k, t)} inputMode="decimal" w={w} />;
  const pts = sweepPoints(form);
  const hidden = Object.keys(errors).filter((k) => k !== "count").length; // los de «Paquetes» se ven fuera de la sección
  return (
    <details className="ping-ext">
      <summary>{t("diag.ext.title")}{active > 0 && <span className="meta"> · {t("diag.ext.active", { n: active })}</span>}{hidden > 0 && <span className="field-error"> · {t("diag.ext.errors", { n: hidden })}</span>}</summary>
      <fieldset disabled={disabled}>
        <div className="field-row">
          <Check label={t("diag.ext.continuous")} checked={form.continuous} onChange={(continuous) => set({ continuous })} />
          <Check label={t("diag.ext.df")} checked={form.df && !(win && form.family === "6")} disabled={win && form.family === "6"} onChange={(df) => set({ df })} />
        </div>
        <div className="field-row">
          {num("diag.ext.ttl", "ttl")}
          {num("diag.ext.timeout", "timeout")}
          {num("diag.ext.duration", "duration")}
          {num("diag.ext.size", "size")}
          {!win && num("diag.ext.interval", "interval")}
          {!win && num("diag.ext.dscp", "dscp", "sm", "diag.ext.dscp.hint")}
          <Select label={t("diag.ext.family")} value={form.family} onChange={(family) => set({ family })} w="md"
            options={[["", t("diag.ext.family.auto")], ["4", "IPv4"], ["6", "IPv6"]]} />
        </div>
        <div className="field-row">
          <Select label={t("diag.ext.source")} value={form.sourceSel} onChange={(sourceSel) => set({ sourceSel })} options={src} error={e(errors, "sourceSel", t)} w="md" keepUnknown />
          <Field label={t("diag.ext.sourceIP")} value={form.sourceIP} onChange={(sourceIP) => set({ sourceIP })} error={e(errors, "sourceIP", t)} w="md" mono />
        </div>
        <fieldset className="ping-sweep">
          <legend>{t("diag.ext.sweep")}</legend>
          <div className="field-row">
            {num("diag.ext.sweepStart", "sweepStart")}
            {num("diag.ext.sweepEnd", "sweepEnd")}
            {num("diag.ext.sweepStep", "sweepStep")}
          </div>
          {pts > 0 && <p className="hint" role="status">{t("diag.ext.sweepPoints", { n: pts })}</p>}
          <p className="hint">{t("diag.ext.sweepHint")}</p>
        </fieldset>
      </fieldset>
    </details>
  );
}

const n2 = (n: number) => String(Math.round(n * 100) / 100);

export function PingSummaryCard({ s }: { s: PingSummary }) {
  const t = useT();
  return (
    <section aria-label={t("diag.sum.title")}>
      <dl className="stats">
        <div><dt>{t("diag.sum.sent")}</dt><dd>{s.sent}</dd></div>
        <div><dt>{t("diag.sum.received")}</dt><dd>{s.received}</dd></div>
        <div><dt>{t("diag.stat.loss")}</dt><dd>{n2(s.lossPct)} %</dd></div>
        <div><dt>{t("diag.stat.min")}</dt><dd>{n2(s.minMs)} ms</dd></div>
        <div><dt>{t("diag.stat.avg")}</dt><dd>{n2(s.avgMs)} ms</dd></div>
        <div><dt>{t("diag.stat.max")}</dt><dd>{n2(s.maxMs)} ms</dd></div>
        <div><dt>{t("diag.sum.mdev")}</dt><dd>{n2(s.mdevMs)} ms</dd></div>
      </dl>
    </section>
  );
}

const TONE = { ok: "ok", loss: "bad", frag: "warn" } as const;

export function SweepTable({ points, fam }: { points: SweepPoint[]; fam: "4" | "6" | "?" }) {
  const t = useT();
  const sorted = [...points].sort((a, b) => a.size - b.size);
  const mtu = fam === "?" ? null : mtuEstimate(points, fam === "6");
  const unknown = fam === "?" && mtuEstimate(points, false) !== null; // no se sabe si suma 28 o 48
  return (
    <section aria-label={t("diag.sweep.title")}>
      {unknown && <p role="status" className="meta">{t("diag.sweep.mtuUnknown")}</p>}
      {mtu && <p role="status"><strong>{t("diag.sweep.mtu", { mtu: mtu.mtu, size: mtu.size })}</strong> <span className="meta">{t("diag.sweep.mtuNote", { n: fam === "6" ? 48 : 28 })}</span></p>}
      <div className="table-wrap">
        <table aria-label={t("diag.sweep.title")}>
          <thead><tr><th scope="col">{t("diag.sweep.size")}</th><th scope="col">{t("diag.sweep.recv")}</th><th scope="col">{t("diag.sweep.result")}</th></tr></thead>
          <tbody>{sorted.map((p) => (
            <tr key={p.size} data-state={mtu?.size === p.size ? "best" : undefined}>
              <th scope="row" className="mono">{p.size}</th>
              <td>{p.received}/{p.sent}</td>
              <td><StatusPill tone={TONE[p.result]} label={t(`diag.sweep.${p.result}` as Key)} /></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </section>
  );
}
