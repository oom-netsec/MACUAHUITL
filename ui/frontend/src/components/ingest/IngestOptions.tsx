// Opciones de los receptores (syslog, traps, flujos): contra inundación y, al guardar, rotación, nombre, retención y formato.
import { Field, Select } from "../../components/Field";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { DEFAULT_TEMPLATES, RANGES, kindKey, previewName, rangeOf, type IngestKind, type KindText, type NumKey, type OptError, type OptForm, type OptKey, type SyslogFormat } from "./ingestOpts";
import "./ingest.css";

const FORMATS: SyslogFormat[] = ["texto", "crudo", "jsonl"];

/** Errores ya traducidos por campo: los de validación en vivo y el que nombró el núcleo al iniciar. */
export type OptMessages = Partial<Record<OptKey, string>>;

export function IngestOptionsBox({ kind = "syslog", form, onChange, save, errors, open, onOpen, disabled }: {
  kind?: IngestKind; form: OptForm; onChange: (k: OptKey, v: string) => void; save: boolean; errors: OptMessages; open: boolean; onOpen: (v: boolean) => void; disabled?: boolean;
}) {
  const t = useT();
  // def: el default que se dice en la ayuda y se pone de marcador.
  const num = (k: NumKey, label: Key, def: string = rangeOf(kind, k).def, hintKey: Key = "syslog.opt.range") => (
    <Field label={t(label)} value={form[k]} onChange={(v) => onChange(k, v)} mono placeholder={def} error={errors[k]} disabled={disabled} inputMode="numeric"
      hint={t(hintKey, { def, lo: RANGES[k].lo, hi: RANGES[k].hi })} />
  );
  const burst = t("syslog.opt.burstDefault");
  const noCap = kind === "flows" && !save; // sin archivo no hay tope ni descartes
  // Tope aproximado en disco con lo escrito, o con los defaults si falta o no es válido.
  const n = (k: NumKey) => (/^\d+$/.test(form[k].trim()) ? Number(form[k]) : Number(RANGES[k].def));
  const size = (mb: number) => (mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb} MB`);
  const perSource = form.nameTemplate.includes("{origen}");
  const disk = perSource
    ? t("syslog.opt.diskOrigin", { size: size(n("rotateMb") * n("maxFiles")), open: size(n("rotateMb") * 64) })
    : t("syslog.opt.disk", { size: size(n("rotateMb") * n("maxFiles")) });
  return (
    <details className="syslog-opts" open={open}>
      <summary onClick={(e) => { e.preventDefault(); onOpen(!open); }}>{t("syslog.opts")}</summary>
      {disabled && <p className="hint">{t("syslog.locked")}</p>}
      <fieldset className="syslog-group">
        <legend>{t("syslog.opts.flood")}</legend>
        <p className="hint">{t(kindKey(kind, "opts.floodHint"))}</p>
        {noCap ? <p className="hint">{t("flows.opts.noCap")}</p> : (
          <div className="grid-2">
            {num("ratePerSource", kindKey(kind, "opt.ratePerSource"))}
            {num("burstPerSource", "syslog.opt.burstPerSource", burst)}
            {num("rateGlobal", kindKey(kind, "opt.rateGlobal"))}
            {num("burstGlobal", "syslog.opt.burstGlobal", burst)}
            {num("queueSize", "syslog.opt.queueSize")}
          </div>
        )}
      </fieldset>
      {save && (
        <fieldset className="syslog-group">
          <legend>{t("syslog.opts.files")}</legend>
          <div className="grid-2">
            {num("rotateMb", "syslog.opt.rotateMb")}
            {num("rotateMinutes", "syslog.opt.rotateMinutes", t("syslog.opt.never"), "syslog.opt.rotateMinutes.hint")}
            {num("maxFiles", "syslog.opt.maxFiles")}
          </div>
          <div className="grid-2">
            <Select label={t("syslog.opt.format")} value={form.format} onChange={(v) => onChange("format", v)} error={errors.format} disabled={disabled} hint={t(kindKey(kind, `fmt.${form.format}` as KindText))}
              options={FORMATS.map((f): [SyslogFormat, string] => [f, t(`syslog.fmtName.${f}`)])} />
            <div>
              <Field label={t("syslog.opt.nameTemplate")} value={form.nameTemplate} onChange={(v) => onChange("nameTemplate", v)} mono placeholder={DEFAULT_TEMPLATES[kind]} disabled={disabled}
                error={errors.nameTemplate} hint={t(kindKey(kind, "opt.tokens"))} />
              {!errors.nameTemplate && <p className="hint">{t("syslog.opt.example", { name: previewName(form.nameTemplate, form.format, new Date(), kind) })}</p>}
            </div>
          </div>
          <p className="hint">{disk}</p>
        </fieldset>
      )}
    </details>
  );
}

/** Texto del error de validación de un campo. */
export const optErrorText = (t: (k: Key, v?: Record<string, string | number>) => string, k: OptKey, code: OptError) =>
  code === "range" && k in RANGES ? t("syslog.err.range", { lo: RANGES[k as NumKey].lo, hi: RANGES[k as NumKey].hi }) : t(`syslog.err.${code}`);
