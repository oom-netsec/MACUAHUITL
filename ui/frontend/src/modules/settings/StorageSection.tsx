import { useCallback, useEffect, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice, PathField, Select, errorText } from "../../components/Field";
import { CopyButton } from "../../components/Data";
import { RANGES, emptyForm, validateOpts, type NumKey, type SyslogFormat } from "../../components/ingest/ingestOpts";
import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { CorePrefs, CorePrefsState } from "./api";

// Motivos estables del núcleo (internal/service/prefs/outputs.go): cada uno tiene su explicación traducida.
const REASONS = ["relativa", "punto_punto", "no_existe", "ilegible", "no_directorio", "otro_dueno", "reservada", "permisos", "ancestro_inseguro", "no_escribible"];
const FORMATS: SyslogFormat[] = ["texto", "crudo", "jsonl"];
const NUMS = ["rotateMb", "rotateMinutes", "maxFiles"] as const;

/** Código del rechazo y, si trae la orden `chmod 700 <ruta>`, la ruta (vacía si no). */
export function parseOutputsError(msg: string): { code: string; path: string } | null {
  const m = /^prefs\.outputs\.([a-z_]+):/.exec(msg);
  if (!m) return null;
  // Sin trim: una carpeta que termina en espacio es otra carpeta.
  return { code: m[1], path: /chmod 700 (\S.*)$/.exec(msg)?.[1] ?? "" };
}
// La ruta va entre comillas solo si lo necesita, para que la orden se pueda pegar tal cual.
const shellQuote = (p: string) => (/^[\w@%+=:,./-]+$/.test(p) ? p : `'${p.replaceAll("'", "'\\''")}'`);

type Form = { outputsDir: string; rotateMb: string; rotateMinutes: string; maxFiles: string; format: CorePrefs["format"] };
type SaveErr = { msg: string; parsed: ReturnType<typeof parseOutputsError> };
const toForm = (s: CorePrefsState): Form => ({ outputsDir: s.outputsDir, rotateMb: s.rotateMb ? String(s.rotateMb) : "", rotateMinutes: s.rotateMin ? String(s.rotateMin) : "", maxFiles: s.maxFiles ? String(s.maxFiles) : "", format: s.format });
const num = (v: string) => (v.trim() ? Number(v.trim()) : 0);

// Ajustes → Almacenamiento: carpeta de salidas y defaults de archivo de syslog, traps y flujos (fase 29e). Guardar reemplaza todo: vacío es el de fábrica.
export function StorageSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const lang = useLang();
  const [state, setState] = useState<CorePrefsState | null>(null);
  const [form, setForm] = useState<Form>({ outputsDir: "", rotateMb: "", rotateMinutes: "", maxFiles: "", format: "" });
  const [loadErr, setLoadErr] = useState("");
  const [saveErr, setSaveErr] = useState<SaveErr | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => core.getCorePrefs().then((s) => { setState(s); setForm(toForm(s)); }, (e) => setLoadErr(errorText(e))), [core]);
  useEffect(() => { void load(); }, [load]);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => { setForm((f) => ({ ...f, [k]: v })); setSaved(false); };
  const errs = validateOpts({ ...emptyForm, rotateMb: form.rotateMb, rotateMinutes: form.rotateMinutes, maxFiles: form.maxFiles }, true);
  const errText = (k: NumKey) => (errs[k] ? t(errs[k] === "int" ? "syslog.err.int" : "syslog.err.range", { lo: RANGES[k].lo, hi: RANGES[k].hi }) : undefined);

  const save = async () => {
    if (Object.keys(errs).length) return;
    setBusy(true); setSaveErr(null); setSaved(false);
    try {
      const s = await core.setCorePrefs({ outputsDir: form.outputsDir.trim(), rotateMb: num(form.rotateMb), rotateMin: num(form.rotateMinutes), maxFiles: num(form.maxFiles), format: form.format });
      setState(s); setForm(toForm(s)); setSaved(true);
    } catch (e) {
      const msg = errorText(e);
      setSaveErr({ msg, parsed: parseOutputsError(msg) });
    } finally { setBusy(false); }
  };

  if (loadErr) return <Notice kind="error">{lang === "es" ? loadErr : t("settings.storage.loadFail")}</Notice>;
  if (!state) return null;

  // La carpeta guardada ya no cumple y rige la de fábrica (el núcleo lo dice en `note`, en español).
  const fellBack = !!state.outputsDir && state.outputsDirEffective !== state.outputsDir;
  const noteText = lang === "es" && state.note ? state.note : fellBack ? t("settings.storage.noteFallback", { path: state.outputsDir }) : t("settings.storage.noteMoved");
  const chmod = saveErr?.parsed?.code === "permisos" ? `chmod 700 ${shellQuote(saveErr.parsed.path || form.outputsDir.trim())}` : "";

  // Los rechazos del núcleo por la carpeta van bajo su campo; el resto (p. ej. fallo al guardar) junto a Guardar.
  const parsedErr = saveErr?.parsed;
  const dirErr = parsedErr && (
    <div role="alert">
      {t(REASONS.includes(parsedErr.code) ? (`settings.storage.err.${parsedErr.code}` as Key) : "settings.storage.err.other")}
      {chmod && <div className="storage-cmd"><code>{chmod}</code><CopyButton value={chmod} label={t("settings.storage.chmod")} /></div>}
    </div>
  );

  return (
    <div className="storage">
      <h4>{t("settings.storage.outputs")}</h4>
      <p className="hint">{t("settings.storage.outputs.what")}</p>
      <dl className="storage-dirs">
        <dt>{t("settings.storage.effective")}</dt><dd><code>{state.outputsDirEffective}</code></dd>
        <dt>{t("settings.storage.default")}</dt><dd><code>{state.outputsDirDefault}</code></dd>
      </dl>
      <PathField label={t("settings.storage.folder")} hint={t("settings.storage.folder.hint", { path: state.outputsDirDefault })} value={form.outputsDir} onChange={(v) => set("outputsDir", v)} error={dirErr}
        pick={() => core.pickPath({ title: t("settings.storage.folder"), directory: true })} />
      <div className="actions">
        <button type="button" disabled={!form.outputsDir} onClick={() => set("outputsDir", "")}>{t("settings.storage.factory")}</button>
      </div>
      <p className="hint">{t("settings.storage.rules")}</p>
      <p className="hint">{t("settings.storage.newOnly")}</p>

      <fieldset className="storage-group">
        <legend>{t("settings.storage.defaults")}</legend>
        <p className="hint">{t("settings.storage.defaults.what")}</p>
        <div className="grid-2">
          {NUMS.map((k) => {
            const def = RANGES[k].def || t("syslog.opt.never"); // sin rotación por tiempo de fábrica
            return (
              <Field key={k} label={t(`syslog.opt.${k}` as Key)} value={form[k]} onChange={(v) => set(k, v)} mono inputMode="numeric" placeholder={def} error={errText(k)}
                hint={t(k === "rotateMinutes" ? "syslog.opt.rotateMinutes.hint" : "syslog.opt.range", { def, lo: RANGES[k].lo, hi: RANGES[k].hi })} />
            );
          })}
          <Select label={t("syslog.opt.format")} value={form.format} onChange={(v) => set("format", v)} hint={t("settings.storage.format.hint")}
            options={[["", t("settings.storage.format.factory")], ...FORMATS.map((f): [CorePrefs["format"], string] => [f, t(`syslog.fmtName.${f}` as Key)])]} />
        </div>
      </fieldset>

      {(!!state.note || fellBack) && <Notice kind="warn">{noteText}</Notice>}
      {saveErr && !parsedErr && <Notice kind="error">{lang === "es" ? saveErr.msg : t("settings.storage.err.save")}</Notice>}
      {saved && !saveErr && <Notice kind="ok">{t("settings.storage.saved")}</Notice>}
      <div className="actions">
        <button type="button" className="primary" disabled={busy || Object.keys(errs).length > 0} onClick={() => void save()}>{t("settings.storage.save")}</button>
      </div>
    </div>
  );
}
