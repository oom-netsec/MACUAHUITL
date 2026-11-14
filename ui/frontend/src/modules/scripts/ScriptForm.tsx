import { useEffect, useRef, useState } from "react";
import { Field, Notice, Select, TextArea, errorText } from "../../components/Field";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { ScriptDraft, ScriptItem, ScriptPlatform, ScriptTech } from "./api";
import { fieldOfError, parseCommands, parseTags, validateScript, type FormErrors } from "./text";

export const TECHS: ScriptTech[] = ["l2", "l3", "gestion", "seguridad", "qos", "etherchannel", "wireless", "diagnostico", "otro"];
export const PLATFORMS: ScriptPlatform[] = ["ios", "ios-xe", "nx-os", "asa", "cualquiera"];

// Alta y edición de un script propio. Valida junto a cada campo (tras el primer intento de guardar) y coloca
// el error del núcleo en el campo que nombra.
export function ScriptForm({ initial, onSave, onCancel }: { initial?: ScriptItem; onSave: (d: ScriptDraft) => Promise<void>; onCancel: () => void }) {
  const t = useT();
  const [name, setName] = useState(initial?.name ?? "");
  const [tech, setTech] = useState<ScriptTech>(initial?.tech ?? "otro");
  const [platform, setPlatform] = useState<ScriptPlatform>(initial?.platform ?? "ios-xe");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [tags, setTags] = useState(initial?.tags.join(" ") ?? "");
  const [commands, setCommands] = useState(initial?.commands.join("\n") ?? "");
  const root = useRef<HTMLFormElement>(null);
  useEffect(() => { root.current?.querySelector("input")?.focus(); }, []); // el primer campo es el nombre
  const [tried, setTried] = useState(false);
  const [busy, setBusy] = useState(false);
  const [coreErr, setCoreErr] = useState<{ field: string; msg: string } | null>(null);

  const draft = { name: name.trim(), tech, platform, description, tags: parseTags(tags), commands: parseCommands(commands) };
  const local: FormErrors = tried ? validateScript(draft) : {};
  const txt = (f: "name" | "desc" | "tags" | "commands") => {
    const e = local[f];
    if (e) return t(e.k, e.n ? { n: String(e.n) } : undefined);
    return coreErr?.field === f ? coreErr.msg : undefined;
  };

  const save = async () => {
    setTried(true);
    setCoreErr(null);
    if (Object.keys(validateScript(draft)).length) return;
    setBusy(true);
    try {
      await onSave(initial ? { id: initial.id, ...draft } : draft);
    } catch (e) {
      const msg = errorText(e);
      setCoreErr({ field: fieldOfError(e), msg });
    } finally { setBusy(false); }
  };

  return (
    <form ref={root} onSubmit={(e) => { e.preventDefault(); void save(); }}>
      <Field label={t("scripts.f.name")} value={name} onChange={(v) => { setName(v); setCoreErr(null); }} error={txt("name")} w="lg" />
      <div className="field-row">
        <Select<ScriptTech> label={t("scripts.f.tech")} value={tech} onChange={setTech} w="md" options={TECHS.map((x) => [x, t(`scripts.tech.${x}` as Key)])} />
        <Select<ScriptPlatform> label={t("scripts.f.platform")} value={platform} onChange={setPlatform} w="md" options={PLATFORMS.map((x) => [x, t(`scripts.plat.${x}` as Key)])} />
      </div>
      <Field label={t("scripts.f.desc")} value={description} onChange={setDescription} error={txt("desc")} w="full" />
      <Field label={t("scripts.f.tags")} hint={t("scripts.f.tagsHint")} value={tags} onChange={setTags} error={txt("tags")} w="lg" mono />
      <TextArea label={t("scripts.f.commands")} hint={t("scripts.f.commandsHint")} value={commands} onChange={setCommands} error={txt("commands")} rows={10} mono />
      {coreErr && !coreErr.field && <Notice kind="error">{coreErr.msg}</Notice>}
      <div className="actions">
        <button type="submit" className="primary" disabled={busy} aria-busy={busy}>{t("scripts.f.save")}</button>
        <button type="button" onClick={onCancel}>{t("scripts.f.cancel")}</button>
      </div>
    </form>
  );
}
