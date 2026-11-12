import { useCallback, useId } from "react";
import { Check, Field, Select } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { vocab } from "../../lib/vocab";
import type { Key } from "../../lib/i18n/es";
import type { SnippetField } from "./api";
import { problemOf } from "./form";

// Texto traducido si la clave existe; si no, el que manda el núcleo (en español). t devuelve la clave cuando falta.
export function useTx() {
  const t = useT();
  return useCallback((key: string, fallback: string, vars?: Record<string, string | number>) => { const r = t(key as Key, vars); return r === key ? fallback : r; }, [t]);
}

// Un renderer por tipo de campo (docs/plans/contratos-front.md §6). `error` es el del núcleo; el del cliente solo ayuda.
export function FieldInput({ tid, f, value, onChange, error }: { tid: string; f: SnippetField; value: string; onChange: (v: string) => void; error?: string }) {
  const t = useT();
  const tx = useTx();
  const uid = useId();
  const base = `snippet.${tid}.field.${f.name}`;
  const label = tx(base, f.label) + (f.required ? " *" : "");
  const help = f.help ? tx(`${base}.help`, f.help) : undefined;
  const p = problemOf(f, value);
  const err = error ?? (p ? t(p.key, p.vars) : undefined);
  switch (f.type) {
    case "bool": {
      const ids = [help && `${uid}-h`, error && `${uid}-e`].filter(Boolean).join(" ") || undefined;
      return (
        <div className="snippet-bool">
          <Check label={label} checked={value === "true"} onChange={(c) => onChange(c ? "true" : "")} describedBy={ids} />
          {help && <p id={`${uid}-h`} className="hint">{help}</p>}
          {error && <p id={`${uid}-e`} className="field-error">{error}</p>}
        </div>
      );
    }
    case "choice": {
      const opts: [string, string][] = (f.choices ?? []).map((c) => [c, vocab(t, "choice", c)]);
      return <Select label={label} hint={help} error={err} required={f.required} value={value} onChange={onChange} w="md" options={f.required ? opts : [["", t("snippets.dontTouch")], ...opts]}
        placeholder={f.required && !f.defaultValue ? t("snippets.pick") : undefined} />;
    }
    case "int": case "decimal": case "vlan_id":
      return <Field label={label} hint={help} error={err} required={f.required} value={value} onChange={onChange} w="md" mono inputMode={f.type === "decimal" ? "decimal" : "numeric"} />;
    case "ipv4": case "ipv4_mask": case "interface":
      return <Field label={label} hint={help} error={err} required={f.required} value={value} onChange={onChange} w="md" mono />;
    case "interfaces":
      return <Field label={label} hint={help ?? t("snippets.rangeHint")} error={err} required={f.required} value={value} onChange={onChange} w="full" mono />;
    case "secret":
      return <Field label={label} hint={help} error={err} required={f.required} type="password" autoComplete="off" value={value} onChange={onChange} w="md" />;
    default:
      return <Field label={label} hint={help} error={err} required={f.required} value={value} onChange={onChange} w="lg" />;
  }
}
