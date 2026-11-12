import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { useT } from "../lib/i18n";
import { Terminal } from "./Terminal";
import { Icon } from "./Icon";

// Ancho del campo según lo que se escribe (ADR 0009): xs puerto, sm número, md nombre, lg host o ruta, full texto largo.
export type Width = "xs" | "sm" | "md" | "lg" | "full";

// Etiqueta + control + ayuda opcional (anunciada como descripción del control).
function Labeled({ label, hint, error, w, children }: { label: string; hint?: string; error?: string; w?: Width; children: (id: string, describedBy?: string) => ReactNode }) {
  const id = useId();
  const hintId = hint ? `${id}-h` : undefined;
  const errId = error ? `${id}-e` : undefined;
  return (
    <div className="field" data-w={w}>
      <label htmlFor={id}>{label}</label>
      {children(id, [hintId, errId].filter(Boolean).join(" ") || undefined)}
      {hint && <p id={hintId} className="hint">{hint}</p>}
      {error && <p id={errId} className="field-error">{error}</p>}
    </div>
  );
}

// mono: IP, puertos, MAC, hashes y comandos van en monoespaciada.
type FieldProps = { label: string; hint?: string; error?: string; type?: string; value: string; onChange: (v: string) => void; autoComplete?: string; w?: Width; mono?: boolean; placeholder?: string; disabled?: boolean; inputMode?: "numeric" | "decimal"; required?: boolean };

export function Field({ label, hint, error, type, value, onChange, autoComplete, w, mono, placeholder, disabled, inputMode, required }: FieldProps) {
  return (
    <Labeled label={label} hint={hint} error={error} w={w}>
      {(id, hintId) => (
        <input id={id} className={mono ? "mono" : undefined} type={type ?? "text"} value={value} placeholder={placeholder} disabled={disabled} inputMode={inputMode} autoComplete={autoComplete ?? "off"} spellCheck={false}
          aria-describedby={hintId} aria-required={required || undefined} aria-invalid={error ? true : undefined} onChange={(e) => onChange(e.target.value)} />
      )}
    </Labeled>
  );
}

// mono: configuración y comandos de equipos.
export function TextArea({ label, hint, error, value, onChange, rows = 5, readOnly, w = "full", mono }: { label: string; hint?: string; error?: string; value: string; onChange?: (v: string) => void; rows?: number; readOnly?: boolean; w?: Width; mono?: boolean }) {
  return (
    <Labeled label={label} hint={hint} error={error} w={w}>
      {(id, hintId) => (
        <textarea id={id} className={mono ? "mono" : undefined} rows={rows} value={value} spellCheck={false} readOnly={readOnly} aria-describedby={hintId} aria-invalid={error ? true : undefined}
          onChange={(e) => onChange?.(e.target.value)} />
      )}
    </Labeled>
  );
}

// Ruta escrita a mano o elegida con el diálogo nativo; cancelar el diálogo conserva lo que había.
export function PathField({ label, hint, error, value, onChange, pick }: { label: string; hint?: string; error?: string; value: string; onChange: (v: string) => void; pick: () => Promise<string> }) {
  const t = useT();
  return (
    <Labeled label={label} hint={hint} error={error}>
      {(id, hintId) => (
        <div className="path">
          <input id={id} value={value} spellCheck={false} autoComplete="off" aria-describedby={hintId} aria-invalid={error ? true : undefined} onChange={(e) => onChange(e.target.value)} />
          <button type="button" aria-label={`${t("common.browse")} ${label}`} onClick={async () => { const p = await pick(); if (p) onChange(p); }}>
            {t("common.browse")}
          </button>
        </div>
      )}
    </Labeled>
  );
}

export function Check({ label, checked, onChange, disabled, describedBy }: { label: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; describedBy?: string }) {
  const id = useId();
  return (
    <div className="check">
      <input id={id} type="checkbox" checked={checked} disabled={disabled} aria-describedby={describedBy} onChange={(e) => onChange(e.target.checked)} />
      <label htmlFor={id}>{label}</label>
    </div>
  );
}

// placeholder: opción vacía deshabilitada que se muestra mientras no se elija nada (un campo obligatorio sin valor sugerido).
export function Select<T extends string>({ label, hint, error, value, onChange, options, w, required, placeholder, disabled }: { label: string; hint?: string; error?: string; value: T; onChange: (v: T) => void; options: [T, string][]; w?: Width; required?: boolean; placeholder?: string; disabled?: boolean }) {
  return (
    <Labeled label={label} hint={hint} error={error} w={w}>
      {(id, hintId) => (
        <select id={id} value={value} disabled={disabled} aria-describedby={hintId} aria-required={required || undefined} aria-invalid={error ? true : undefined} onChange={(e) => onChange(e.target.value as T)}>
          {placeholder !== undefined && <option value="" disabled>{placeholder}</option>}
          {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      )}
    </Labeled>
  );
}

// Errores como alerta (se anuncian al instante); éxito y avisos como estado.
export function Notice({ kind, children }: { kind: "error" | "warn" | "ok" | "info"; children: ReactNode }) {
  const icon = kind === "error" ? "error" : kind === "warn" ? "alert" : kind === "ok" ? "ok" : "info";
  return <div role={kind === "error" ? "alert" : "status"} className={`notice ${kind}`}><Icon name={icon} /><div className="notice-body">{children}</div></div>;
}

// Acción destructiva en dos pasos, sin ventana modal; si no se confirma en 4 s vuelve a su estado.
export function ConfirmButton({ label, confirmLabel, onConfirm, children }: { label: string; confirmLabel: string; onConfirm: () => void; children?: ReactNode }) {
  const [armed, setArmed] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const click = () => {
    window.clearTimeout(timer.current);
    if (armed) { setArmed(false); onConfirm(); return; }
    setArmed(true);
    timer.current = window.setTimeout(() => setArmed(false), 4000);
  };
  return (
    <button type="button" className={armed ? "danger" : "quiet danger-text"} aria-label={armed ? confirmLabel : label} onClick={click}>
      {armed ? confirmLabel : children ?? label}
    </button>
  );
}

// Salida de texto con copiar y limpiar.
export function Console({ label, text, copy, onClear }: { label: string; text: string; copy: (t: string) => Promise<void>; onClear?: () => void }) {
  const t = useT();
  const [copied, setCopied] = useState(false);
  const ref = useRef<HTMLPreElement>(null);
  // Sigue la última línea salvo que se haya subido a leer.
  useEffect(() => {
    const el = ref.current;
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 48) el.scrollTop = el.scrollHeight;
  }, [text]);
  return (
    <div className="console-wrap">
      <div className="console-bar">
        <span>{label}</span>
        <button type="button" className="quiet" disabled={!text} onClick={async () => { await copy(text); setCopied(true); window.setTimeout(() => setCopied(false), 1500); }}>
          {copied ? t("common.copied") : t("common.copy")}
        </button>
        {onClear && <button type="button" className="quiet" disabled={!text} onClick={onClear}>{t("common.clear")}</button>}
      </div>
      <Terminal ref={ref} text={text} role="log" aria-label={label} />
    </div>
  );
}

export function errorText(e: unknown): string {
  const m = e instanceof Error ? e.message : String(e);
  return m.replace(/^rpc error: code = \w+ desc = /, "");
}
