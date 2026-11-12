// Patrones de página del ADR 0009 §4: Page, Section, Tabs, ResultPanel (+ useResult), EmptyState y Badge.
// Un módulo arma su vista con estas piezas; así los 30 se leen igual.
import { useCallback, useId, useRef, useState, type ReactNode } from "react";
import { Icon, type IconName } from "./Icon";
import { Notice, errorText } from "./Field";

export function Page({ title, description, actions, tabs, children }: { title: string; description?: ReactNode; actions?: ReactNode; tabs?: ReactNode; children?: ReactNode }) {
  const h = useId();
  const d = useId();
  return (
    <section className="page" aria-labelledby={h} aria-describedby={description ? d : undefined}>
      <header className="page-head">
        <div>
          <h2 id={h}>{title}</h2>
          {description && <p id={d} className="desc">{description}</p>}
        </div>
        {actions && <div className="page-actions">{actions}</div>}
      </header>
      {tabs}
      {children}
    </section>
  );
}

export function Section({ title, description, children }: { title: string; description?: ReactNode; children?: ReactNode }) {
  const h = useId();
  return (
    <section className="section" aria-labelledby={h}>
      <h3 id={h}>{title}</h3>
      {description && <p className="desc">{description}</p>}
      {children}
    </section>
  );
}

// Pestañas de subherramientas: foco itinerante y activación con flechas (WAI-ARIA tabs).
export function Tabs<T extends string>({ label, value, onChange, tabs }: { label: string; value: T; onChange: (v: T) => void; tabs: [T, string][] }) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const move = (i: number) => {
    const n = (i + tabs.length) % tabs.length;
    onChange(tabs[n][0]);
    refs.current[n]?.focus();
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map(([v, l], i) => (
        <button key={v} ref={(el) => { refs.current[i] = el; }} role="tab" aria-selected={v === value} tabIndex={v === value ? 0 : -1}
          onClick={() => onChange(v)}
          onKeyDown={(e) => {
            if (e.key === "ArrowRight") { e.preventDefault(); move(i + 1); }
            else if (e.key === "ArrowLeft") { e.preventDefault(); move(i - 1); }
            else if (e.key === "Home") { e.preventDefault(); move(0); }
            else if (e.key === "End") { e.preventDefault(); move(tabs.length - 1); }
          }}>{l}</button>
      ))}
    </div>
  );
}

// Una llamada al núcleo con su estado: ocupado, último resultado y error legible. Reemplaza los useReport de cada módulo.
export function useResult<T>() {
  const [s, setS] = useState<{ busy: boolean; data: T | null; error: string }>({ busy: false, data: null, error: "" });
  const seq = useRef(0);
  const run = useCallback(async (f: () => Promise<T>) => {
    const n = ++seq.current; // solo cuenta la última ejecución
    setS({ busy: true, data: null, error: "" });
    try {
      const data = await f();
      if (n === seq.current) setS({ busy: false, data, error: "" });
    } catch (e) {
      if (n === seq.current) setS({ busy: false, data: null, error: errorText(e) });
    }
  }, []);
  const reset = useCallback(() => { seq.current++; setS({ busy: false, data: null, error: "" }); }, []);
  return { ...s, run, reset };
}

export type Tone = "ok" | "bad" | "warn" | "info" | "";
const toneIcon: Record<Exclude<Tone, "">, IconName> = { ok: "ok", bad: "error", warn: "alert", info: "info" };

export function Badge({ tone = "", children }: { tone?: Tone; children: ReactNode }) {
  return <span className="badge" data-tone={tone || undefined}>{tone && <Icon name={toneIcon[tone]} size={12} />}{children}</span>;
}

// pad: envuelve el contenido con el relleno del panel (texto, tablas sueltas); sin pad, el contenido ocupa el cuerpo (terminal, tabla plana).
export function ResultPanel({ title, status, meta, actions, error, pad, children }: { title: string; status?: { tone: Tone; label: string }; meta?: ReactNode; actions?: ReactNode; error?: string; pad?: boolean; children?: ReactNode }) {
  const h = useId();
  return (
    <section className="panel flush result" aria-labelledby={h}>
      <header className="panel-head">
        <h3 id={h}>{title}</h3>
        {status && <Badge tone={status.tone}>{status.label}</Badge>}
        {meta && <span className="meta">{meta}</span>}
        {actions && <div className="panel-actions">{actions}</div>}
      </header>
      {error ? <div className="panel-body"><Notice kind="error">{error}</Notice></div> : pad ? <div className="panel-body">{children}</div> : children}
    </section>
  );
}

export function EmptyState({ icon = "info", title, children, action }: { icon?: IconName; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state">
      <Icon name={icon} />
      <strong>{title}</strong>
      {children && <span>{children}</span>}
      {action}
    </div>
  );
}

// Error de una vista: qué pasó y la acción siguiente (reintentar, abrir la bóveda, revisar el núcleo…).
export function ErrorState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty-state error-state" role="alert">
      <Icon name="error" />
      <strong>{title}</strong>
      {children && <span>{children}</span>}
      {action}
    </div>
  );
}
