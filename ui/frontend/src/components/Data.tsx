// Piezas de datos reutilizables (ADR 0009): copiar con un clic, tiempos legibles y estados con texto.
import { useContext, useEffect, useRef, useState } from "react";
import { CoreContext } from "../app/activity";
import { useLang, useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";
import { Icon } from "./Icon";
import { Badge, type Tone } from "./Page";

// Copia IP, MAC, hash, huella, comando o ruta. Confirma en el mismo lugar, sin mover nada.
export function CopyButton({ value, label }: { value: string; label: string }) {
  const t = useT();
  const core = useContext(CoreContext);
  const [done, setDone] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const copy = async () => {
    await (core ? core.copyText(value) : navigator.clipboard?.writeText(value));
    setDone(true);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setDone(false), 1400);
  };
  return (
    <span className="copy">
      <button type="button" className="quiet icon sm" aria-label={t("data.copy", { label })} title={t("data.copy", { label })} onClick={copy}>
        <Icon name={done ? "ok" : "copy"} size={14} />
      </button>
      <span role="status" className="sr">{done ? t("data.copied") : ""}</span>
    </span>
  );
}

// "hace 3 minutos" en el idioma de la app; la hora exacta queda en el título.
export function RelativeTime({ iso }: { iso: string }) {
  const lang = useLang();
  const [, tick] = useState(0);
  useEffect(() => { const id = window.setInterval(() => tick((n) => n + 1), 30_000); return () => window.clearInterval(id); }, []);
  const d = new Date(iso);
  const s = Math.round((d.getTime() - Date.now()) / 1000);
  const abs = Math.abs(s);
  const [v, unit]: [number, Intl.RelativeTimeFormatUnit] =
    abs < 60 ? [s, "second"] : abs < 3600 ? [Math.round(s / 60), "minute"] : abs < 86_400 ? [Math.round(s / 3600), "hour"] : [Math.round(s / 86_400), "day"];
  return <time dateTime={iso} title={d.toLocaleString(lang)}>{new Intl.RelativeTimeFormat(lang, { numeric: "auto" }).format(v, unit)}</time>;
}

// Fecha y hora locales con segundos en el idioma de la app; si no es una fecha válida, el texto tal cual.
export function formatDateTime(iso: string, lang: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString(lang, { dateStyle: "medium", timeStyle: "medium" });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${Math.round(ms)} ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m} min ${s % 60} s` : `${m} min`;
  const h = Math.floor(m / 60);
  return m % 60 ? `${h} h ${m % 60} min` : `${h} h`;
}
export const Duration = ({ ms }: { ms: number }) => <span className="mono">{formatDuration(ms)}</span>;

// Estado con ícono y texto. "run" es en curso.
export function StatusPill({ tone, label }: { tone: Tone | "run"; label: string }) {
  if (tone === "run") return <span className="badge" data-tone="info"><Icon name="loader" size={12} />{label}</span>;
  return <Badge tone={tone}>{label}</Badge>;
}

// Severidad syslog 0-7 con número y nombre.
export function SeverityBadge({ sev }: { sev: number }) {
  const t = useT();
  const tone: Tone = sev <= 3 ? "bad" : sev === 4 ? "warn" : sev === 5 ? "info" : "";
  return <Badge tone={tone}>{`${sev} · ${t(`sev.${Math.max(0, Math.min(7, sev))}` as Key)}`}</Badge>;
}
