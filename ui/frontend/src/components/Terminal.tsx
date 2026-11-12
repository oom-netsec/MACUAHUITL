import { memo, type ComponentProps, type CSSProperties, type ReactNode } from "react";
import { MAX_HIGHLIGHT_LINES, PALETTES, CATEGORIES, classify } from "../lib/termHighlight";
import { useTermPrefs } from "../lib/termPrefs";
import type { Key } from "../lib/i18n/es";

// Nombre traducido de cada paleta de internal/termcolor/palettes.json (el nombre del JSON queda de respaldo).
const PALETTE_KEYS: Record<string, Key> = { classic: "term.palette.classic", p1: "term.palette.p1", p3: "term.palette.p3", ibm: "term.palette.ibm", solarized: "term.palette.solarized", light: "term.palette.light", "consola-oscura": "term.palette.consolaOscura", "consola-clara": "term.palette.consolaClara",
  medianoche: "term.palette.medianoche", grafito: "term.palette.grafito", oceano: "term.palette.oceano", bosque: "term.palette.bosque", brasa: "term.palette.brasa", ciruela: "term.palette.ciruela", arena: "term.palette.arena", papel: "term.palette.papel", niebla: "term.palette.niebla", contraste: "term.palette.contraste" };
/** Nombre de la paleta en el idioma activo (el del JSON queda de respaldo). */
export const paletteName = (t: (k: Key) => string, p: { id: string; name: string }) => (p.id in PALETTE_KEYS ? t(PALETTE_KEYS[p.id]) : p.name);

// Resalta una línea sin tocar su texto. Solo construye nodos React (texto y <span>): lo
// que llega de la red nunca se interpreta como HTML.
export const Hl = memo(function Hl({ text }: { text: string }) {
  const spans = classify(text);
  if (spans.length === 0) return <>{text}</>;
  const out: ReactNode[] = [];
  let pos = 0;
  spans.forEach((s, i) => {
    if (s.start > pos) out.push(text.slice(pos, s.start));
    out.push(<span key={i} className={`t-${s.cat}`}>{text.slice(s.start, s.end)}</span>);
    pos = s.end;
  });
  if (pos < text.length) out.push(text.slice(pos));
  return <>{out}</>;
});

function Lines({ text }: { text: string }) {
  const lines = text.split("\n");
  const cut = Math.max(0, lines.length - MAX_HIGHLIGHT_LINES);
  return (
    <>
      {cut > 0 && lines.slice(0, cut).join("\n") + "\n"}
      {lines.slice(cut).map((l, i, a) => <span key={cut + i}><Hl text={l} />{i < a.length - 1 ? "\n" : ""}</span>)}
    </>
  );
}

type Props = (ComponentProps<"pre"> | ComponentProps<"ul">) & { as?: "pre" | "ul"; text?: string };

/** Terminal con paleta elegible. `pre` recibe `text`; `ul` recibe <li> con <Hl>. */
export function Terminal({ as = "pre", text, children, ...rest }: Props) {
  const { palette } = useTermPrefs();
  const p = PALETTES.find((x) => x.id === palette) ?? PALETTES[0];
  const vars = { "--t-bg": p.bg, "--t-fg": p.fg } as Record<string, string>;
  for (const c of CATEGORIES) vars[`--t-${c}`] = p[c];
  const El = as as "pre";
  return (
    <div className="term" data-palette={p.id} style={vars as CSSProperties}>
      <El {...(rest as ComponentProps<"pre">)} className="console">{text !== undefined ? <Lines text={text} /> : children}</El>
    </div>
  );
}

const SWATCH = ["prompt", "ok", "bad", "iface", "addr"] as const;

/** Muestra de una paleta: fondo, texto y cinco colores de categoría (la usan el menú «Cambiar tema» de la terminal y Ajustes). */
export function PaletteSwatch({ p }: { p: (typeof PALETTES)[number] }) {
  return (
    <span className="theme-swatch" aria-hidden="true" style={{ background: p.bg, color: p.fg } as CSSProperties}>
      {SWATCH.map((k) => <i key={k} style={{ background: p[k] }} />)}
    </span>
  );
}
