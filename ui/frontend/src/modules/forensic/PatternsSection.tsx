import { useEffect, useRef, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Check, Field, Notice, errorText } from "../../components/Field";
import { Badge, ResultPanel, Section } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import type { PatternsReport } from "./api";
import { FirstRun, Intro, SourcePicker, Warnings, emptySource, runKbd, toSource, type SourceState } from "./shared";

// Con el modo en vivo se relee a lo más esto del final de la captura.
const LIVE_KIB = 4096;
// Patrones dibujados de golpe: los más repetidos van primero; el resto se pide con «Mostrar más».
const SHOW_STEP = 100;

// Syslog inteligente: agrupa por patrón (números, interfaces y direcciones normalizados), cuenta y marca ráfagas.
// refreshMs: cada cuánto se vuelve a leer la captura del receptor syslog cuando se pide «en vivo».
export function PatternsSection({ core, refreshMs = 10_000 }: { core: CoreAPI; refreshMs?: number }) {
  const t = useT();
  const [src, setSrc] = useState<SourceState>(emptySource);
  const [burst, setBurst] = useState("5");
  const [win, setWin] = useState("60");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [rep, setRep] = useState<PatternsReport | null>(null);
  const [live, setLive] = useState(false);
  const [shown, setShown] = useState(SHOW_STEP);
  const source = toSource(src);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  // Una lectura a la vez: en vivo, el tic que cae con otra en curso se salta (si no, se apilarían).
  const inflight = useRef(false);
  // En vivo se relee solo el final de la captura: lo reciente, sin volver a analizar 32 MiB cada vuelta.
  const liveOn = live && src.kind === "capture";
  const run = async () => {
    if (!source || inflight.current) return;
    inflight.current = true;
    setErr(""); setBusy(true);
    try { const r = await core.forensicPatterns(liveOn ? { ...source, max_kib: LIVE_KIB } : source, Number(burst) || 0, Number(win) || 0); if (alive.current) setRep(r); } catch (e) { if (alive.current) { setRep(null); setErr(errorText(e)); } } finally { inflight.current = false; if (alive.current) setBusy(false); }
  };
  // En vivo = releer la captura que va guardando el receptor syslog; no abre ninguna escucha por su cuenta.
  const runRef = useRef(run);
  runRef.current = run;
  useEffect(() => {
    if (!liveOn) return;
    const id = setInterval(() => { void runRef.current(); }, refreshMs);
    return () => clearInterval(id);
  }, [liveOn, refreshMs]);
  return (
    <>
      <Intro text={t("forensic.pat.intro")} />
      <Section title={t("forensic.section.source")}>
        <SourcePicker value={src} onChange={setSrc} />
        {src.kind === "capture" && <Check label={t("forensic.pat.live", { n: Math.round(refreshMs / 1000) })} checked={live} onChange={setLive} />}
      </Section>
      <Section title={t("forensic.section.thresholds")}>
        <div className="field-row">
          <Field label={t("forensic.pat.burst")} type="number" value={burst} onChange={setBurst} w="sm" />
          <Field label={t("forensic.pat.win")} type="number" value={win} onChange={setWin} w="sm" />
        </div>
      </Section>
      <div className="actions"><button className="primary" disabled={!source || busy} aria-busy={busy} onClick={run}>{t("forensic.pat.btn")}{runKbd}</button></div>
      {err && <Notice kind="error">{err}</Notice>}
      {!rep && !err && <FirstRun what="forensic.empty.patterns" />}
      {rep && (
        <>
          <p className="meta">{t("forensic.pat.summary", { n: rep.entries, p: rep.patterns.length, src: rep.source })}</p>
          <Warnings list={rep.warnings} />
          {rep.patterns.length > 0 && (
            <ResultPanel title={t("forensic.sec.patterns")}>
              <div className="panel-body forensic-patterns">
                {rep.patterns.slice(0, shown).map((p, i) => {
                  const kb = p.mnemonic ? rep.kb?.[p.mnemonic] : undefined;
                  return (
                    <details key={i} className="finding" aria-label={t("forensic.pat.aria", { n: i + 1 })}>
                      <summary>
                        {p.unstable && <Badge tone="bad">{t("forensic.pat.unstable")}</Badge>}
                        {!p.unstable && p.burst && <Badge tone="warn">{t("forensic.pat.burstTag")}</Badge>}
                        {t("forensic.pat.count", { n: p.count })} <code>{p.pattern}</code>
                      </summary>
                      <ul className="notes">
                        {p.peak > 0 && <li>{t("forensic.pat.peak", { peak: p.peak, ep: p.episodes })}</li>}
                        {p.first && <li>{t("forensic.pat.range", { a: p.first ?? "", b: p.last ?? "" })}</li>}
                        {p.host_count > 0 && <li>{t("forensic.pat.hosts", { n: p.host_count, list: p.hosts?.join(", ") ?? "" })}</li>}
                        <li>{t("forensic.pat.example")} <Terminal text={p.example} /></li>
                        {kb && <li>{t("forensic.pat.kb")} {kb.meaning} <strong>{t("forensic.card.action")}</strong> {kb.action} {t("forensic.pat.verify")} {kb.verify.map((c) => <code key={c}>{c}; </code>)}</li>}
                      </ul>
                    </details>
                  );
                })}
                {rep.patterns.length > shown && (
                  <button className="sm" onClick={() => setShown((n) => n + SHOW_STEP)}>{t("forensic.pat.more", { n: rep.patterns.length - shown })}</button>
                )}
              </div>
            </ResultPanel>
          )}
        </>
      )}
    </>
  );
}
