import { useState } from "react";
import type { CleanResult, CoreAPI } from "../../lib/core";
import { Check, Notice, TextArea } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, useResult } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { Terminal } from "../../components/Terminal";
import { DiffView } from "../../components/DiffView";
import { useT } from "../../lib/i18n";
import "./cleaner.css";

// Limpiador: ordena el texto de un running-config y marca las huérfanas. Nunca borra en silencio:
// cada cambio sale en el informe, y las huérfanas solo se marcan.
export function CleanerView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const [sort, setSort] = useState(false);
  const [copied, setCopied] = useState(false);
  const [ran, setRan] = useState(""); // lo que se limpió: el diff no cambia si se sigue editando la entrada
  const q = useResult<CleanResult>();
  const res = q.data;
  const copy = async () => { await core.copyText(res?.output ?? ""); setCopied(true); window.setTimeout(() => setCopied(false), 1500); };

  return (
    <Page title={t("cleaner.title")} description={t("cleaner.intro")}>
      <Section title={t("cleaner.section.input")}>
        <TextArea label={t("cleaner.config")} rows={12} value={text} onChange={setText} />
        <Check label={t("cleaner.sort")} checked={sort} onChange={setSort} />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!text.trim() || q.busy} aria-busy={q.busy} onClick={() => { setRan(text); void q.run(() => core.cleanerRun(text, sort)); }}>{t("common.clear")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
      </div>
      {q.error && <Notice kind="error">{q.error}</Notice>}
      {!res && !q.error && <EmptyState icon="layers" title={t("cleaner.empty.title")}>{t("cleaner.empty")}</EmptyState>}
      {res && (
        <>
          <ResultPanel title={t("cleaner.report")}>
            <Terminal text={res.text} />
          </ResultPanel>
          <DiffView label={t("cleaner.diff")} before={ran} after={res.output} />
          {res.report.orphans.length > 0 && (
            <ResultPanel title={t("cleaner.orphans", { n: res.report.orphans.length })}>
              <div className="table-wrap cleaner-orphans">
                <table aria-label={t("cleaner.orphans", { n: res.report.orphans.length })}>
                  <thead><tr><th>{t("cleaner.col.line")}</th><th>{t("cleaner.col.text")}</th><th>{t("cleaner.col.why")}</th></tr></thead>
                  <tbody>{res.report.orphans.map((o) => <tr key={o.line}><td className="mono">{o.line}</td><td className="mono">{o.text}</td><td>{o.why}</td></tr>)}</tbody>
                </table>
              </div>
            </ResultPanel>
          )}
          <ResultPanel title={t("cleaner.result")}
            actions={<button className="quiet sm" onClick={copy}><Icon name="copy" size={14} />{t(copied ? "common.copied" : "common.copy")}</button>}>
            <Terminal text={res.output} role="log" aria-label={t("cleaner.result")} />
          </ResultPanel>
        </>
      )}
    </Page>
  );
}
