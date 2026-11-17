import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { TextArea } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { IkeReportData } from "./api";
import { IkeCards } from "./SecCards";
import { kbd, Outcome, probe, Raw, type Probe } from "./shared";

export function IkePanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const r = useResult<Probe<IkeReportData>>();
  return (
    <>
      <Section title={t("security.sec.ike")} description={t("security.ike.note")}>
        <TextArea label={t("security.ike.input")} value={text} onChange={setText} rows={14} />
        <div className="actions"><button className="primary" disabled={!text || r.busy} aria-busy={r.busy} onClick={() => r.run(() => probe(core.secIkeReport, core.secIkeDecode, text))}>{t("security.decode")}{kbd}</button></div>
      </Section>
      <Outcome r={r} bare empty={t("security.ike.empty")}>{r.data && (r.data.report ? <IkeCards report={r.data.report} /> : <Raw text={r.data.text} />)}</Outcome>
    </>
  );
}
