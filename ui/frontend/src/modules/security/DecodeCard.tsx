import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { TextArea } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { PkiReportData } from "./api";
import { CertChain } from "./SecCards";
import { Outcome, probe, Raw, type Probe } from "./shared";

export function DecodeCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const r = useResult<Probe<PkiReportData>>();
  return (
    <>
      <Section title={t("security.decode")}>
        <TextArea label={t("security.decode.input")} value={text} onChange={setText} />
        <div className="actions"><button disabled={!text || r.busy} aria-busy={r.busy} onClick={() => r.run(() => probe(core.secPkiDecodeReport, core.secPkiDecode, text))}>{t("security.decode.cert")}</button></div>
      </Section>
      <Outcome r={r} bare>{r.data && <CertChain text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}
