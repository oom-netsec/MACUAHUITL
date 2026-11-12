import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { MsgEntry } from "./api";
import { FirstRun, Intro, MsgCard, runKbd } from "./shared";

// Base de conocimiento de mensajes de Cisco: mnemónico exacto o con comodín (* y ?).
export function MsgSection({ core }: { core: CoreAPI }) {
  const t = useT();
  const [q, setQ] = useState("");
  const r = useResult<MsgEntry[]>();
  return (
    <>
      <Intro text={t("forensic.msg.intro")} />
      <div className="field-row">
        <Field label={t("forensic.msg.field")} value={q} onChange={setQ} w="lg" mono />
      </div>
      <div className="actions"><button className="primary" disabled={r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.forensicMsg(q.trim()))}>{t("forensic.msg.btn")}{runKbd}</button></div>
      {r.error && <Notice kind="error">{r.error}</Notice>}
      {!r.data && !r.error && <FirstRun what="forensic.empty.msg" />}
      {r.data && (r.data.length === 0 ? <Notice kind="info">{t("forensic.msg.none")}</Notice> : r.data.map((e) => <MsgCard key={e.id} e={e} />))}
    </>
  );
}
