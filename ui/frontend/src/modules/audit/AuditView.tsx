import type { CoreAPI } from "../../lib/core";
import { Notice } from "../../components/Field";
import { EmptyState, Page, ResultPanel, useResult } from "../../components/Page";
import { CopyButton } from "../../components/Data";
import { useT } from "../../lib/i18n";
import { AUDIT_EXPORT_CMD as EXPORT_CMD } from "./api";


export function AuditView({ core }: { core: CoreAPI }) {
  const t = useT();
  const r = useResult<{ intact: boolean; firstBroken: number; head: string }>();
  return (
    <Page title={t("audit.title")} description={t("audit.desc")}>
      <p>{t("audit.intro")} <code>{EXPORT_CMD}</code><CopyButton value={EXPORT_CMD} label={t("audit.copyCmd")} /></p>
      <div className="actions">
        <button className="primary" onClick={() => r.run(() => core.auditVerify())} disabled={r.busy} aria-busy={r.busy}>{t("audit.verify")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
      </div>
      {r.error && <Notice kind="error">{r.error}</Notice>}
      {!r.data && !r.error && <EmptyState icon="shield" title={t("audit.empty.title")}>{t("audit.empty")}</EmptyState>}
      {r.data && (
        <ResultPanel title={t("audit.integrity")} pad status={r.data.intact ? { tone: "ok", label: t("audit.badge.ok") } : { tone: "bad", label: t("audit.badge.broken", { n: r.data.firstBroken }) }}
          meta={r.data.intact && r.data.head ? <span className="mono">{r.data.head}<CopyButton value={r.data.head} label={t("audit.copyHead")} /></span> : undefined}>
          {r.data.intact
            ? <Notice kind="ok">{t("audit.ok", { head: r.data.head })}</Notice>
            : <Notice kind="error">{t("audit.broken", { n: r.data.firstBroken })}</Notice>}
        </ResultPanel>
      )}
    </Page>
  );
}
