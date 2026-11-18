import { useState } from "react";
import { Terminal } from "../../components/Terminal";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";

export function HashView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [path, setPath] = useState("");
  const [md5, setMd5] = useState("");
  const [sha, setSha] = useState("");
  const r = useResult<{ text: string; ok: boolean }>();
  const published = md5.trim() !== "" || sha.trim() !== "";
  const status = r.data ? (!r.data.ok ? { tone: "bad" as const, label: t("field.hash.bad") } : published ? { tone: "ok" as const, label: t("field.hash.match") } : { tone: "info" as const, label: t("field.hash.computed") }) : undefined;
  return (
    <Page title={t("nav.hash")} description={t("hash.desc")}>
      <Section title={t("hash.sec")} description={t("field.hash.note")}>
        <Field label={t("field.hash.path")} value={path} onChange={setPath} w="full" mono />
        <div className="field-row">
          <Field label={t("field.hash.md5")} value={md5} onChange={setMd5} w="lg" mono />
          <Field label={t("field.hash.sha")} value={sha} onChange={setSha} w="full" mono />
        </div>
        <div className="actions">
          <button className="primary" disabled={!path || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.fieldHash(path, md5.trim(), sha.trim()))}>{t("field.hash.calc")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
        </div>
      </Section>
      {r.data && !r.data.ok && <Notice kind="error">{t("field.hash.mismatch")}</Notice>}
      {!r.data && !r.error && !r.busy && <EmptyState icon="tools" title={t("field.empty.title")}>{t("field.hash.empty")}</EmptyState>}
      {(r.data || r.error) && (
        <ResultPanel title={t("common.output")} status={status} error={r.error}>
          {r.data && <Terminal text={r.data.text} aria-label={t("common.output")} />}
        </ResultPanel>
      )}
    </Page>
  );
}
