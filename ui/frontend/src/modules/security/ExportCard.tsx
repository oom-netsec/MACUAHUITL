import type { CoreAPI } from "../../lib/core";
import { Check, Field, Notice, Select, TextArea } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";

interface ExportForm {
  format: string; cert: string; chain: string; sealedKey: string; keyPassword: string; exportPassword: string; plainKey: boolean; path: string;
}
const initial: ExportForm = { format: "p12", cert: "", chain: "", sealedKey: "", keyPassword: "", exportPassword: "", plainKey: false, path: "" };

export function ExportCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, set] = useForm(initial);
  const r = useResult<string>();
  const p12 = f.format.startsWith("p12");
  return (
    <Section title={t("security.export")}>
      <Select label={t("security.format")} value={f.format} onChange={set("format")} w="lg"
        options={[["p12", "PKCS#12 (AES-256)"], ["p12-legacy", t("security.export.p12legacy")], ["pem", "PEM"], ["der", t("security.export.der")]]} />
      <TextArea label={t("security.export.cert")} value={f.cert} onChange={set("cert")} rows={4} />
      {f.format !== "der" && <TextArea label={t("security.export.chain")} value={f.chain} onChange={set("chain")} rows={3} />}
      {(p12 || f.plainKey) && (
        <>
          <TextArea label={t("security.export.sealed")} value={f.sealedKey} onChange={set("sealedKey")} rows={3} />
          <Field label={t("security.export.keyPassword")} type="password" value={f.keyPassword} onChange={set("keyPassword")} w="md" />
        </>
      )}
      {p12 && <Field label={t("security.export.p12Password")} type="password" value={f.exportPassword} onChange={set("exportPassword")} autoComplete="new-password" w="md" />}
      {f.format === "pem" && <Check label={t("security.export.plain")} checked={f.plainKey} onChange={set("plainKey")} />}
      <Field label={t("security.export.path")} value={f.path} onChange={set("path")} w="full" mono />
      <div className="actions">
        <button disabled={!f.cert || !f.path || r.busy} aria-busy={r.busy}
          onClick={() => { void r.run(() => core.secPkiExport({ ...f })); set("keyPassword")(""); set("exportPassword")(""); }}>{t("security.export")}</button>
      </div>
      {r.error && <Notice kind="error">{r.error}</Notice>}
      {r.data && <Notice kind="ok">{t("security.export.saved", { path: r.data })}</Notice>}
    </Section>
  );
}
