import { useEffect } from "react";
import { RunButton } from "../../components/RunButton";
import type { CoreAPI } from "../../lib/core";
import { Field, Notice, Select, TextArea } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";
import { Outcome } from "./shared";
import { algorithms, type Pem } from "./pki";

interface CaForm {
  name: string; days: string; algorithm: string; password: string; caCert: string; caKey: string; csr: string; profile: string; certDays: string;
}
const initial: CaForm = { name: "", days: "3650", algorithm: "p256", password: "", caCert: "", caKey: "", csr: "", profile: "server", certDays: "365" };

export function CaCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, set] = useForm(initial);
  const init = useResult<Pem>();
  const sign = useResult<Pem>();
  useEffect(() => {
    if (init.data) { set("caCert")(init.data.pem); set("caKey")(init.data.key); }
  }, [init.data, set]);
  return (
    <>
      <Section title={t("security.ca.title")}>
        <Notice kind="warn">{t("security.ca.warn")}</Notice>
        <div className="field-row">
          <Field label={t("security.ca.name")} value={f.name} onChange={set("name")} w="lg" />
          <Field label={t("security.ca.days")} type="number" value={f.days} onChange={set("days")} w="sm" mono />
        </div>
        <div className="field-row">
          <Select label={t("security.ca.algorithm")} value={f.algorithm} onChange={set("algorithm")} options={algorithms} w="md" />
          {/* La contraseña de la CA se conserva a propósito tras crearla: «Firmar» la usa enseguida y la borra al firmar. */}
          <Field label={t("security.ca.password")} type="password" value={f.password} onChange={set("password")} autoComplete="new-password" w="md" />
        </div>
        <div className="actions">
          <RunButton busy={init.busy} missing={[!f.name && t("need.name"), !f.password && t("need.caPassword")]} onClick={() => init.run(() => core.secPkiCaInit(f.name, Number(f.days) || 3650, f.algorithm, f.password))}>{t("security.ca.create")}</RunButton>
        </div>
        <Outcome r={init}>{init.data && <Terminal text={init.data.text} aria-label={t("common.output")} />}</Outcome>
        <TextArea label={t("security.ca.cert")} value={f.caCert} onChange={set("caCert")} rows={4} />
        <TextArea label={t("security.ca.sealedKey")} value={f.caKey} onChange={set("caKey")} rows={4} />
        <TextArea label={t("security.ca.csr")} value={f.csr} onChange={set("csr")} rows={4} />
        <div className="field-row">
          <Select label={t("security.ca.profile")} value={f.profile} onChange={set("profile")} w="md"
            options={[["server", t("security.ca.profile.server")], ["client", t("security.ca.profile.client")], ["server-client", t("security.ca.profile.both")]]} />
          <Field label={t("security.ca.certDays")} type="number" value={f.certDays} onChange={set("certDays")} w="sm" mono />
        </div>
        <div className="actions">
          <RunButton busy={sign.busy} missing={[!f.caCert && t("need.caCert"), !f.caKey && t("need.caKey"), !f.csr && t("need.csr"), !f.password && t("need.caPassword")]}
            onClick={() => { void sign.run(() => core.secPkiCaSign(f.caCert, f.caKey, f.password, f.csr, f.profile, Number(f.certDays) || 365)); set("password")(""); }}>{t("security.ca.sign")}</RunButton>
        </div>
      </Section>
      <Outcome r={sign}>
        {sign.data && (
          <>
            <div className="panel-body"><TextArea label={t("security.ca.signed")} value={sign.data.pem} readOnly /></div>
            <Terminal text={sign.data.text} aria-label={t("common.output")} />
          </>
        )}
      </Outcome>
    </>
  );
}
