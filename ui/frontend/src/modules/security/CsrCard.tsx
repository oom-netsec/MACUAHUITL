import type { CoreAPI } from "../../lib/core";
import { RunButton } from "../../components/RunButton";
import { Advanced } from "../../components/Advanced";
import { Field, Select, TextArea } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";
import { list, Outcome } from "./shared";
import { algorithms, type Pem } from "./pki";

interface CsrForm {
  cn: string; o: string; ou: string; l: string; st: string; c: string; dns: string; ips: string;
  algorithm: string; sealedKey: string; keyPassword: string;
}
const initial: CsrForm = { cn: "", o: "", ou: "", l: "", st: "", c: "", dns: "", ips: "", algorithm: "p256", sealedKey: "", keyPassword: "" };

export function CsrCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, set] = useForm(initial);
  const r = useResult<Pem>();
  return (
    <>
      <Section title="CSR">
        <Field label="CN" value={f.cn} onChange={set("cn")} w="lg" mono />
        <div className="field-row">
          <Field label={t("security.csr.sanDns")} value={f.dns} onChange={set("dns")} w="lg" mono />
          <Field label={t("security.csr.sanIp")} value={f.ips} onChange={set("ips")} w="lg" mono />
        </div>
        <Advanced label={t("security.csr.subject")} changed={(["o", "ou", "l", "st", "c"] as const).filter((k) => f[k] !== "").length}>
          <div className="field-row">
            <Field label="O" value={f.o} onChange={set("o")} w="md" />
            <Field label="OU" value={f.ou} onChange={set("ou")} w="md" />
            <Field label="L" value={f.l} onChange={set("l")} w="md" />
            <Field label="ST" value={f.st} onChange={set("st")} w="md" />
            <Field label={t("security.csr.c")} value={f.c} onChange={set("c")} w="xs" mono />
          </div>
        </Advanced>
        <TextArea label={t("security.csr.sealedExisting")} value={f.sealedKey} onChange={set("sealedKey")} rows={3} />
        <div className="field-row">
          {!f.sealedKey && <Select label={t("security.algorithm")} value={f.algorithm} onChange={set("algorithm")} options={algorithms} w="md" />}
          <Field label={t("security.keyPassword")} type="password" value={f.keyPassword} onChange={set("keyPassword")} autoComplete="new-password" w="md" />
        </div>
        <div className="actions">
          <RunButton primary kbd busy={r.busy} missing={[!f.cn && t("need.cn"), !f.keyPassword && t("need.keyPassword")]}
            onClick={() => { void r.run(() => core.secPkiCsr({ cn: f.cn, o: f.o, ou: f.ou, l: f.l, st: f.st, c: f.c, dns: list(f.dns), ips: list(f.ips), algorithm: f.sealedKey ? "" : f.algorithm, sealedKey: f.sealedKey, keyPassword: f.keyPassword })); set("keyPassword")(""); }}>{t("security.csr.generate")}</RunButton>
        </div>
      </Section>
      <Outcome r={r}>
        {r.data && (
          <>
            <div className="panel-body">
              <TextArea label="CSR (PEM)" value={r.data.pem} readOnly />
              <TextArea label={t("security.csr.sealedOut")} value={r.data.key} readOnly />
            </div>
            <Terminal text={r.data.text} aria-label={t("common.output")} />
          </>
        )}
      </Outcome>
    </>
  );
}
