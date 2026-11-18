import type { CoreAPI } from "../../lib/core";
import { RunButton } from "../../components/RunButton";
import { Advanced } from "../../components/Advanced";
import { Check, Field, Select } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { TacacsReportData } from "./api";
import { useForm } from "../../lib/useForm";
import { ResultCards } from "./SecCards";
import { Outcome, probe, Raw, type Probe } from "./shared";
import { useSecrets } from "./useSecrets";

interface TacacsForm { host: string; port: string; authenType: string; command: string; accounting: boolean }
const initial: TacacsForm = { host: "", port: "49", authenType: "ascii", command: "show running-config", accounting: true };

export function TacacsPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const s = useSecrets(core);
  const [f, set] = useForm(initial);
  const r = useResult<Probe<TacacsReportData>>();
  return (
    <>
      <Section title={t("security.sec.target")}>
        <div className="field-row">
          <Field label={t("security.server")} value={f.host} onChange={set("host")} w="lg" mono />
          <Field label={t("security.port")} type="number" value={f.port} onChange={set("port")} w="xs" mono />
        </div>
      </Section>
      {s.view(true)}
      <Advanced label={t("security.sec.authz")} changed={(["authenType", "command", "accounting"] as const).filter((k) => f[k] !== initial[k]).length}>
        <div className="field-row">
          <Select label={t("security.authen")} value={f.authenType} onChange={set("authenType")} options={[["ascii", t("security.authenAscii")], ["pap", "PAP"]]} w="md" />
          <Field label={t("security.tacCommand")} value={f.command} onChange={set("command")} w="lg" mono />
        </div>
        <Check label={t("security.accounting")} checked={f.accounting} onChange={set("accounting")} />
      </Advanced>
      <div className="actions">
        <RunButton primary kbd busy={r.busy} missing={[!f.host && t("need.target"), ...s.missing(true)]}
          onClick={() => { void r.run(() => probe(core.secTacacsReport, core.secTacacs, { host: f.host, port: Number(f.port) || 49, ...s.values, authenType: f.authenType, command: f.command, accounting: f.accounting })); s.clear(); }}>{t("security.test")}</RunButton>
      </div>
      <Outcome r={r} bare empty={t("security.tacacs.empty")}>{r.data && <ResultCards kind="tacacs" text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}
