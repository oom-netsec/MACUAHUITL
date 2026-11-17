import type { CoreAPI } from "../../lib/core";
import { Check, Field, Select } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { TacacsReportData } from "./api";
import { useForm } from "./form";
import { ResultCards } from "./SecCards";
import { kbd, Outcome, probe, Raw, type Probe } from "./shared";
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
      <Section title={t("security.sec.authz")}>
        <div className="field-row">
          <Select label={t("security.authen")} value={f.authenType} onChange={set("authenType")} options={[["ascii", t("security.authenAscii")], ["pap", "PAP"]]} w="md" />
          <Field label={t("security.tacCommand")} value={f.command} onChange={set("command")} w="lg" mono />
        </div>
        <Check label={t("security.accounting")} checked={f.accounting} onChange={set("accounting")} />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!f.host || !s.ready(true) || r.busy} aria-busy={r.busy}
          onClick={() => { void r.run(() => probe(core.secTacacsReport, core.secTacacs, { host: f.host, port: Number(f.port) || 49, ...s.values, authenType: f.authenType, command: f.command, accounting: f.accounting })); s.clear(); }}>{t("security.test")}{kbd}</button>
      </div>
      <Outcome r={r} bare empty={t("security.tacacs.empty")}>{r.data && <ResultCards kind="tacacs" text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}
