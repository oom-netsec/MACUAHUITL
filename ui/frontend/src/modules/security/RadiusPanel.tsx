import type { CoreAPI } from "../../lib/core";
import { Check, Field, Select } from "../../components/Field";
import { Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { RadiusReportData } from "./api";
import { useForm } from "../../lib/useForm";
import { ResultCards } from "./SecCards";
import { kbd, Outcome, probe, Raw, type Probe } from "./shared";
import { useSecrets } from "./useSecrets";

const portTypes = (none: string): [string, string][] => [["ethernet", "Ethernet (15)"], ["wireless-802.11", "Wireless-802.11 (19)"], ["virtual", "Virtual (5)"], ["async", "Async (0)"], ["", none]];
const serviceTypes = (none: string): [string, string][] => [["framed", "Framed (2)"], ["login", "Login (1)"], ["call-check", "Call-Check (10, MAB)"], ["nas-prompt", "NAS-Prompt (7)"], ["administrative", "Administrative (6)"], ["", none]];

interface RadiusForm {
  host: string; authPort: string; acctPort: string; method: string; nasIp: string; nasId: string;
  portType: string; serviceType: string; called: string; calling: string; statusServer: boolean; accounting: boolean;
}
const initial: RadiusForm = {
  host: "", authPort: "1812", acctPort: "1813", method: "pap", nasIp: "", nasId: "",
  portType: "ethernet", serviceType: "framed", called: "", calling: "", statusServer: false, accounting: false,
};

export function RadiusPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const s = useSecrets(core);
  const [f, set] = useForm(initial);
  const r = useResult<Probe<RadiusReportData>>();
  const go = () => {
    void r.run(() => probe(core.secRadiusReport, core.secRadius, { host: f.host, authPort: Number(f.authPort) || 1812, acctPort: Number(f.acctPort) || 1813, ...s.values, method: f.method,
      nasIp: f.nasIp, nasId: f.nasId, portType: f.portType, serviceType: f.serviceType, called: f.called, calling: f.calling, statusServer: f.statusServer, accounting: f.accounting }));
    s.clear();
  };
  return (
    <>
      <Section title={t("security.sec.target")}>
        <div className="field-row">
          <Field label={t("security.server")} value={f.host} onChange={set("host")} w="lg" mono />
          <Field label={t("security.authPort")} type="number" value={f.authPort} onChange={set("authPort")} w="sm" mono />
        </div>
        <Check label={t("security.statusOnly")} checked={f.statusServer} onChange={set("statusServer")} />
      </Section>
      {s.view(!f.statusServer)}
      {!f.statusServer && (
        <Section title={t("security.sec.attrs")}>
          <div className="field-row">
            <Select label={t("security.method")} value={f.method} onChange={set("method")} options={[["pap", "PAP"], ["chap", "CHAP"], ["mschapv2", "MS-CHAPv2"]]} w="md" />
            <Select label="NAS-Port-Type" value={f.portType} onChange={set("portType")} options={portTypes(t("security.noSend"))} w="md" />
            <Select label="Service-Type" value={f.serviceType} onChange={set("serviceType")} options={serviceTypes(t("security.noSend"))} w="md" />
          </div>
          <div className="field-row">
            <Field label="NAS-IP-Address" value={f.nasIp} onChange={set("nasIp")} w="md" mono />
            <Field label="NAS-Identifier" value={f.nasId} onChange={set("nasId")} w="md" mono />
            <Field label="Called-Station-Id" value={f.called} onChange={set("called")} w="md" mono />
          </div>
          <div className="field-row">
            <Field label={t("security.callingId")} value={f.calling} onChange={set("calling")} w="lg" mono />
          </div>
          <Check label={t("security.accounting")} checked={f.accounting} onChange={set("accounting")} />
          {f.accounting && <Field label={t("security.acctPort")} type="number" value={f.acctPort} onChange={set("acctPort")} w="sm" mono />}
        </Section>
      )}
      <p className="hint">{t("security.radiusNote")}</p>
      <div className="actions"><button className="primary" disabled={!f.host || !s.ready(!f.statusServer) || r.busy} aria-busy={r.busy} onClick={go}>{t("security.test")}{kbd}</button></div>
      <Outcome r={r} bare empty={t("security.radius.empty")}>{r.data && <ResultCards kind="radius" text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}
