import { useState } from "react";
import { RunButton } from "../../components/RunButton";
import { CredentialSelect, useCredentials } from "../../components/CredentialSelect";
import type { CoreAPI } from "../../lib/core";
import { AssistBanner, AssistExecution, targetOf } from "../../components/AssistRun";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { PortsPlanResult, PortsRequest } from "./api";
import type { PortStatus } from "../metrics/api";
import { toFront } from "./front";
import { FrontPanel } from "./FrontPanel";
import "./ports.css";
import { hostKeyFromError, hostOfTarget, parseFingerprints, resolveAccepted, type AcceptedKey, type HostKeyInfo } from "../../lib/hostkeys";
import { errInfo } from "../../lib/coreError";
import { HostKeyTrust } from "../../components/HostKeyTrust";

type Shut = "" | "shut" | "noshut";

export function PortsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const { creds, vault, error: vaultError } = useCredentials(core);
  const [credId, setCredId] = useState("");
  const [equipo, setEquipo] = useState("");
  const [ifaces, setIfaces] = useState("");
  const [vlan, setVlan] = useState("");
  const [voice, setVoice] = useState("");
  const [desc, setDesc] = useState("");
  const [shut, setShut] = useState<Shut>("");
  const [writeMem, setWriteMem] = useState(false);
  const [fps, setFps] = useState("");
  const pairs = (d: { address: string; port?: number }) => { const acceptedKeys = resolveAccepted(fps, [d]).keys; return acceptedKeys.length ? { acceptedKeys } : {}; };
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [err, setErr] = useState("");
  const [active, setActive] = useState(false);
  const [planned, setPlanned] = useState(false);
  const front = useResult<PortStatus>();
  const [hk, setHk] = useState<HostKeyInfo | null>(null);
  // Los puertos elegidos son los que están escritos en el campo Interfaces: el panel y el campo son una sola selección.
  const names = ifaces.split(/[\s,]+/).filter(Boolean);
  const toggle = (name: string) => setIfaces((names.includes(name) ? names.filter((n) => n !== name) : [...names, name]).join(", "));


  // extra: pares (equipo, huella) aceptados con un clic, solo para este reintento (el campo de huellas es del plan asistido).
  const readPorts = (extra: AcceptedKey[] = []) => {
    setHk(null);
    return front.run(async () => {
      const d = targetOf(equipo, credId);
      const keys = [...(pairs(d).acceptedKeys ?? []), ...extra];
      try {
        return await core.portStatus({ device: d.address, port: d.port ?? 0, credentialId: credId, acceptedHostKeys: parseFingerprints(fps), ...(keys.length ? { acceptedKeys: keys } : {}) });
      } catch (e) {
        const info = hostKeyFromError(errorText(e), errInfo(e));
        setHk(info && { ...info, host: hostOfTarget(d) }); // el par va atado al destino que se consultó
        throw e;
      }
    });
  };

  const doPlan = async () => {
    setErr(""); setPlan(null); setPlanned(true);
    const req: PortsRequest = {
      target: targetOf(equipo, credId),
      interfaces: ifaces.split(/[\s,]+/).filter(Boolean),
    };
    if (vlan) req.vlan = Number(vlan);
    if (voice) req.voice = Number(voice);
    if (desc) req.description = desc;
    if (shut) req.shutdown = shut === "shut";
    if (writeMem) req.writeMemory = true;
    const accepted = parseFingerprints(fps);
    if (accepted.length) req.acceptedHostKeyFingerprints = accepted;
    const keys = resolveAccepted(fps, [req.target]).keys;
    if (keys.length) req.acceptedHostKeys = keys;
    try {
      setPlan(await core.assistPlanPorts(req));
    } catch (e) {
      setErr(errorText(e));
    }
  };


  return (
    <Page title={t("ports.title")} description={t("ports.hint")}>
      <AssistBanner active={active} />
      <Section title={t("ports.section.target")}>
        <div className="field-row">
          <Field label={t("assist.device")} value={equipo} onChange={(v) => { setEquipo(v); setHk(null); }} w="lg" mono />
          <CredentialSelect creds={creds} vault={vault} vaultError={vaultError} value={credId} onChange={setCredId} />
        </div>
      </Section>
      <Section title={t("ports.section.panel")} description={t("ports.panel.hint")}>
        <div className="actions">
          <RunButton busy={front.busy} missing={[!equipo.trim() && t("need.target"), !credId && t("need.cred")]} onClick={() => readPorts()}>{t("ports.read")}</RunButton>
        </div>
        {front.error && !hk && <Notice kind="error">{front.error}</Notice>}
        {hk && <HostKeyTrust items={[hk]} busy={front.busy} onTrust={readPorts} />}
        {front.data?.warnings.map((w) => <Notice key={w} kind="warn">{w}</Notice>)}
        {front.data && (front.data.ports.length
          ? <FrontPanel ports={front.data.ports.map(toFront)} selected={new Set(names)} onToggle={toggle} />
          : <EmptyState icon="ops" title={t("ports.panel.none")} />)}
      </Section>
      <Section title={t("ports.section.change")}>
        <Field label={t("ports.interfaces")} value={ifaces} onChange={setIfaces} w="full" mono />
        <div className="field-row">
          <Field label={t("ports.vlan")} value={vlan} onChange={setVlan} w="sm" mono />
          <Field label={t("ports.voice")} value={voice} onChange={setVoice} w="sm" mono />
          <Select<Shut> label={t("ports.state")} value={shut} onChange={setShut} w="md" options={[["", t("ports.state.none")], ["shut", t("ports.state.shut")], ["noshut", t("ports.state.noshut")]]} />
          <Field label={t("assist.desc")} value={desc} onChange={setDesc} w="lg" />
        </div>
      </Section>
      <Section title={t("ports.section.run")}>
        <Check label={t("assist.writeMem")} checked={writeMem} onChange={setWriteMem} />
        <Field label={t("fps.accepted")} hint={t("fps.accepted.hint")} value={fps} onChange={setFps} w="full" mono />
      </Section>
      <div className="actions">
        <RunButton primary disabled={active} onClick={doPlan} missing={[!equipo.trim() && t("need.target"), !credId && t("need.cred"), !ifaces.trim() && t("need.ifaces"), (vlan === "" && voice === "" && desc === "" && shut === "") && t("need.portChange")]}>{t("assist.plan")}</RunButton>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {!planned && !active && <EmptyState icon="ops" title={t("ports.empty.title")}>{t("ports.empty")}</EmptyState>}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Page>
  );
}
