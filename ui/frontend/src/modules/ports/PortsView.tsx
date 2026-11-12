import { useEffect, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { AssistBanner, AssistExecution, targetOf } from "../../components/AssistRun";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, Section, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { PortsPlanResult, PortsRequest } from "./api";
import type { PortStatus } from "../metrics/api";
import { toFront } from "./front";
import { FrontPanel } from "./FrontPanel";
import "./ports.css";
import { useVaultVersion } from "../../lib/vaultSignal";
import { parseFingerprints } from "../../lib/hostkeys";

type Shut = "" | "shut" | "noshut";

export function PortsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [credId, setCredId] = useState("");
  const [equipo, setEquipo] = useState("");
  const [ifaces, setIfaces] = useState("");
  const [vlan, setVlan] = useState("");
  const [voice, setVoice] = useState("");
  const [desc, setDesc] = useState("");
  const [shut, setShut] = useState<Shut>("");
  const [writeMem, setWriteMem] = useState(false);
  const [fps, setFps] = useState("");
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [err, setErr] = useState("");
  const [active, setActive] = useState(false);
  const [planned, setPlanned] = useState(false);
  const front = useResult<PortStatus>();
  // Los puertos elegidos son los que están escritos en el campo Interfaces: el panel y el campo son una sola selección.
  const names = ifaces.split(/[\s,]+/).filter(Boolean);
  const toggle = (name: string) => setIfaces((names.includes(name) ? names.filter((n) => n !== name) : [...names, name]).join(", "));

  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    // Con la bóveda cerrada la lista se vacía y el error queda a la vista; al reabrirla se limpia.
    core.listCredentials().then((c) => { setCreds(c); setErr(""); setCredId((cur) => (c.some((x) => x.id === cur) ? cur : c[0]?.id ?? "")); }).catch((e) => { setCreds([]); setErr(errorText(e)); });
  }, [core, vv]);

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
    try {
      setPlan(await core.assistPlanPorts(req));
    } catch (e) {
      setErr(errorText(e));
    }
  };

  const canPlan = equipo.trim() !== "" && credId !== "" && ifaces.trim() !== "" && (vlan !== "" || voice !== "" || desc !== "" || shut !== "");

  return (
    <Page title={t("ports.title")} description={t("ports.hint")}>
      <AssistBanner active={active} />
      <Section title={t("ports.section.target")}>
        <div className="field-row">
          <Field label={t("assist.device")} value={equipo} onChange={setEquipo} w="lg" mono />
          <Select label={t("assist.cred")} value={credId} onChange={setCredId} w="md" options={creds.map((c) => [c.id, `${c.label} (${c.username})`])} />
        </div>
      </Section>
      <Section title={t("ports.section.panel")} description={t("ports.panel.hint")}>
        <div className="actions">
          <button disabled={!equipo.trim() || !credId || front.busy} aria-busy={front.busy} onClick={() => front.run(() => { const d = targetOf(equipo, credId); return core.portStatus({ device: d.address, port: d.port ?? 0, credentialId: credId, acceptedHostKeys: parseFingerprints(fps) }); })}>{t("ports.read")}</button>
        </div>
        {front.error && <Notice kind="error">{front.error}</Notice>}
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
        <Field label={t("fps.accepted")} value={fps} onChange={setFps} w="full" mono />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!canPlan || active} onClick={doPlan}>{t("assist.plan")}</button>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {!planned && !active && <EmptyState icon="ops" title={t("ports.empty.title")}>{t("ports.empty")}</EmptyState>}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Page>
  );
}
