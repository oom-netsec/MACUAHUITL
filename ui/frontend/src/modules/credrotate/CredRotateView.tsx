import { useEffect, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { AssistBanner, AssistExecution, targetOf } from "../../components/AssistRun";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, Section } from "../../components/Page";
import type { PortsPlanResult } from "../ports/api";
import { useT } from "../../lib/i18n";
import type { CredRotateRequest } from "./api";
import "./credrotate.css";
import { useVaultVersion } from "../../lib/vaultSignal";

export function CredRotateView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [credId, setCredId] = useState("");
  const [update, setUpdate] = useState("");
  const [equipo, setEquipo] = useState("");
  const [user, setUser] = useState("");
  const [secret, setSecret] = useState("");
  const [generate, setGenerate] = useState(false);
  const [fps, setFps] = useState("");
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [err, setErr] = useState("");
  const [active, setActive] = useState(false);
  const [planned, setPlanned] = useState(false);

  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    // Con la bóveda cerrada la lista se vacía y el error queda a la vista; al reabrirla se limpia.
    core.listCredentials().then((c) => { setCreds(c); setErr(""); setCredId((cur) => (c.some((x) => x.id === cur) ? cur : c[0]?.id ?? "")); }).catch((e) => { setCreds([]); setErr(errorText(e)); });
  }, [core, vv]);

  const doPlan = async () => {
    setErr(""); setPlan(null); setPlanned(true);
    const req: CredRotateRequest = { target: targetOf(equipo, credId), user: user.trim(), writeMemory: true }; // obligatorio en la rotación
    if (!generate) req.newSecret = secret;
    if (update) req.updateCredentialId = update;
    const accepted = fps.split(/[\s,]+/).filter(Boolean);
    if (accepted.length) req.acceptedHostKeyFingerprints = accepted;
    setSecret(""); // el secreto no se queda en la pantalla: se manda una vez y se borra
    try {
      setPlan(await core.assistPlanCredRotate(req));
    } catch (e) {
      setErr(errorText(e));
    }
  };

  const canPlan = equipo.trim() !== "" && credId !== "" && user.trim() !== "" && (generate ? update !== "" : secret !== "");

  return (
    <Page title={t("nav.credrotate")} description={t("credrotate.hint")}>
      <AssistBanner active={active} />
      <Section title={t("credrotate.section.target")}>
        <div className="field-row">
          <Field label={t("assist.device")} value={equipo} onChange={setEquipo} w="lg" mono />
          <Select label={t("credrotate.cred")} value={credId} onChange={setCredId} w="md" options={creds.map((c) => [c.id, `${c.label} (${c.username})`])} />
        </div>
      </Section>
      <Section title={t("credrotate.section.secret")}>
        <div className="field-row">
          <Field label={t("credrotate.user")} value={user} onChange={setUser} w="md" mono />
          <Select label={t("credrotate.vault")} value={update} onChange={setUpdate} w="lg" options={[["", t("credrotate.vault.none")], ...creds.map((c): [string, string] => [c.id, `${c.label} (${c.username})`])]} />
        </div>
        <Check label={t("credrotate.generate")} checked={generate} onChange={setGenerate} />
        {!generate && <Field label={t("credrotate.secret")} type="password" value={secret} onChange={setSecret} autoComplete="new-password" w="md" />}
        <Notice kind="warn">{t("credrotate.wm")}</Notice>
      </Section>
      <Section title={t("credrotate.section.run")}>
        <Field label={t("fps.accepted")} value={fps} onChange={setFps} w="full" mono />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!canPlan || active} onClick={doPlan}>{t("assist.plan")}</button>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {!planned && !active && <EmptyState icon="ops" title={t("credrotate.empty.title")}>{t("credrotate.empty")}</EmptyState>}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Page>
  );
}
