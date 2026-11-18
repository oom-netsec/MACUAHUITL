import { useState } from "react";
import { RunButton } from "../../components/RunButton";
import { CredentialSelect, useCredentials } from "../../components/CredentialSelect";
import type { CoreAPI } from "../../lib/core";
import { resolveAccepted } from "../../lib/hostkeys";
import { AssistBanner, AssistExecution, targetOf } from "../../components/AssistRun";
import { Check, Field, Notice, errorText } from "../../components/Field";
import { EmptyState, Page, Section } from "../../components/Page";
import type { PortsPlanResult } from "../ports/api";
import { useT } from "../../lib/i18n";
import type { CredRotateRequest } from "./api";
import "./credrotate.css";

export function CredRotateView({ core }: { core: CoreAPI }) {
  const t = useT();
  const { creds, vault, error: vaultError } = useCredentials(core);
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


  const doPlan = async () => {
    setErr(""); setPlan(null); setPlanned(true);
    const req: CredRotateRequest = { target: targetOf(equipo, credId), user: user.trim(), writeMemory: true }; // obligatorio en la rotación
    if (!generate) req.newSecret = secret;
    if (update) req.updateCredentialId = update;
    const accepted = fps.split(/[\s,]+/).filter(Boolean);
    if (accepted.length) req.acceptedHostKeyFingerprints = accepted;
    const keys = resolveAccepted(fps, [req.target]).keys;
    if (keys.length) req.acceptedHostKeys = keys;
    setSecret(""); // el secreto no se queda en la pantalla: se manda una vez y se borra
    try {
      setPlan(await core.assistPlanCredRotate(req));
    } catch (e) {
      setErr(errorText(e));
    }
  };


  return (
    <Page title={t("nav.credrotate")} description={t("credrotate.hint")}>
      <AssistBanner active={active} />
      <Section title={t("credrotate.section.target")}>
        <div className="field-row">
          <Field label={t("assist.device")} value={equipo} onChange={setEquipo} w="lg" mono />
          <CredentialSelect creds={creds} vault={vault} vaultError={vaultError} value={credId} onChange={setCredId} />
        </div>
      </Section>
      <Section title={t("credrotate.section.secret")}>
        <div className="field-row">
          <Field label={t("credrotate.user")} value={user} onChange={setUser} w="md" mono />
          <CredentialSelect creds={creds} vault={vault} notice={false} value={update} onChange={setUpdate} label={t("credrotate.vault")} optional w="lg" />
        </div>
        <Check label={t("credrotate.generate")} checked={generate} onChange={setGenerate} />
        {!generate && <Field label={t("credrotate.secret")} type="password" value={secret} onChange={setSecret} autoComplete="new-password" w="md" />}
        <Notice kind="warn">{t("credrotate.wm")}</Notice>
      </Section>
      <Section title={t("credrotate.section.run")}>
        <Field label={t("fps.accepted")} hint={t("fps.accepted.hint")} value={fps} onChange={setFps} w="full" mono />
      </Section>
      <div className="actions">
        <RunButton primary disabled={active} onClick={doPlan} missing={[!equipo.trim() && t("need.target"), !credId && t("need.cred"), !user.trim() && t("need.user"), generate ? !update && t("need.vaultCred") : !secret && t("need.secret")]}>{t("assist.plan")}</RunButton>
      </div>
      {err && <Notice kind="error">{err}</Notice>}
      {!planned && !active && <EmptyState icon="ops" title={t("credrotate.empty.title")}>{t("credrotate.empty")}</EmptyState>}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Page>
  );
}
