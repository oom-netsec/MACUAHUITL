import { useEffect, useMemo, useRef, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { AssistBanner, AssistExecution, targetOf } from "../../components/AssistRun";
import { Check, Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { PortsPlanResult } from "../ports/api";
import { useVaultVersion } from "../../lib/vaultSignal";
import type { SnippetTemplate } from "./api";
import { FieldInput, useTx } from "./FieldInput";
import { errInfo } from "../../lib/coreError";
import { firstInvalid, formReady, groupTemplates, initialValues, mapInvalid, parseCoreError, valuesToSend } from "./form";

const techLabel: Record<string, Key> = {
  l2: "snippets.tech.l2", l3: "snippets.tech.l3", gestion: "snippets.tech.gestion", seguridad: "snippets.tech.seguridad", qos: "snippets.tech.qos", etherchannel: "snippets.tech.etherchannel",
};

type Platform = "" | "ios" | "ios-xe";

export function SnippetsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const tx = useTx();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [credId, setCredId] = useState("");
  const [equipo, setEquipo] = useState("");
  const [platform, setPlatform] = useState<Platform>("");
  const [catalog, setCatalog] = useState<SnippetTemplate[]>([]);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<SnippetTemplate | null>(null);
  const [values, setValues] = useState<Record<string, string>>({});
  const [fieldErr, setFieldErr] = useState<Record<string, string>>({});
  const [writeMem, setWriteMem] = useState(false);
  const [fps, setFps] = useState("");
  const [plan, setPlan] = useState<PortsPlanResult | null>(null);
  const [err, setErr] = useState("");
  const [warn, setWarn] = useState("");
  const [active, setActive] = useState(false);
  const [planned, setPlanned] = useState(false);
  // Número de la última acción que invalida el plan: una respuesta (plan o error) de una petición anterior se descarta.
  const seq = useRef(0);

  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    // Con la bóveda cerrada la lista se vacía y el error queda a la vista; al reabrirla se limpia.
    core.listCredentials().then((c) => { setCreds(c); setErr(""); setCredId((cur) => (c.some((x) => x.id === cur) ? cur : c[0]?.id ?? "")); }).catch((e) => { setCreds([]); setErr(errorText(e)); });
  }, [core, vv]);

  useEffect(() => {
    let alive = true;
    core.listSnippetTemplates(platform).then((l) => {
      if (!alive) return;
      setCatalog(l);
      setSel((cur) => (cur && l.some((x) => x.id === cur.id) ? cur : null)); // la plantilla elegida deja de aplicar a esta plataforma
    }).catch((e) => { if (alive) { setCatalog([]); setErr(errorText(e)); } });
    return () => { alive = false; };
  }, [core, platform]);

  const groups = useMemo(() => groupTemplates(catalog, q, (x) => tx(`snippet.${x.id}.name`, x.name)), [catalog, q, tx]);

  const clearMsgs = () => { setErr(""); setWarn(""); setFieldErr({}); };
  // Todo lo que entra en la petición (campos, equipo, credencial, huellas, write memory, plataforma) deja obsoleto el plan y cualquier respuesta pendiente.
  const stale = () => { seq.current++; setPlan(null); };
  const edit = <T,>(set: (v: T) => void) => (v: T) => { stale(); set(v); };
  const pick = (x: SnippetTemplate) => { stale(); setSel(x); setValues(initialValues(x)); setPlanned(false); clearMsgs(); };
  // Cambiar un dato también quita el rechazo que el núcleo dio a ese campo.
  const setVal = (name: string, v: string) => {
    stale();
    setValues((cur) => ({ ...cur, [name]: v }));
    setFieldErr(({ [name]: _, ...rest }) => rest);
  };

  const doPlan = async () => {
    if (!sel) return;
    clearMsgs(); setPlan(null); setPlanned(true);
    const mine = ++seq.current;
    const accepted = fps.split(/[\s,]+/).filter(Boolean);
    try {
      const res = await core.planTemplateSnippet({
        target: targetOf(equipo, credId), id: sel.id, values: valuesToSend(sel, values),
        ...(writeMem ? { writeMemory: true } : {}), ...(accepted.length ? { acceptedHostKeyFingerprints: accepted } : {}),
      });
      if (mine === seq.current) setPlan(res);
    } catch (e) {
      if (mine !== seq.current) return;
      const { code, desc } = parseCoreError(e);
      const info = errInfo(e);
      if (code === "InvalidArgument") {
        const { byField, rest } = mapInvalid(desc, sel.fields);
        const first = firstInvalid(info, sel.fields); // el texto del núcleo (con valor y rango) manda; el motivo solo ubica el campo si el texto no lo nombra
        if (first && !byField[first[0]]) byField[first[0]] = t(first[1]);
        setFieldErr(byField);
        if (rest.length) setErr(rest.join("; "));
      } else if (info?.reason === "assist.refused") setWarn(t("snippets.refused", { why: desc.replace(/^assist: [^:]+: /, "") }));
      else if (code === "FailedPrecondition") setWarn(desc); // el equipo no puede recibir el cambio: se muestra el motivo tal cual
      else setErr(desc);
    }
  };

  const canPlan = equipo.trim() !== "" && credId !== "" && !!sel && formReady(sel, values);

  return (
    <Page title={t("nav.snippets")} description={t("snippets.hint")}>
      <AssistBanner active={active} />
      <Section title={t("snippets.section.target")}>
        <div className="field-row">
          <Field label={t("assist.device")} value={equipo} onChange={edit(setEquipo)} w="lg" mono />
          <Select label={t("assist.cred")} value={credId} onChange={edit(setCredId)} w="md" options={creds.map((c) => [c.id, `${c.label} (${c.username})`])} />
          <Select<Platform> label={t("snippets.platform")} value={platform} onChange={edit(setPlatform)} w="sm" options={[["", t("snippets.platform.all")], ["ios", "IOS"], ["ios-xe", "IOS-XE"]]} />
        </div>
      </Section>
      <Section title={t("snippets.section.pick")}>
        <Field label={t("snippets.search")} type="search" value={q} onChange={setQ} w="lg" />
        {groups.length === 0 && <p className="empty">{t("snippets.none")}</p>}
        {groups.map(([tech, list]) => (
          <fieldset key={tech} className="pb-group">
            <legend>{techLabel[tech] ? t(techLabel[tech]) : tech}</legend>
            {list.map((x) => (
              <div key={x.id} className="check">
                <input id={`sn-${x.id}`} type="radio" name="snippet" checked={sel?.id === x.id} onChange={() => pick(x)} />
                <label htmlFor={`sn-${x.id}`}>{tx(`snippet.${x.id}.name`, x.name)}</label>
              </div>
            ))}
          </fieldset>
        ))}
      </Section>
      {sel && (
        <Section title={tx(`snippet.${sel.id}.name`, sel.name)}>
          <div className="field-row">
            {sel.fields.map((f) => (
              <FieldInput key={f.name} tid={sel.id} f={f} value={values[f.name] ?? ""} onChange={(v) => setVal(f.name, v)} error={fieldErr[f.name]} />
            ))}
          </div>
          <p className="hint">{t("snippets.required")}</p>
        </Section>
      )}
      <Section title={t("snippets.section.run")}>
        <Check label={t("assist.writeMem")} checked={writeMem} onChange={edit(setWriteMem)} />
        <Field label={t("fps.accepted")} value={fps} onChange={edit(setFps)} w="full" mono />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!canPlan || active} onClick={doPlan}>{t("assist.plan")}</button>
      </div>
      {warn && <Notice kind="warn">{warn}</Notice>}
      {err && <Notice kind="error">{err}</Notice>}
      {!planned && !active && <EmptyState icon="ops" title={t("snippets.empty.title")}>{t("snippets.empty")}</EmptyState>}
      <AssistExecution core={core} plan={plan} onStarted={() => setPlan(null)} onActive={setActive} onError={setErr} />
    </Page>
  );
}
