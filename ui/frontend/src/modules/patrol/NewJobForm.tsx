import { pathProblem } from "../../lib/paths";
import { useEffect, useState } from "react";
import type { CoreAPI, Credential, JobSpec } from "../../lib/core";
import { CredentialSelect, type VaultGate } from "../../components/CredentialSelect";
import { Advanced } from "../../components/Advanced";
import { Segmented } from "../../components/Segmented";
import { Check, Field, Notice, PathField, Select, TextArea, errorText } from "../../components/Field";
import { Section } from "../../components/Page";
import { useCoreLang, useT } from "../../lib/i18n";
import { errInfo } from "../../lib/coreError";
import { outputsErrorText } from "../../lib/outputsError";
import type { Key } from "../../lib/i18n/es";
import type { PlaybookInfo } from "./api";
import { PlaybookPicker } from "./PlaybookPicker";
import { useScriptsVersion } from "../scripts/signal";
import { NoPacks } from "../../components/NoPacks";
import { useNav } from "../../app/activity";
import { parseTargets, targetSpec } from "../../lib/targets";
import { TargetsField } from "../inventory/TargetField";
import { useVaultVersion } from "../../lib/vaultSignal";

// Un tipo de dato nuevo del núcleo que el front aún no traduce: se muestra el nombre del dato, sin ayuda.
const known = (k: string) => ["mac", "ap", "wlan", "interface", "ip", "vrf", "vnid"].includes(k);

// Crea el trabajo; el Login Test y el armado se hacen después, desde el detalle del trabajo.
export function NewJobForm({ core, creds, vault, onCreated }: { core: CoreAPI; creds: Credential[]; vault: VaultGate; onCreated: (id: string) => void }) {
  const t = useT();
  const coreLang = useCoreLang();
  const contentVer = useScriptsVersion(); // instalar, quitar o importar un paquete cambia el catálogo de playbooks
  const [name, setName] = useState("");
  const [targets, setTargets] = useState("");
  const [cred, setCred] = useState("");
  const pickCred = (id: string) => { if (!cred && creds.some((c) => c.id === id)) setCred(id); }; // de la libreta; no pisa la que ya se eligió
  const [cmds, setCmds] = useState("");
  const [catalog, setCatalog] = useState<PlaybookInfo[] | null>(null);
  const go = useNav();
  const [pbErr, setPbErr] = useState(false);
  const [pbs, setPbs] = useState<string[]>([]);
  const [pbTry, setPbTry] = useState(0); // el núcleo pudo estar arrancando: reintentar sin rehacer el formulario
  // Los nombres vienen en el idioma del núcleo: se piden cuando el núcleo ya tiene el de la interfaz.
  // vv: también al reconectar el núcleo (App avisa con vaultChanged), para que no quede el aviso del intento sin núcleo.
  const vv = useVaultVersion();
  useEffect(() => {
    if (!coreLang) return;
    let off = false; // una respuesta tardía en el idioma anterior no pisa la nueva
    setPbErr(false);
    core.listPlaybooks().then((c) => { if (!off) setCatalog(c); }).catch(() => { if (!off) setPbErr(true); });
    return () => { off = true; };
  }, [core, pbTry, coreLang, contentVer, vv]);
  const [vals, setVals] = useState<Record<string, string>>({});
  const [paramErr, setParamErr] = useState<Record<string, string>>({});
  // Un campo por nombre, aunque dos playbooks elegidos lo pidan.
  const asked = [...new Map((catalog ?? []).filter((p) => pbs.includes(p.id)).flatMap((p) => p.params ?? []).map((q) => [q.name, q.kind])).entries()];
  const [out, setOut] = useState("");
  // «Una vez» manda intervalo 0 y 1 ronda (el motor corre una sola sin intervalo ni cron). Los valores de abajo son los de «Repetir».
  const [repeat, setRepeat] = useState(false);
  const [byCron, setByCron] = useState(false);
  const [minutes, setMinutes] = useState("60");
  const [rounds, setRounds] = useState("0");
  const [roundsErr, setRoundsErr] = useState("");
  const [minutesErr, setMinutesErr] = useState("");
  const [hours, setHours] = useState("4");
  const [cron, setCron] = useState("");
  const [split, setSplit] = useState<JobSpec["split"]>("SPLIT_STRATEGY_PER_ROUND");
  const [zip, setZip] = useState<JobSpec["zip"]>("ZIP_POLICY_AT_END");
  const [delLoose, setDelLoose] = useState(false);
  const [mask, setMask] = useState(true);
  const [acceptChanged, setAcceptChanged] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const devices = parseTargets(targets);
  const winHours = Math.min(96, Math.max(1, Number(hours) || 1));
  const minutesOk = /^\d+$/.test(minutes.trim()) && Number(minutes) >= 1 && Number(minutes) <= 10080; // una semana: el núcleo rechaza lo demás con un error crudo
  // Solo viaja lo que se ve: con cron no hay intervalo y con intervalo no hay cron.
  const schedule = (): JobSpec["schedule"] => !repeat ? { intervalSeconds: 0, rounds: 1 }
    : byCron ? { cron: cron.trim(), rounds: Number(rounds) } : { intervalSeconds: Number(minutes) * 60, rounds: Number(rounds) };
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const noVal = asked.filter(([n]) => !(vals[n] ?? "").trim());
    setParamErr(Object.fromEntries(noVal.map(([n]) => [n, t("patrol.param.required")])));
    const missing = ([[!name.trim(), "name"], [!devices.length, "targets"], [!cred, "cred"], [!pbs.length && !cmds.trim(), "commands"], [!out.trim(), "outDir"], [repeat && !byCron && !minutesOk, "interval"], [repeat && byCron && !cron.trim(), "cron"]] as const)
      .filter(([m]) => m).map(([, k]) => t(`patrol.missing.${k}` as Key));
    setMinutesErr(repeat && !byCron && !minutesOk ? t("patrol.interval.invalid") : "");
    if (missing.length) return setErr(t("patrol.missing", { list: missing.join(", ") }));
    if (pathProblem(out.trim())) return setErr(t(pathProblem(out.trim())!)); // también junto al campo (PathField)
    if (noVal.length) return setErr(t("patrol.param.check"));
    if (repeat && !/^\d+$/.test(rounds.trim())) return setRoundsErr(t("patrol.rounds.invalid")); // vacío no es 0: 0 es hasta el fin de la ventana
    setRoundsErr("");
    const spec: JobSpec = {
      name, targets: devices.map((a) => ({ ...targetSpec(a), deviceId: a })), defaultCredentialId: cred, customCommands: cmds, playbookIds: pbs,
      outputDir: out, split, zip, deleteLooseFiles: zip !== "ZIP_POLICY_NONE" && delLoose, disableMasking: !mask, acceptChangedHostKeys: acceptChanged,
      windowHours: winHours,
      schedule: schedule(),
    };
    if (asked.length) spec.params = Object.fromEntries(asked.map(([n]) => [n, vals[n].trim()]));
    setErr(""); setBusy(true);
    try {
      onCreated(await core.createJob(spec));
    } catch (e) {
      const i = errInfo(e);
      if (i?.metadata.field === "params" && i.metadata.name && asked.some(([n]) => n === i.metadata.name)) {
        setParamErr({ [i.metadata.name]: errorText(e).replace(/^patrol: params: /, "") }); // el prefijo interno no aporta junto al campo
        setErr(t("patrol.param.check")); // aviso junto al botón (role=alert): el campo puede estar fuera de la vista
      } else setErr(outputsErrorText(e, t));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} aria-labelledby="newjob-h" noValidate className="newjob">
      <h3 id="newjob-h">{t("patrol.newJob")}</h3>
      <p className="desc">{t("patrol.newJob.hint")}</p>
      <Section title={`1 · ${t("patrol.step.targets")}`}>
        <div className="field-row">
          <Field label={t("patrol.name")} value={name} onChange={setName} w="md" />
          <CredentialSelect creds={creds} vault={vault} notice={false} value={cred} onChange={setCred} w="lg" />
        </div>
        <TargetsField core={core} hint={t("patrol.targets.hint")} value={targets} onChange={setTargets} rows={4} onPickCredential={pickCred} />
        <p className="hint count">{t("patrol.deviceCount", { n: devices.length })}</p>
      </Section>
      <Section title={`2 · ${t("patrol.step.commands")}`}>
        <h4>{t("patrol.pb.title")}</h4>
        <p className="hint">{t("patrol.pb.hint")}</p>
        {catalog && !pbErr && !catalog.some((p) => p.pack && p.pack !== "usuario") && (
          <NoPacks action={<button type="button" className="sm" onClick={() => go("settings", "packs")}>{t("packs.none.open")}</button>} />
        )}
        {pbErr ? <Notice kind="warn">{t("patrol.pb.unavailable")} <button type="button" className="sm" onClick={() => setPbTry((n) => n + 1)}>{t("common.retry")}</button></Notice> : catalog && <PlaybookPicker playbooks={catalog} selected={pbs} onChange={setPbs} />}
        {asked.map(([n, k]) => (
          <Field key={n} label={known(k) ? `${t(`patrol.param.kind.${k}` as Key)} (${n})` : n} hint={known(k) ? t(`patrol.param.${k}` as Key) : undefined} value={vals[n] ?? ""} error={paramErr[n]} onChange={(v) => setVals({ ...vals, [n]: v })} w="md" mono />
        ))}
        <TextArea label={t("patrol.commands")} hint={t("patrol.commands.hint")} value={cmds} onChange={setCmds} rows={4} mono />
        <PathField label={t("patrol.outDir")} value={out} onChange={setOut} pick={() => core.pickPath({ title: t("patrol.outDir"), directory: true })} />
      </Section>
      <Section title={`3 · ${t("patrol.step.schedule")}`}>
        <Segmented legend={t("patrol.sched.mode")} value={repeat ? "repeat" : "once"} onChange={(v) => setRepeat(v === "repeat")} options={[["once", t("patrol.sched.once")], ["repeat", t("patrol.sched.repeat")]]} />
        {repeat && (
          <>
            <Segmented legend={t("patrol.sched.kind")} value={byCron ? "cron" : "every"} onChange={(v) => setByCron(v === "cron")} options={[["every", t("patrol.sched.every")], ["cron", t("patrol.sched.cron")]]} />
            <div className="field-row">
              {byCron ? <Field label={t("patrol.cron")} value={cron} onChange={setCron} w="sm" mono /> : <Field label={t("patrol.interval")} error={minutesErr} type="number" value={minutes} onChange={setMinutes} w="sm" />}
              <Field label={t("patrol.rounds")} hint={t("patrol.rounds.hint", { h: winHours })} error={roundsErr} type="number" value={rounds} onChange={setRounds} w="sm" />
            </div>
          </>
        )}
      </Section>
      <Advanced changed={[split !== "SPLIT_STRATEGY_PER_ROUND", zip !== "ZIP_POLICY_AT_END", zip !== "ZIP_POLICY_NONE" && delLoose, hours !== "4", !mask, acceptChanged].filter(Boolean).length}>
        <div className="field-row">
          <Select label={t("patrol.split")} value={split} onChange={setSplit} w="md"
            options={[["SPLIT_STRATEGY_PER_ROUND", t("patrol.split.perRound")], ["SPLIT_STRATEGY_CONSOLIDATED", t("patrol.split.consolidated")]]} />
          <Select label={t("patrol.zip")} value={zip} onChange={setZip} w="md"
            options={[["ZIP_POLICY_AT_END", t("patrol.zip.atEnd")], ["ZIP_POLICY_PER_ROUND", t("patrol.zip.perRound")], ["ZIP_POLICY_NONE", t("patrol.zip.none")]]} />
        </div>
        {zip !== "ZIP_POLICY_NONE" && <Check label={t("patrol.deleteLoose")} checked={delLoose} onChange={setDelLoose} />}
        <Field label={t("patrol.window")} hint={t("patrol.window.hint")} type="number" value={hours} onChange={setHours} w="sm" />
        <Check label={t("patrol.mask")} checked={mask} onChange={setMask} />
        <Check label={t("patrol.acceptKeys")} checked={acceptChanged} onChange={setAcceptChanged} />
      </Advanced>
      {!mask && <Notice kind="error">{t("patrol.mask.off")}</Notice>}
      {acceptChanged && <Notice kind="error">{t("patrol.acceptKeys.on")}</Notice>}
      {err && <Notice kind="error">{err}</Notice>}
      <div className="actions">
        <button type="submit" className="primary" aria-busy={busy} disabled={busy}>{t("patrol.create")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
      </div>
    </form>
  );
}
