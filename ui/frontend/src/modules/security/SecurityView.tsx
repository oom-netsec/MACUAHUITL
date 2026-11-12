import { useEffect, useState, type ReactNode } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { Check, Field, Notice, Select, TextArea } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, Tabs, useResult } from "../../components/Page";
import { Terminal } from "../../components/Terminal";
import { useT } from "../../lib/i18n";
import type { PkiReportData, RadiusReportData, TacacsReportData } from "./api";
import { CertChain, ResultCards } from "./SecCards";
import "./security.css";
import { useVaultVersion } from "../../lib/vaultSignal";

type Sub = "RADIUS" | "TACACS+" | "PKI" | "IKE/IPsec";
const subs: Sub[] = ["RADIUS", "TACACS+", "PKI", "IKE/IPsec"];

const list = (s: string) => s.split(/[\s,;]+/).filter(Boolean);

// Salida de una prueba: sin ejecutar muestra qué hacer primero; después, el panel con el texto o el error del núcleo.
// bare: los hijos arman sus propios paneles (tarjetas); el error sigue saliendo en el panel de salida.
function Outcome({ r, empty, bare, children }: { r: { busy: boolean; data: unknown; error: string }; empty?: string; bare?: boolean; children: ReactNode }) {
  const t = useT();
  if (r.busy) return null;
  if (!r.data && !r.error) return empty ? <EmptyState icon="shield" title={t("security.empty.title")}>{empty}</EmptyState> : null;
  if (bare && r.data) return <>{children}</>;
  return <ResultPanel title={t("common.output")} error={r.error}>{children}</ResultPanel>;
}

// Salida cruda cuando el texto no tiene la forma de un informe del núcleo.
function Raw({ text }: { text: string }) {
  const t = useT();
  return <ResultPanel title={t("common.output")}><Terminal text={text} aria-label={t("common.output")} /></ResultPanel>;
}

function useCreds(core: CoreAPI) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    core.listCredentials().then(setCreds).catch(() => setCreds([])); // bóveda cerrada: solo secretos escritos
  }, [core, vv]);
  return [["", t("security.typeHere")] as [string, string], ...creds.map((c) => [c.id, t("security.credVault", { label: c.label, user: c.username })] as [string, string])];
}

// Secreto compartido y usuario de prueba: de la bóveda o escritos sin eco.
function useSecrets(core: CoreAPI) {
  const t = useT();
  const options = useCreds(core);
  const [secretCredId, setSecretCredId] = useState("");
  const [secret, setSecret] = useState("");
  const [credId, setCredId] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const view = (needUser: boolean) => (
    <Section title={t("security.sec.creds")}>
      <div className="field-row">
        <Select label={t("security.secretFrom")} value={secretCredId} onChange={setSecretCredId} options={options} w="lg" />
        {!secretCredId && <Field label={t("security.secret")} type="password" value={secret} onChange={setSecret} autoComplete="new-password" w="lg" />}
      </div>
      {needUser && (
        <div className="field-row">
          <Select label={t("security.userFrom")} value={credId} onChange={setCredId} options={options} w="lg" />
          {!credId && (
            <>
              <Field label={t("security.testUser")} value={username} onChange={setUsername} w="md" />
              <Field label={t("security.testPass")} type="password" value={password} onChange={setPassword} autoComplete="new-password" w="md" />
            </>
          )}
        </div>
      )}
    </Section>
  );
  const values = { secretCredId, secret: secretCredId ? "" : secret, credId, username: credId ? "" : username, password: credId ? "" : password };
  const ready = (needUser: boolean) => (!!secretCredId || !!secret) && (!needUser || !!credId || !!username);
  return { view, values, ready };
}

// Resultado de una prueba: el informe estructurado y, si no lo hay o llega sin texto (doble de pruebas), el texto de siempre.
// Un error del informe NO cae al texto: repetiría la prueba contra el servidor (dos intentos de autenticación).
interface Probe<R> { text: string; report?: R }
async function probe<A, R extends { text: string }>(report: ((a: A) => Promise<R>) | undefined, plain: (a: A) => Promise<string>, arg: A): Promise<Probe<R>> {
  const rep = report && await report(arg);
  return rep?.text ? { text: rep.text, report: rep } : { text: await plain(arg) };
}

const kbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;
const portTypes = (none: string): [string, string][] => [["ethernet", "Ethernet (15)"], ["wireless-802.11", "Wireless-802.11 (19)"], ["virtual", "Virtual (5)"], ["async", "Async (0)"], ["", none]];
const serviceTypes = (none: string): [string, string][] => [["framed", "Framed (2)"], ["login", "Login (1)"], ["call-check", "Call-Check (10, MAB)"], ["nas-prompt", "NAS-Prompt (7)"], ["administrative", "Administrative (6)"], ["", none]];

function RadiusPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const s = useSecrets(core);
  const [host, setHost] = useState("");
  const [authPort, setAuthPort] = useState("1812");
  const [acctPort, setAcctPort] = useState("1813");
  const [method, setMethod] = useState("pap");
  const [nasIp, setNasIp] = useState("");
  const [nasId, setNasId] = useState("");
  const [portType, setPortType] = useState("ethernet");
  const [serviceType, setServiceType] = useState("framed");
  const [called, setCalled] = useState("");
  const [calling, setCalling] = useState("");
  const [statusServer, setStatusServer] = useState(false);
  const [accounting, setAccounting] = useState(false);
  const r = useResult<Probe<RadiusReportData>>();
  const go = () => r.run(() => probe(core.secRadiusReport, core.secRadius, { host, authPort: Number(authPort) || 1812, acctPort: Number(acctPort) || 1813, ...s.values, method,
    nasIp, nasId, portType, serviceType, called, calling, statusServer, accounting }));
  return (
    <>
      <Section title={t("security.sec.target")}>
        <div className="field-row">
          <Field label={t("security.server")} value={host} onChange={setHost} w="lg" mono />
          <Field label={t("security.authPort")} type="number" value={authPort} onChange={setAuthPort} w="sm" mono />
        </div>
        <Check label={t("security.statusOnly")} checked={statusServer} onChange={setStatusServer} />
      </Section>
      {s.view(!statusServer)}
      {!statusServer && (
        <Section title={t("security.sec.attrs")}>
          <div className="field-row">
            <Select label={t("security.method")} value={method} onChange={setMethod} options={[["pap", "PAP"], ["chap", "CHAP"], ["mschapv2", "MS-CHAPv2"]]} w="md" />
            <Select label="NAS-Port-Type" value={portType} onChange={setPortType} options={portTypes(t("security.noSend"))} w="md" />
            <Select label="Service-Type" value={serviceType} onChange={setServiceType} options={serviceTypes(t("security.noSend"))} w="md" />
          </div>
          <div className="field-row">
            <Field label="NAS-IP-Address" value={nasIp} onChange={setNasIp} w="md" mono />
            <Field label="NAS-Identifier" value={nasId} onChange={setNasId} w="md" mono />
            <Field label="Called-Station-Id" value={called} onChange={setCalled} w="md" mono />
          </div>
          <div className="field-row">
            <Field label={t("security.callingId")} value={calling} onChange={setCalling} w="lg" mono />
          </div>
          <Check label={t("security.accounting")} checked={accounting} onChange={setAccounting} />
          {accounting && <Field label={t("security.acctPort")} type="number" value={acctPort} onChange={setAcctPort} w="sm" mono />}
        </Section>
      )}
      <p className="hint">{t("security.radiusNote")}</p>
      <div className="actions"><button className="primary" disabled={!host || !s.ready(!statusServer) || r.busy} aria-busy={r.busy} onClick={go}>{t("security.test")}{kbd}</button></div>
      <Outcome r={r} bare empty={t("security.radius.empty")}>{r.data && <ResultCards kind="radius" text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}

function TacacsPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const s = useSecrets(core);
  const [host, setHost] = useState("");
  const [port, setPort] = useState("49");
  const [authenType, setAuthenType] = useState("ascii");
  const [command, setCommand] = useState("show running-config");
  const [accounting, setAccounting] = useState(true);
  const r = useResult<Probe<TacacsReportData>>();
  return (
    <>
      <Section title={t("security.sec.target")}>
        <div className="field-row">
          <Field label={t("security.server")} value={host} onChange={setHost} w="lg" mono />
          <Field label={t("security.port")} type="number" value={port} onChange={setPort} w="xs" mono />
        </div>
      </Section>
      {s.view(true)}
      <Section title={t("security.sec.authz")}>
        <div className="field-row">
          <Select label={t("security.authen")} value={authenType} onChange={setAuthenType} options={[["ascii", t("security.authenAscii")], ["pap", "PAP"]]} w="md" />
          <Field label={t("security.tacCommand")} value={command} onChange={setCommand} w="lg" mono />
        </div>
        <Check label={t("security.accounting")} checked={accounting} onChange={setAccounting} />
      </Section>
      <div className="actions">
        <button className="primary" disabled={!host || !s.ready(true) || r.busy} aria-busy={r.busy}
          onClick={() => r.run(() => probe(core.secTacacsReport, core.secTacacs, { host, port: Number(port) || 49, ...s.values, authenType, command, accounting }))}>{t("security.test")}{kbd}</button>
      </div>
      <Outcome r={r} bare empty={t("security.tacacs.empty")}>{r.data && <ResultCards kind="tacacs" text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}

const algorithms: [string, string][] = [["p256", "ECDSA P-256"], ["p384", "ECDSA P-384"], ["rsa2048", "RSA 2048"], ["rsa3072", "RSA 3072"], ["rsa4096", "RSA 4096"]];
type Pem = { pem: string; key: string; text: string };

function CsrCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [cn, setCn] = useState("");
  const [o, setO] = useState("");
  const [ou, setOu] = useState("");
  const [l, setL] = useState("");
  const [st, setSt] = useState("");
  const [c, setC] = useState("");
  const [dns, setDns] = useState("");
  const [ips, setIps] = useState("");
  const [algorithm, setAlgorithm] = useState("p256");
  const [sealedKey, setSealedKey] = useState("");
  const [keyPassword, setKeyPassword] = useState("");
  const r = useResult<Pem>();
  return (
    <>
      <Section title="CSR">
        <div className="field-row">
          <Field label="CN" value={cn} onChange={setCn} w="lg" mono />
          <Field label={t("security.csr.c")} value={c} onChange={setC} w="xs" mono />
        </div>
        <div className="field-row">
          <Field label="O" value={o} onChange={setO} w="md" />
          <Field label="OU" value={ou} onChange={setOu} w="md" />
          <Field label="L" value={l} onChange={setL} w="md" />
          <Field label="ST" value={st} onChange={setSt} w="md" />
        </div>
        <div className="field-row">
          <Field label={t("security.csr.sanDns")} value={dns} onChange={setDns} w="lg" mono />
          <Field label={t("security.csr.sanIp")} value={ips} onChange={setIps} w="lg" mono />
        </div>
        <TextArea label={t("security.csr.sealedExisting")} value={sealedKey} onChange={setSealedKey} rows={3} />
        <div className="field-row">
          {!sealedKey && <Select label={t("security.algorithm")} value={algorithm} onChange={setAlgorithm} options={algorithms} w="md" />}
          <Field label={t("security.keyPassword")} type="password" value={keyPassword} onChange={setKeyPassword} autoComplete="new-password" w="md" />
        </div>
        <div className="actions">
          <button className="primary" disabled={!cn || !keyPassword || r.busy} aria-busy={r.busy}
            onClick={() => r.run(() => core.secPkiCsr({ cn, o, ou, l, st, c, dns: list(dns), ips: list(ips), algorithm, sealedKey, keyPassword }))}>{t("security.csr.generate")}{kbd}</button>
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

function CaCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [name, setName] = useState("");
  const [days, setDays] = useState("3650");
  const [algorithm, setAlgorithm] = useState("p256");
  const [password, setPassword] = useState("");
  const [caCert, setCaCert] = useState("");
  const [caKey, setCaKey] = useState("");
  const [csr, setCsr] = useState("");
  const [profile, setProfile] = useState("server");
  const [certDays, setCertDays] = useState("365");
  const init = useResult<Pem>();
  const sign = useResult<Pem>();
  useEffect(() => {
    if (init.data) { setCaCert(init.data.pem); setCaKey(init.data.key); }
  }, [init.data]);
  return (
    <>
      <Section title={t("security.ca.title")}>
        <Notice kind="warn">{t("security.ca.warn")}</Notice>
        <div className="field-row">
          <Field label={t("security.ca.name")} value={name} onChange={setName} w="lg" />
          <Field label={t("security.ca.days")} type="number" value={days} onChange={setDays} w="sm" mono />
        </div>
        <div className="field-row">
          <Select label={t("security.ca.algorithm")} value={algorithm} onChange={setAlgorithm} options={algorithms} w="md" />
          <Field label={t("security.ca.password")} type="password" value={password} onChange={setPassword} autoComplete="new-password" w="md" />
        </div>
        <div className="actions">
          <button disabled={!name || !password || init.busy} aria-busy={init.busy} onClick={() => init.run(() => core.secPkiCaInit(name, Number(days) || 3650, algorithm, password))}>{t("security.ca.create")}</button>
        </div>
        <Outcome r={init}>{init.data && <Terminal text={init.data.text} aria-label={t("common.output")} />}</Outcome>
        <TextArea label={t("security.ca.cert")} value={caCert} onChange={setCaCert} rows={4} />
        <TextArea label={t("security.ca.sealedKey")} value={caKey} onChange={setCaKey} rows={4} />
        <TextArea label={t("security.ca.csr")} value={csr} onChange={setCsr} rows={4} />
        <div className="field-row">
          <Select label={t("security.ca.profile")} value={profile} onChange={setProfile} w="md"
            options={[["server", t("security.ca.profile.server")], ["client", t("security.ca.profile.client")], ["server-client", t("security.ca.profile.both")]]} />
          <Field label={t("security.ca.certDays")} type="number" value={certDays} onChange={setCertDays} w="sm" mono />
        </div>
        <div className="actions">
          <button disabled={!caCert || !caKey || !csr || !password || sign.busy} aria-busy={sign.busy}
            onClick={() => sign.run(() => core.secPkiCaSign(caCert, caKey, password, csr, profile, Number(certDays) || 365))}>{t("security.ca.sign")}</button>
        </div>
      </Section>
      <Outcome r={sign}>
        {sign.data && (
          <>
            <div className="panel-body"><TextArea label={t("security.ca.signed")} value={sign.data.pem} readOnly /></div>
            <Terminal text={sign.data.text} aria-label={t("common.output")} />
          </>
        )}
      </Outcome>
    </>
  );
}

function ExportCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [format, setFormat] = useState("p12");
  const [cert, setCert] = useState("");
  const [chain, setChain] = useState("");
  const [sealedKey, setSealedKey] = useState("");
  const [keyPassword, setKeyPassword] = useState("");
  const [exportPassword, setExportPassword] = useState("");
  const [plainKey, setPlainKey] = useState(false);
  const [path, setPath] = useState("");
  const r = useResult<string>();
  const p12 = format.startsWith("p12");
  return (
    <Section title={t("security.export")}>
      <Select label={t("security.format")} value={format} onChange={setFormat} w="lg"
        options={[["p12", "PKCS#12 (AES-256)"], ["p12-legacy", t("security.export.p12legacy")], ["pem", "PEM"], ["der", t("security.export.der")]]} />
      <TextArea label={t("security.export.cert")} value={cert} onChange={setCert} rows={4} />
      {format !== "der" && <TextArea label={t("security.export.chain")} value={chain} onChange={setChain} rows={3} />}
      {(p12 || plainKey) && (
        <>
          <TextArea label={t("security.export.sealed")} value={sealedKey} onChange={setSealedKey} rows={3} />
          <Field label={t("security.export.keyPassword")} type="password" value={keyPassword} onChange={setKeyPassword} w="md" />
        </>
      )}
      {p12 && <Field label={t("security.export.p12Password")} type="password" value={exportPassword} onChange={setExportPassword} autoComplete="new-password" w="md" />}
      {format === "pem" && <Check label={t("security.export.plain")} checked={plainKey} onChange={setPlainKey} />}
      <Field label={t("security.export.path")} value={path} onChange={setPath} w="full" mono />
      <div className="actions">
        <button disabled={!cert || !path || r.busy} aria-busy={r.busy}
          onClick={() => r.run(() => core.secPkiExport({ format, cert, chain, sealedKey, keyPassword, exportPassword, plainKey, path }))}>{t("security.export")}</button>
      </div>
      {r.error && <Notice kind="error">{r.error}</Notice>}
      {r.data && <Notice kind="ok">{t("security.export.saved", { path: r.data })}</Notice>}
    </Section>
  );
}

function DecodeCard({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const r = useResult<Probe<PkiReportData>>();
  return (
    <>
      <Section title={t("security.decode")}>
        <TextArea label={t("security.decode.input")} value={text} onChange={setText} />
        <div className="actions"><button disabled={!text || r.busy} aria-busy={r.busy} onClick={() => r.run(() => probe(core.secPkiDecodeReport, core.secPkiDecode, text))}>{t("security.decode.cert")}</button></div>
      </Section>
      <Outcome r={r} bare>{r.data && <CertChain text={r.data.text} report={r.data.report} fallback={<Raw text={r.data.text} />} />}</Outcome>
    </>
  );
}

function IkePanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [text, setText] = useState("");
  const r = useResult<string>();
  return (
    <>
      <Section title={t("security.sec.ike")} description={t("security.ike.note")}>
        <TextArea label={t("security.ike.input")} value={text} onChange={setText} rows={14} />
        <div className="actions"><button className="primary" disabled={!text || r.busy} aria-busy={r.busy} onClick={() => r.run(() => core.secIkeDecode(text))}>{t("security.decode")}{kbd}</button></div>
      </Section>
      <Outcome r={r} empty={t("security.ike.empty")}>{r.data && <Terminal text={r.data} aria-label={t("common.output")} />}</Outcome>
    </>
  );
}

export function SecurityView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("RADIUS");
  return (
    <Page title={t("security.title")} description={t("security.desc")}
      tabs={<Tabs label={t("security.tool")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, s] as [Sub, string])} />}>
      {sub === "RADIUS" && <RadiusPanel core={core} />}
      {sub === "TACACS+" && <TacacsPanel core={core} />}
      {sub === "PKI" && (
        <>
          <CsrCard core={core} />
          <CaCard core={core} />
          <ExportCard core={core} />
          <DecodeCard core={core} />
        </>
      )}
      {sub === "IKE/IPsec" && <IkePanel core={core} />}
    </Page>
  );
}
