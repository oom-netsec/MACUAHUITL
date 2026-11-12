import { useEffect, useRef, useState } from "react";
import { Terminal } from "../../components/Terminal";
import type { ConsoleEvent, CoreAPI } from "../../lib/core";
import { Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { cleanTerminal, useStream } from "../../lib/stream";
import { useInbox } from "../../app/activity";
import "./console.css";

// Consola serie (RS-232 / USB-serie). Vive en el grupo Acceso junto a la terminal SSH.
export function ConsoleView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [ports, setPorts] = useState<string[]>([]);
  const [port, setPort] = useState("");
  const [baud, setBaud] = useState("9600");
  const [dataBits, setDataBits] = useState("8");
  const [parity, setParity] = useState("none");
  const [stopBits, setStopBits] = useState("1");
  const [flow, setFlow] = useState("none");
  const [runId, setRunId] = useState("");
  const [status, setStatus] = useState<{ k: Key; v?: Record<string, string> } | null>(null);
  const [err, setErr] = useState("");
  const [text, setText] = useState("");
  const [cmd, setCmd] = useState("");
  const out = useRef<HTMLPreElement>(null);
  // «Consola serie» del menú de equipo: una ruta de puerto se toma; una dirección solo se recuerda (el equipo no dice en qué puerto está).
  const [forDevice, setForDevice] = useState("");
  useInbox("console", (d) => { if (/^(\/dev\/|COM\d)/.test(d)) { setPort(d); setForDevice(""); } else setForDevice(d); });

  const scan = () =>
    core.fieldPorts().then((p) => {
      setPorts(p ?? []);
      setPort((cur) => cur || (p?.[0] ?? ""));
    }).catch((e) => setErr(errorText(e)));
  useEffect(() => { scan(); }, [core]);
  useEffect(() => { out.current?.scrollTo?.(0, out.current.scrollHeight); }, [text]);

  const s = useStream<ConsoleEvent>(core.onConsole, (e) => {
    if (e.done) {
      if (e.error) setErr(errorText(new Error(e.error)));
      setStatus({ k: "console.closed" });
      setRunId("");
      s.clear();
    } else if (e.opened) {
      setStatus({ k: "console.connected", v: { port: e.opened, path: e.outputPath ?? "" } });
    } else if (e.data) {
      const d = e.data;
      setText((prev) => cleanTerminal(prev, d));
    }
  });
  s.onUnmount(core.consoleClose);
  const open = async () => {
    setErr(""); setText(""); setStatus(null);
    try {
      setRunId(await s.start(() => core.consoleOpen({ port, baud: Number(baud), dataBits: Number(dataBits), parity, stopBits: Number(stopBits), flow })));
    } catch (e) {
      setErr(errorText(e));
    }
  };
  const act = (f: () => Promise<void>) => f().catch((e) => setErr(errorText(e)));
  const send = (d: string) => act(() => core.consoleSend(runId, d));
  const started = !!runId || !!text || !!status;
  return (
    <Page title={t("nav.console")} description={t("console.desc")}>
      <Section title={t("console.section.port")}>
        <Field label={t("console.port")} value={port} onChange={setPort} w="lg" mono />
        <p className="meta port-scan">
          {ports.length ? t("console.detected", { ports: ports.join(", ") }) : t("console.none")}
          <button className="quiet sm" onClick={scan}>{t("console.scan")}</button>
        </p>
        <div className="field-row">
          <Select label={t("console.baud")} value={baud} onChange={setBaud} w="sm" options={["9600", "19200", "38400", "57600", "115200"].map((v) => [v, v])} />
          <Select label={t("console.dataBits")} value={dataBits} onChange={setDataBits} w="sm" options={[["8", "8"], ["7", "7"]]} />
          <Select label={t("console.parity")} value={parity} onChange={setParity} w="sm" options={[["none", t("console.parity.none")], ["even", t("console.parity.even")], ["odd", t("console.parity.odd")]]} />
          <Select label={t("console.stopBits")} value={stopBits} onChange={setStopBits} w="sm" options={[["1", "1"], ["2", "2"]]} />
          <Select label={t("console.flow")} value={flow} onChange={setFlow} w="md" options={[["none", t("console.flow.none")], ["rtscts", "RTS/CTS"], ["xonxoff", "XON/XOFF"]]} />
        </div>
        <p className="hint defaults">{t("console.defaults")}</p>
        <div className="actions">
          <button className="primary" disabled={!!runId || !port} onClick={open}>{t("console.open")}<kbd aria-hidden="true">Ctrl ↵</kbd></button>
          <button disabled={!runId} onClick={() => send("\x03")}>Ctrl-C</button>
          <button disabled={!runId} onClick={() => act(() => core.consoleBreak(runId))}>BREAK</button>
          <button disabled={!runId} onClick={() => act(() => core.consoleClose(runId))}>{t("console.close")}</button>
        </div>
      </Section>
      {err && <Notice kind="error">{err}</Notice>}
      {forDevice && <Notice kind="info">{t("console.forDevice", { address: forDevice })}</Notice>}
      <Notice kind="info">{t("console.note")}</Notice>
      {!started && <EmptyState icon="terminal" title={t("console.empty.title")}>{t("console.empty")}</EmptyState>}
      {started && (
        <div className="serial-session">
          {status && <p className="meta">{t(status.k, status.v)}</p>}
          <Terminal text={text} ref={out} aria-label={t("console.output")} />
          <form className="serial-bar" onSubmit={(e) => { e.preventDefault(); send(cmd + "\r"); setCmd(""); }}>
            <Field label={t("console.cmd")} value={cmd} onChange={setCmd} w="full" mono />
            <button type="submit" disabled={!runId}>{t("console.send")}</button>
          </form>
        </div>
      )}
    </Page>
  );
}
