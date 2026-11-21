import { Suspense, lazy, useEffect, useId, useLayoutEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { Field, Notice, Select, errorText } from "../../components/Field";
import { EmptyState, Page, Section } from "../../components/Page";
import { Icon } from "../../components/Icon";
import { DownloadButton } from "../../components/Files";
import { useInbox } from "../../app/activity";
import { SessionSearch } from "./SessionSearch";
import { ViewMenu } from "./ViewMenu";
import { ScriptsMenu } from "./ScriptsMenu";
import { parseTarget, parseTargets } from "../../lib/targets";
import { cleanTerminal } from "../../lib/stream";
import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import { PALETTES } from "../../lib/termHighlight";
import { useTermPrefs } from "../../lib/termPrefs";
import { createLiveWriter } from "../../lib/termAnsi";
import type { AuthPrompt, TerminalEvent } from "./api";
import { AuthPanel } from "./AuthPanel";
import type { FindReq } from "./XTermPane";
import { xtermTheme } from "./termTheme";
import "./terminal.css";
import { useVaultVersion } from "../../lib/vaultSignal";
import { hostsChanged } from "../inventory/signal";
import { passwordCreds } from "../vault/api";
import { HostPicker } from "../inventory/HostPicker";
import { targetOf } from "../../lib/targets";
import { SavedHosts } from "./SavedHosts";
import { HostKeyTrust } from "../../components/HostKeyTrust";
import { hostKeyFromError, hostOfTarget, parseFingerprints, type AcceptedKey, type HostKeyInfo } from "../../lib/hostkeys";
import { errInfo, type ErrInfo } from "../../lib/coreError";
import type { ScriptItem } from "../scripts/api";
import { useScriptsVersion } from "../scripts/signal";
import { decodeInsert, needsCopy, scriptText, type Insert } from "../scripts/text";
import { pasteNeedsConfirm } from "../../lib/safeText";

// xterm.js (MIT) pesa más que el resto del módulo: se baja solo al abrir la primera sesión.
const XTermPane = lazy(() => import("./XTermPane"));

// Terminal SSH multipestaña. Es manual: lo que se teclea va directo al equipo, sin modo asistido.
// Cada pestaña es un emulador xterm.js: las teclas salen en crudo (Tab, ?, flechas, Ctrl-teclas) y la salida del equipo se escribe tal cual.
// La salida viva se resalta con las reglas de la app (lib/termAnsi): solo líneas completas y sin ESC; el texto limpio (búsqueda, descarga y registro) no lleva códigos.

interface Tab {
  key: number; label: string; device: string; cred: string; user: string; ask?: AuthPrompt; hostId?: string; startup?: string; proto: "ssh" | "telnet"; runId: string; status: { k: Key; v?: Record<string, string> }; err: string; errInfo?: ErrInfo; done: boolean;
  logPath: string; logAt: Date | null; logErr: string; // registro opcional en el archivo que eligió la persona
}
interface LogState { path: string; last: string; chain: Promise<void> }

// Punto de estado de la pestaña y de la línea de estado: conectando, viva, cerrada o con error.
const stateOf = (tab: Tab) => (tab.done ? (tab.err ? "error" : "closed") : tab.status.k === "ssh.connecting" ? "connecting" : "live");

const TYPED = "\u0000typed"; // valor de la opción «Escribir usuario y contraseña al conectar» del selector
const QUICK = ["show running-config", "show version", "show ip interface brief", "show interfaces status"];
// Nombre de archivo seguro: la dirección puede traer ":" del puerto.
const LOG_EVERY = 30_000;
// shortcut: el texto de una sesión con registro se acota a 4 M de caracteres; al pasarlo se pierde el principio (el núcleo graba todo en outputs/terminal/).
const LOG_MAX = 4_000_000; // cada \b del equipo recorta el texto entero: más grande y el --More-- se vuelve lento
const stamp = (d: Date) => { const z = (n: number) => String(n).padStart(2, "0"); return `${d.getFullYear()}${z(d.getMonth() + 1)}${z(d.getDate())}-${z(d.getHours())}${z(d.getMinutes())}${z(d.getSeconds())}`; };
const fileBase = (label: string) => label.replace(/[^\w.-]+/g, "_");
// Tamaño con el que se abre la sesión: el último medido o una estimación por la ventana; el ajuste real llega con terminalResize.
const estimate = () => ({ cols: Math.max(80, Math.min(300, Math.floor((window.innerWidth - 320) / 8.4))), rows: Math.max(24, Math.min(80, Math.floor(window.innerHeight * 0.6 / 16.8))) });

export function TerminalView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [creds, setCreds] = useState<Credential[]>([]);
  const [cred, setCred] = useState("");
  const [proto, setProto] = useState<"ssh" | "telnet">("ssh"); // Telnet: credencial de contraseña o login tecleado en la terminal; sin usuario, huellas ni libreta
  const [typed, setTyped] = useState(false); // sin credencial: el equipo pregunta usuario y contraseña en la propia terminal
  const [user, setUser] = useState(""); // usuario opcional en modo tecleado; vacío = «login as:»
  const [device, setDevice] = useState("");
  const [accept, setAccept] = useState("");
  const [err, setErr] = useState("");
  // Llave de host rechazada en la apertura misma (sin pestaña): el aviso va arriba. Hoy el núcleo lo manda por el stream de la pestaña.
  const [openHk, setOpenHk] = useState<{ hk: HostKeyInfo; dev: string; cred: string; user: string; hostId?: string; startup: string } | null>(null);
  const [note, setNote] = useState<"" | "nosession" | "noconfig">(""); // aviso de un script que no se pudo insertar
  const [pins, setPins] = useState<ScriptItem[]>([]); // scripts fijados (hasta 5, en su orden), junto a los comandos rápidos
  const sv = useScriptsVersion(); // los scripts cambiaron: volver a listar los fijados
  const [busy, setBusy] = useState(false);
  const [find, setFind] = useState<FindReq>({ q: "", dir: 1, n: 0 });
  const [hits, setHits] = useState({ index: -1, count: 0 });
  const { palette, hl, srm } = useTermPrefs();
  const lang = useLang();
  const pal = useMemo(() => PALETTES.find((x) => x.id === palette) ?? PALETTES[0], [palette]);
  const theme = useMemo(() => xtermTheme(pal), [pal]);
  const palRef = useRef(hl ? pal : null);
  palRef.current = hl ? pal : null;
  const [logPick, setLogPick] = useState(""); // archivo de registro elegido en el formulario (opcional)
  const logs = useRef(new Map<string, LogState>());
  const writers = useRef(new Map<string, ReturnType<typeof createLiveWriter>>());
  const [split, setSplit] = useState(false);
  const [secondKey, setSecondKey] = useState(0);
  const [focusKey, setFocusKey] = useState(0); // último panel en el que se hizo clic o tomó el foco
  const logId = useId();
  const texts = useRef(new Map<string, string>()); // salida limpia por sesión, solo para «Descargar sesión»
  const sinks = useRef(new Map<string, (d: string) => void>()); // escritura de cada emulador
  const waiting = useRef(new Map<string, string[]>()); // salida que llegó antes de que el emulador (carga diferida) existiera
  const size = useRef(estimate());
  useInbox("terminal", setDevice); // «Abrir SSH» del menú de equipo trae la dirección
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [active, setActive] = useState(0);
  const tabsRef = useRef<Tab[]>([]);
  tabsRef.current = tabs;
  const keySeq = useRef(0);
  const early = useRef(new Map<string, TerminalEvent[]>()); // eventos que llegan antes de conocer el id
  const closed = useRef(new Set<string>()); // pestañas cerradas por la persona: sus eventos tardíos se descartan
  const newRef = useRef<HTMLDetailsElement>(null); // formulario de sesión nueva, plegado cuando ya hay pestañas
  const winRef = useRef<HTMLDivElement>(null);
  const vv = useVaultVersion(); // la bóveda cambió: volver a listar credenciales
  useEffect(() => {
    let live = true;
    core.listPinnedScripts().then((l) => { if (live) setPins(l.filter((x) => scriptText(x.commands))); }, () => { if (live) setPins([]); });
    return () => { live = false; };
  }, [core, sv]);
  useEffect(() => { core.listCredentials().then((l) => { setCreds(l); const pw = passwordCreds(l); setCred((c) => (pw.some((x) => x.id === c) ? c : pw[0]?.id ?? "")); }).catch(() => { setCreds([]); setCred(""); }); }, [core, vv]); // bóveda cerrada: sin lista ni credencial elegida
  // Lo que ve la persona manda: una credencial que ya no está en la lista (bóveda cerrada) cuenta como «Escribir…».
  const credOk = passwordCreds(creds).some((c) => c.id === cred) ? cred : "";

  const patch = (runId: string, f: (t: Tab) => Tab) => setTabs((ts) => ts.map((t) => (t.runId === runId ? f(t) : t)));
  const apply = (e: TerminalEvent) => {
    if (e.done) {
      writers.current.get(e.runId)?.flush();
      saveLog(e.runId);
      if (e.errorInfo?.reason === "terminal.err.startup_changed") hostsChanged(); // volver a leer los hosts: reintentar usa la orden nueva
      patch(e.runId, (t) => ({ ...t, ask: undefined, done: true, status: { k: "ssh.closed" }, err: e.error ? errorText(new Error(e.error)) : t.err, errInfo: e.error ? errInfo({ cause: e.errorInfo }) : t.errInfo }));
    } else if (e.prompts) {
      const ask = { seq: e.seq ?? 0, name: e.name ?? "", instruction: e.instruction ?? "", prompts: e.prompts };
      patch(e.runId, (t) => ({ ...t, ask }));
    } else if (e.opened) {
      patch(e.runId, (t) => ({ ...t, ask: undefined, status: { k: t.proto === "telnet" ? "ssh.connectedTelnet" : "ssh.connected", v: { port: e.opened ?? "", path: e.recording ?? "" } } }));
    } else if (e.data) {
      const d = e.data;
      texts.current.set(e.runId, cleanTerminal(texts.current.get(e.runId) ?? "", d, logs.current.has(e.runId) ? LOG_MAX : undefined));
      let lw = writers.current.get(e.runId);
      if (!lw) {
        const id = e.runId;
        lw = createLiveWriter((x) => { const w = sinks.current.get(id); if (w) w(x); else waiting.current.set(id, [...(waiting.current.get(id) ?? []), x]); }, () => palRef.current);
        writers.current.set(id, lw);
      }
      lw.push(d);
    }
  };
  // Escribe el texto limpio en el archivo elegido (overwrite: la persona ya lo eligió). Las escrituras de una sesión van en cadena.
  const saveLog = (runId: string) => {
    const L = logs.current.get(runId);
    if (!L) return;
    const text = texts.current.get(runId) ?? "";
    if (text === L.last) return; // nada nuevo desde la última escritura (también en la final)
    L.chain = L.chain.then(() => core.writeFile(L.path, text, "utf8", true)).then(
      () => { L.last = text; patch(runId, (t) => ({ ...t, logAt: new Date(), logErr: "" })); },
      // Si la pestaña ya se cerró (la escritura final), el error va al aviso general: es cuando más importa verlo.
      (e) => (tabsRef.current.some((t) => t.runId === runId) ? patch(runId, (t) => ({ ...t, logErr: errorText(e) })) : setErr(t("ssh.logFinalError", { path: L.path, error: errorText(e) }))),
    );
  };
  const saveRef = useRef(saveLog);
  saveRef.current = saveLog;
  const applyRef = useRef(apply);
  applyRef.current = apply;
  useEffect(() => core.onTerminal((e) => {
    if (tabsRef.current.some((t) => t.runId === e.runId)) applyRef.current(e);
    else if (closed.current.has(e.runId)) { if (e.done) closed.current.delete(e.runId); } // el done es lo último que manda el núcleo
    else early.current.set(e.runId, [...(early.current.get(e.runId) ?? []), e]);
  }), [core]);
  // Registro en archivo: cada 30 s mientras la sesión vive, y una última escritura al salir de la ventana o del módulo.
  useEffect(() => {
    const id = setInterval(() => tabsRef.current.forEach((t) => { if (!t.done) saveRef.current(t.runId); }), LOG_EVERY);
    const last = () => tabsRef.current.forEach((t) => saveRef.current(t.runId));
    window.addEventListener("beforeunload", last);
    const off = core.onClosing(last); // WebKitGTK no garantiza beforeunload al destruir la ventana
    return () => { clearInterval(id); window.removeEventListener("beforeunload", last); off(); };
  }, [core]);
  // Al salir del módulo no queda ninguna sesión abierta: cada pestaña viva se cierra en el núcleo.
  useEffect(() => () => {
    tabsRef.current.forEach((t) => { writers.current.get(t.runId)?.dispose(); saveRef.current(t.runId); });
    tabsRef.current.filter((t) => t.runId && !t.done).forEach((t) => { core.terminalClose(t.runId).catch(() => {}); });
  }, [core]);
  const cur = tabs[active];
  const bind = (runId: string, write: ((d: string) => void) | null) => {
    if (!write) { sinks.current.delete(runId); return; }
    sinks.current.set(runId, write);
    (waiting.current.get(runId) ?? []).forEach(write);
    waiting.current.delete(runId);
  };

  // Reintentar tras aceptar una huella usa el equipo y la credencial de la pestaña que falló, no lo que hay hoy en los campos.
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  // hostId: conexión de un clic a un host guardado; el núcleo pone dirección, puerto, credencial y orden de inicio (la UI no los manda).
  // usr solo lo pasa quien sabe que el host no tiene credencial (modo tecleado); con credencial va vacío o el núcleo lo rechaza.
  const open = async (accepted = accept, dev = device, credId = cred, hostId?: string, startup = "", usr = user, keys: AcceptedKey[] = [], pr = proto) => {
    // Dos sesiones vivas en el mismo archivo se pisarían cada 30 s.
    if (logPick && tabsRef.current.some((x) => !x.done && x.logPath === logPick)) { setOpenHk(null); setErr(t("ssh.logInUse")); return; }
    setErr(""); setOpenHk(null); setBusy(true);
    try {
      const label = dev.trim();
      const tg = parseTarget(parseTargets(dev)[0] ?? "");
      const base = { name: label, accept: parseFingerprints(accepted), ...(keys.length ? { acceptedKeys: keys } : {}), rows: size.current.rows, cols: size.current.cols };
      const runId = await core.terminalOpen(hostId && pr === "telnet" ? { name: label, accept: [], rows: size.current.rows, cols: size.current.cols, hostId } : pr === "telnet" ? { name: label, accept: [], rows: size.current.rows, cols: size.current.cols, protocol: "telnet", address: tg.address, port: tg.port, credentialId: credId } : hostId ? { ...base, hostId, expectedStartupCommand: startup, ...(usr.trim() ? { username: usr.trim() } : {}) } : { ...base, address: tg.address, port: tg.port, credentialId: credId, ...(credId ? {} : { username: usr.trim() }) });
      if (!alive.current) { core.terminalClose(runId).catch(() => {}); return; } // la vista se fue con la apertura en vuelo: no queda huérfana
      const tab: Tab = { key: ++keySeq.current, label, device: dev, cred: credId, user: usr, hostId, startup, proto: pr, runId, status: { k: "ssh.connecting" }, err: "", done: false, logPath: logPick, logAt: null, logErr: "" };
      if (logPick) { logs.current.set(runId, { path: logPick, last: "", chain: Promise.resolve() }); setLogPick(""); } // el archivo es de esta sesión, no de las siguientes
      // La pestaña se registra ya (no al renderizar) para que ningún evento se quede sin dueño.
      tabsRef.current = [...tabsRef.current, tab];
      setActive(tabsRef.current.length - 1);
      setNote("");
      setTabs((ts) => [...ts, tab]);
      const pending = early.current.get(runId) ?? [];
      early.current.delete(runId);
      pending.forEach((e) => applyRef.current(e)); // las actualizaciones se encolan después de agregar la pestaña
      if (newRef.current) newRef.current.open = false;
    } catch (e) {
      const hk = hostKeyFromError(errorText(e), errInfo(e));
      if (hk && pr === "ssh") setOpenHk({ hk, dev, cred: credId, user: usr, hostId, startup });
      else setErr(errorText(e));
    } finally { setBusy(false); }
  };
  // Las llamadas del puente no garantizan orden de llegada: por sesión hay un solo envío en vuelo y lo que se teclea mientras
  // tanto se junta y sale en una sola llamada al terminar el anterior.
  const sendQ = useRef(new Map<string, { busy: boolean; buf: string }>());
  const send = (runId: string, data: string) => {
    const q = sendQ.current.get(runId) ?? { busy: false, buf: "" };
    sendQ.current.set(runId, q);
    if (q.busy) { q.buf += data; return; }
    q.busy = true;
    const go = (d: string) => core.terminalSend(runId, d).catch((e) => { if (sendQ.current.get(runId) === q) setErr(errorText(e)); }).then(() => {
      if (sendQ.current.get(runId) !== q) return; // la pestaña se cerró: lo acumulado ya no tiene destino
      if (q.buf) { const n = q.buf; q.buf = ""; go(n); } else q.busy = false;
    });
    go(data);
  };
  // Respuesta a una pregunta del equipo: el panel entrega las respuestas y aquí solo se mandan; el estado de la pestaña pierde
  // la pregunta en el mismo handler (el panel se desmonta) y las respuestas no se guardan en ninguna parte.
  const answer = (runId: string, seq: number, answers: string[]) => {
    patch(runId, (t) => ({ ...t, ask: undefined }));
    // El error del puente no se pinta: un núcleo descuidado podría reflejar lo recibido. La razón real llega por el evento done.
    core.terminalAnswer(runId, seq, answers).catch(() => patch(runId, (x) => ({ ...x, err: x.err || t("ssh.auth.sendFail") })));
  };
  const closeTab = (i: number) => {
    const t = tabs[i];
    sendQ.current.delete(t.runId);
    if (!t.done) closed.current.add(t.runId);
    writers.current.get(t.runId)?.dispose(); writers.current.delete(t.runId);
    saveLog(t.runId); logs.current.delete(t.runId);
    texts.current.delete(t.runId); waiting.current.delete(t.runId);
    if (t.runId && !t.done) core.terminalClose(t.runId).catch(() => {});
    setTabs((ts) => ts.filter((_, j) => j !== i));
    if (tabs.length <= 2) setSplit(false); // con una sola pestaña no hay división: la próxima sesión no se divide sola
    setActive((a) => Math.max(0, i < a || a >= tabs.length - 1 ? a - 1 : a));
  };

  // Como en un emulador de terminal de escritorio, la terminal ocupa todo el alto que queda visible: alto del área con scroll menos lo que hay encima,
  // debajo y el marco de la ventana (pestañas y línea de estado). Se recalcula al cambiar la ventana o lo que hay encima.
  const hasTabs = tabs.length > 0;
  useLayoutEffect(() => {
    const w = winRef.current;
    if (!w) return;
    let box = w.parentElement;
    while (box && !/(auto|scroll)/.test(getComputedStyle(box).overflowY)) box = box.parentElement;
    const sc = box ?? document.documentElement;
    const fill = () => {
      const x = w.querySelector<HTMLElement>(".ssh-pane:not([hidden]) .ssh-xterm");
      if (!x) return;
      const top = w.getBoundingClientRect().top - (box ? sc.getBoundingClientRect().top : 0) + sc.scrollTop;
      // Lo que va debajo se mide (resto de la página y el relleno del área), no con scrollHeight: si la página es más corta que
      // la pantalla, scrollHeight cuenta el hueco vacío y la terminal solo podría encogerse.
      const page = w.closest(".page") ?? w.parentElement ?? w;
      const below = page.getBoundingClientRect().bottom - w.getBoundingClientRect().bottom + parseFloat(getComputedStyle(sc).paddingBottom || "0");
      let h = Math.max(320, Math.floor(sc.clientHeight - top - below - (w.offsetHeight - x.offsetHeight)));
      w.style.setProperty("--ssh-xh", `${h}px`);
      // Márgenes que quedan fuera de la caja de la página (colapsados) no se ven arriba: si aún sobra, se quita lo que sobra.
      const over = sc.scrollHeight - sc.clientHeight;
      if (over > 0 && h > 320) { h = Math.max(320, h - over); w.style.setProperty("--ssh-xh", `${h}px`); }
    };
    fill();
    const ro = new ResizeObserver(fill);
    ro.observe(sc);
    if (w.parentElement) ro.observe(w.parentElement);
    return () => ro.disconnect();
  }, [hasTabs]);

  // En pantalla dividida, el panel derecho es otra pestaña; sus herramientas (búsqueda, descarga, comandos) siguen al panel con el foco.
  const others = cur ? tabs.filter((x) => x.key !== cur.key) : [];
  const second = split ? others.find((x) => x.key === secondKey) ?? others[0] : undefined;
  const tool = second && focusKey === second.key ? second : cur;

  // Inserta un script en una sesión SIN Enter final (la persona decide si lo ejecuta). Varias líneas: las intermedias se ejecutarían
  // al llegar, así que solo van las de solo lectura y con la misma confirmación que el pegado; las de configuración se copian y se avisa
  // (ADR 0007: la app no aplica configuración fuera del modo asistido). Sin sesión viva no se pierde en silencio: aviso, y no queda pendiente.
  // Devuelve true solo si el texto se envió a la sesión; con false (copiado, sin sesión o rechazado) el menú recupera el foco.
  const insert = async (tab: Tab | undefined, ins: Insert): Promise<boolean> => {
    setNote("");
    if (!ins.text) return false;
    const multi = ins.text.includes("\n");
    if (multi && !ins.readOnly) { void core.copyText(ins.text).catch(() => {}); setNote("noconfig"); return false; }
    if (!tab || tab.done) { setNote("nosession"); return false; }
    if (multi && !(await core.confirmPaste(ins.text, tab.label, ins.name))) return false;
    if (!tabsRef.current.some((x) => x.runId === tab.runId && !x.done)) return false; // se cerró mientras se confirmaba
    // Ctrl+U borra la línea en el prompt de IOS, IOS-XE y NX-OS: si había algo a medio teclear, el script no se le pega detrás.
    send(tab.runId, "\x15" + ins.text.replace(/\r?\n/g, "\r"));
    // El foco va al emulador de la pestaña destino (con pantalla dividida no es el primero del DOM).
    requestAnimationFrame(() => document.querySelector<HTMLElement>(`.ssh-pane[data-key="${tab.key}"] .xterm-helper-textarea`)?.focus());
    return true;
  };
  useInbox("terminal-insert", (data) => { const ins = decodeInsert(data); if (ins) void insert(tool, ins); }); // «Enviar a la terminal» de Scripts

  // Huella nueva o cambiada: el aviso compartido (HostKeyTrust) la muestra con la orden para compararla y entrega el par {host, huella}
  // del destino, nunca lo del campo de huellas ni respuestas. Con un host guardado la UI no conoce la dirección: sirve la que informó el
  // núcleo; sin host el botón queda deshabilitado (falla cerrado). Dividida, el aviso no toma el foco: se teclea en el otro panel.
  const hostKeyNotice = (hk: HostKeyInfo, dev: string, hostId: string | undefined, retry: (keys: AcceptedKey[]) => void) => {
    const host = hostId ? hk.host : hostOfTarget(parseTarget(parseTargets(dev)[0] ?? ""));
    return <HostKeyTrust key={hk.fp} items={[{ ...hk, host }]} busy={busy} onTrust={retry} autoFocus={!second} />;
  };
  // Estado de una sesión: conexión, registro en archivo y avisos. Solo, arriba; dividida, en la cabecera de cada panel.
  const head = (tab: Tab) => {
    const hk = tab.err && tab.proto === "ssh" ? hostKeyFromError(tab.err, tab.errInfo) : null;
    const changedStartup = tab.errInfo?.reason === "terminal.err.startup_changed"; // el host se editó (o un import cambió la orden) tras mostrarla
    return (
      <>
        {tab.logErr && <Notice kind="error">{t("ssh.logError", { path: tab.logPath, error: tab.logErr })}</Notice>}
        {tab.err && <Notice kind="error">{tab.err}</Notice>}
        {changedStartup && <Notice kind="warn">{t("ssh.startupChanged")}</Notice>}
        {hk && hostKeyNotice(hk, tab.device, tab.hostId, (keys) => { void open(accept, tab.device, tab.cred, tab.hostId, tab.startup, tab.user, keys, tab.proto); })}
      </>
    );
  };
  // Línea de estado bajo la terminal: punto y estado de la conexión, sesión y registro en archivo.
  const statusLine = (tab: Tab) => (
    <div className="ssh-status" data-state={stateOf(tab)}>
      <span className="ssh-dot" aria-hidden="true" />
      <span className="ssh-state">{t(tab.status.k, tab.status.v)}</span>
      {tab.logPath && (
        <span className="ssh-log"><span className="ssh-rec" aria-hidden="true" />{t("ssh.logging", { path: tab.logPath })} · {tab.logAt ? t("ssh.loggedAt", { time: tab.logAt.toLocaleTimeString(lang) }) : t("ssh.logWaiting")}</span>
      )}
    </div>
  );
  // Sin credencial de contraseña a la vista (llave, sin credencial o bóveda cerrada) se abre por hostId y el núcleo decide; el usuario solo viaja si su campo se ve.
  const shownUser = proto === "ssh" && (typed || !credOk) ? user : "";
  const form = (
    <>
      {/* Cada host abre con su propio protocolo (lo pone el núcleo): la lista sirve aunque el formulario manual esté en Telnet. */}
      <SavedHosts core={core} creds={creds} busy={busy} onConnect={(h) => { void open("", h.name, "", h.id, h.startCommand, h.credentialId || h.protocol === "telnet" ? "" : shownUser, [], h.protocol === "telnet" ? "telnet" : "ssh"); }} />
      <HostPicker core={core} disabled={busy} onPick={(h) => { if (h.protocol === "telnet" || !passwordCreds(creds).some((c) => c.id === h.credentialId)) { void open("", h.name, "", h.id, h.startCommand, h.credentialId || h.protocol === "telnet" ? "" : shownUser, [], h.protocol === "telnet" ? "telnet" : "ssh"); return; } setProto("ssh"); setOpenHk(null); setDevice(targetOf(h)); setCred(h.credentialId); setTyped(false); }} />
      <div className="field-row">
        <Select label={t("ssh.proto")} value={proto} onChange={(v) => { setProto(v); setOpenHk(null); if (v === "telnet") setTyped(true); }} w="sm" options={[["ssh", "SSH"], ["telnet", "Telnet"]]} />
        {<Select label={t("ssh.cred")} value={typed || !credOk ? TYPED : credOk} onChange={(v) => { setTyped(v === TYPED); if (v !== TYPED) setCred(v); }} w="md" options={[...passwordCreds(creds).map((c) => [c.id, `${c.label} (${c.username})`] as [string, string]), [TYPED, t("ssh.credTyped")] as [string, string]]} />}
        {proto === "ssh" && (typed || !credOk) && <Field label={t("ssh.user")} hint={t("ssh.userHint")} value={user} onChange={setUser} w="md" mono />}
        <Field label={t("ssh.device")} hint={t("ssh.portDefault", { port: proto === "telnet" ? "23" : "22" })} value={device} onChange={setDevice} w="lg" mono />
        {proto === "ssh" && <Field label={t("fps.accepted.short")} hint={t("fps.accepted.hint")} value={accept} onChange={setAccept} w="md" mono />}
      </div>
      {proto === "telnet" && <Notice kind="warn">{t("ssh.telnetWarn")}{!typed && credOk ? " " + t("ssh.telnetCredWarn") : ""}</Notice>}
      <div className="field ssh-logpick" data-w="lg">
        <label htmlFor={logId}>{t("ssh.logTo")}</label>
        <div className="path">
          <input id={logId} readOnly value={logPick} placeholder={t("ssh.logNone")} aria-describedby={`${logId}-h`} />
          <button type="button" onClick={async () => { const p = await core.pickSavePath(`${fileBase(device.trim() || "sesion")}-${stamp(new Date())}.log`); if (p) setLogPick(p); }}>{t("ssh.logPick")}</button>
          {logPick && <button type="button" className="quiet" onClick={() => setLogPick("")}>{t("ssh.logClear")}</button>}
        </div>
        <p id={`${logId}-h`} className="hint">{t("ssh.logHelp")}</p>
      </div>
      <div className="actions">
        <button className="primary" disabled={busy || !device.trim()} aria-busy={busy} onClick={() => open(accept, device, typed ? "" : credOk, undefined, "", typed || !credOk ? user : "", [], proto)}>
          {busy ? t("ssh.connectingBtn") : <>{t("ssh.openTab")}<kbd aria-hidden="true">Ctrl ↵</kbd></>}
        </button>
      </div>
    </>
  );
  return (
    <Page title={t("ssh.title")} description={t("ssh.desc")}>
      {!hasTabs && <Notice kind="warn">{t("ssh.note")}</Notice>}
      {/* Sin sesiones, el formulario a la vista; con sesiones se pliega en una línea y la terminal se queda con la pantalla. */}
      {!hasTabs ? <Section title={t("ssh.new")}>{form}</Section> : <details ref={newRef} className="ssh-new"><summary>{t("ssh.new")}</summary>{form}</details>}
      {err && <Notice kind="error">{err}</Notice>}
      {openHk && hostKeyNotice(openHk.hk, openHk.dev, openHk.hostId, (keys) => { void open(accept, openHk.dev, openHk.cred, openHk.hostId, openHk.startup, openHk.user, keys, "ssh"); })}
      {note && <Notice kind="warn">{t(note === "nosession" ? "ssh.scriptNoSession" : "scripts.noSend")}</Notice>}
      {tabs.length === 0 && <EmptyState icon="terminal" title={t("ssh.empty.title")}>{t("ssh.empty")}</EmptyState>}
      {cur && !second && head(cur)}
      {cur && (
        <>
          <div className="ssh-tools">
            <SessionSearch q={find.q} onQ={(q) => { setFind((f) => ({ q, dir: 1, n: f.n + 1 })); if (!q) setHits({ index: -1, count: 0 }); }} onStep={(dir) => setFind((f) => ({ ...f, dir, n: f.n + 1 }))} index={hits.index} count={hits.count} />
            <div className="ssh-opts">
              <ViewMenu split={tabs.length > 1 ? { checked: !!second, onChange: setSplit } : undefined} />
              {second && <Select label={t("ssh.splitSecond")} value={String(second.key)} onChange={(v) => setSecondKey(Number(v))} w="md" options={others.map((x) => [String(x.key), x.label] as [string, string])} />}
              <DownloadButton label={t("ssh.download")} name={`${fileBase(tool.label)}-${new Date().toISOString().slice(0, 10)}.txt`} data={() => texts.current.get(tool.runId) ?? ""} />
            </div>
          </div>
          <div className="ssh-quick" role="group" aria-label={t("ssh.quick")}>
            {QUICK.map((c) => <button key={c} className="sm mono" disabled={tool.done} onClick={() => send(tool.runId, c + "\r")}>{c}</button>)}
            {pins.map((x) => {
              const copy = needsCopy(x); // configuración de varias líneas: se copia, no se envía
              return (
                <button key={x.id} className="sm mono ssh-fav" disabled={!copy && tool.done} title={scriptText(x.commands)} aria-label={t(copy ? "ssh.scriptCopy" : "ssh.scriptFav", { name: x.name })}
                  onClick={() => { void insert(tool, { name: x.name, text: scriptText(x.commands), readOnly: x.readOnly }); }}><Icon name={copy ? "copy" : "pin"} size={12} />{x.name}</button>
              );
            })}
            <ScriptsMenu core={core} version={sv} onPick={(x) => insert(tool, { name: x.name, text: scriptText(x.commands), readOnly: x.readOnly })} />
          </div>
        </>
      )}
      {tabs.length > 0 && (
        // Ventana de terminal: barra de pestañas, emulador y línea de estado con los colores de la paleta elegida.
        <div ref={winRef} className="ssh-window" style={{ "--term-bg": theme.background, "--term-fg": theme.foreground } as CSSProperties}>
          <div role="tablist" aria-label={t("ssh.sessions")} className="tabs ssh-tabs">
            {tabs.map((tab, i) => (
              <span key={tab.key} className="ssh-tab" data-state={stateOf(tab)}>
                <button role="tab" aria-selected={i === active} onClick={() => setActive(i)}><span className="ssh-dot" aria-hidden="true" />{tab.label}{tab.done ? t("ssh.closedTab") : ""}</button>
                <button className="quiet sm icon" aria-label={t("ssh.closeTab", { label: tab.label })} onClick={() => closeTab(i)}><Icon name="close" size={14} /></button>
              </span>
            ))}
          </div>
          {cur && (
            <div role="tabpanel" aria-label={t("ssh.session", { label: cur.label })} className="ssh-session">
              <div className={second ? "ssh-terms split" : "ssh-terms"} style={second ? undefined : { background: theme.background }}>
                <Suspense fallback={null}>
                  {tabs.map((tab, i) => {
                    // Cada sesión tiene su emulador una sola vez: dividir solo cambia dónde se coloca (y no lo recrea).
                    const side = tab.key === second?.key ? "right" : "left";
                    const shown = i === active || tab.key === second?.key;
                    return (
                      <div key={tab.key} hidden={!shown} data-key={tab.key} className={`ssh-pane ${side}`} onFocus={() => setFocusKey(tab.key)} onMouseDown={() => setFocusKey(tab.key)}>
                        {second && shown && <div className="ssh-pane-head"><strong>{tab.label}</strong>{head(tab)}</div>}
                        {tab.ask && <AuthPanel key={`${tab.runId}:${tab.ask.seq}`} prompt={tab.ask} label={tab.label} active={second ? tab.key === tool.key : i === active} onAnswer={(seq, a) => answer(tab.runId, seq, a)} />}
                        <div className="ssh-term" style={second ? { background: theme.background } : undefined}>
                          <XTermPane runId={tab.runId} screenReader={srm} onCopy={(x) => { void core.copyText(x).catch(() => {}); }} onPaste={async (given) => { const txt = given ?? await core.pasteText(); return pasteNeedsConfirm(txt) && !(await core.confirmPaste(txt, tab.label)) ? "" : txt; }} active={i === active} focus={second ? tab.key === tool.key : i === active} asking={!!tab.ask} shown={shown} done={tab.done} theme={theme} search={tab.key === tool.key ? find : undefined}
                            label={second && shown ? t(side === "left" ? "ssh.pane.left" : "ssh.pane.right", { label: tab.label }) : undefined}
                            bind={bind} onInput={(d) => send(tab.runId, d)} onResults={(index, count) => { if (tab.key === tool.key) setHits({ index, count }); }}
                            onSize={(rows, cols) => { size.current = { rows, cols }; core.terminalResize(tab.runId, rows, cols).catch(() => {}); }}
                            onLeave={() => document.querySelector<HTMLElement>('.ssh-tabs [role="tab"][aria-selected="true"]')?.focus()} />
                        </div>
                        {shown && statusLine(tab)}
                      </div>
                    );
                  })}
                </Suspense>
              </div>
            </div>
          )}
        </div>
      )}
      {cur && <p className="meta">{t("ssh.termHint")}</p>}
    </Page>
  );
}
