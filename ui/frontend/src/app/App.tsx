import { Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { CoreAPI, CoreStatus } from "../lib/core";
import { BusyContext, CoreContext, ModuleIdContext, NavContext, type Delivery } from "./activity";
import { groups, modules } from "../modules";
import { Sidebar } from "./Sidebar";
import { StatusBar } from "./StatusBar";
import { CommandPalette, rememberRecent, type PaletteAction } from "./CommandPalette";
import { ShortcutsDialog } from "./ShortcutsDialog";
import { assistOwner, useShellStatus } from "./useShellStatus";
import { Icon } from "../components/Icon";
import { I18nProvider, useSetLang, useT } from "../lib/i18n";
import { setTheme } from "../lib/theme";
import { vaultChanged } from "../lib/vaultSignal";

// `chrome` son los controles de la ventana sin marco; las pruebas no los necesitan.
// `initial` abre otro módulo al arrancar (vista previa y capturas).
export function App(props: { core: CoreAPI; chrome?: ReactNode; initial?: string }) {
  // El núcleo habla el idioma de la interfaz; un fallo al avisarle no debe romper nada.
  const sync = (l: string) => { try { void Promise.resolve(props.core.setPreference("ui.language", l)).catch(() => {}); } catch { /* núcleo sin la preferencia */ } };
  return <I18nProvider onLang={sync}><Shell {...props} /></I18nProvider>;
}

const collapsedKey = "macuahuitl.barra-contraida";
const readCollapsed = () => { try { return localStorage.getItem(collapsedKey) === "1"; } catch { return false; } };

function Shell({ core, chrome, initial }: { core: CoreAPI; chrome?: ReactNode; initial?: string }) {
  const t = useT();
  const setLang = useSetLang();
  const [status, setStatus] = useState<CoreStatus>("connected");
  const start = modules.some((m) => m.id === initial) ? initial! : modules[0].id;
  const [current, setCurrent] = useState(start);
  // Un módulo visitado se queda montado (oculto) para no perder su salida ni sus tareas en vivo.
  const [visited, setVisited] = useState(() => new Set([start]));
  const [busy, setBusy] = useState<Set<string>>(new Set());
  const busySetters = useRef(new Map<string, (b: boolean) => void>());
  const [inbox, setInbox] = useState<Record<string, Delivery>>({});
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const [palette, setPalette] = useState(false);
  const [shortcuts, setShortcuts] = useState(false);
  const history = useRef({ back: [] as string[], fwd: [] as string[] });
  const shell = useShellStatus(core);
  // Marca de rendimiento: el shell ya está montado (la mide la prueba de presupuestos en WebKitGTK).
  useEffect(() => { performance.mark("macuahuitl:shell"); }, []);


  const recheck = useCallback(() => { core.coreStatus().then(setStatus).catch(() => setStatus("disconnected")); }, [core]);
  useEffect(() => {
    const off = core.onStatus(setStatus);
    recheck(); // el primer core:status pudo salir antes de que existiera la ventana
    return off;
  }, [core, recheck]);

  const busySetter = (id: string) => {
    let f = busySetters.current.get(id);
    if (!f) {
      f = (b) => setBusy((s) => {
        if (s.has(id) === b) return s;
        const n = new Set(s);
        if (b) n.add(id); else n.delete(id);
        return n;
      });
      busySetters.current.set(id, f);
    }
    return f;
  };
  const show = (id: string) => {
    setCurrent(id);
    setVisited((v) => (v.has(id) ? v : new Set(v).add(id)));
    rememberRecent(id);
  };
  const currentRef = useRef(current);
  currentRef.current = current;
  const select = useCallback((id: string) => {
    if (currentRef.current !== id) { history.current.back.push(currentRef.current); history.current.fwd = []; }
    show(id);
  }, []);
  const step = (dir: "back" | "fwd") => {
    const h = history.current;
    const to = (dir === "back" ? h.back : h.fwd).pop();
    if (!to) return;
    (dir === "back" ? h.fwd : h.back).push(current);
    show(to);
  };
  const go = useCallback((id: string, data?: string, channel = id) => {
    if (data !== undefined) setInbox((b) => ({ ...b, [channel]: { data, n: (b[channel]?.n ?? 0) + 1 } }));
    select(id);
  }, [select]);
  // Valor estable: si no, cada render del shell vuelve a renderizar todas las vistas montadas que usan useNav.
  const nav = useMemo(() => ({ go, inbox }), [go, inbox]);
  const toggleSidebar = useCallback(() => setCollapsed((c) => {
    try { localStorage.setItem(collapsedKey, c ? "0" : "1"); } catch { /* sin persistencia */ }
    return !c;
  }), []);

  // Atajos globales (ADR 0009 §3). Ctrl+Enter nunca actúa dentro del modo asistido.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.target as Element | null)?.closest?.(".xterm")) return; // en una terminal SSH todas las teclas son del equipo; se sale con Ctrl+Mayús+K
      if (document.querySelector(".dialog[aria-modal=true]")) return; // con una ventana de detalles abierta no corren los atajos de la app
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
      else if (mod && e.key.toLowerCase() === "b") { e.preventDefault(); toggleSidebar(); }
      else if (mod && e.key === "/") { e.preventDefault(); setShortcuts(true); }
      else if (e.altKey && (e.key === "ArrowLeft" || e.key === "ArrowRight")) { e.preventDefault(); step(e.key === "ArrowLeft" ? "back" : "fwd"); }
      else if (mod && e.key === "Enter") {
        // Ya lo atendió alguien (la paleta abre el módulo con Enter) o hay un diálogo encima: no se ejecuta nada.
        if (e.defaultPrevented || document.querySelector("[aria-modal=true]")) return;
        const view = document.querySelector(".view:not([hidden])");
        if (!view || view.querySelector("[data-assist]")) return;
        // Un primario dentro de un <details> plegado no está a la vista: no se dispara sin que la persona lo vea.
        const pick = (root: Element | null | undefined) => [...(root?.querySelectorAll<HTMLButtonElement>("button.primary:not(:disabled):not(.danger), button[type=submit]:not(:disabled):not(.danger)") ?? [])].find((b) => !b.closest("details:not([open]), [hidden]")); // ni plegado ni en un panel oculto (p. ej. la otra pestaña de Transferencias)
        // Primero el primario de la sección o el formulario donde está el foco; si no hay, el de la vista.
        const near = document.activeElement?.closest("form, section:not(.page)");
        const b = (near && view.contains(near) && pick(near)) || pick(view);
        if (b) { e.preventDefault(); b.click(); }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  });

  const actions: PaletteAction[] = useMemo(() => [
    { id: "theme-dark", labelKey: "shell.action.themeDark", icon: "theme", run: () => setTheme("dark") },
    { id: "theme-light", labelKey: "shell.action.themeLight", icon: "theme", run: () => setTheme("light") },
    { id: "theme-system", labelKey: "shell.action.themeSystem", icon: "theme", run: () => setTheme("system") },
    { id: "lang-es", labelKey: "shell.action.langEs", icon: "command", run: () => setLang("es") },
    { id: "lang-en", labelKey: "shell.action.langEn", icon: "command", run: () => setLang("en") },
    { id: "sidebar", labelKey: "shell.action.sidebar", icon: "sidebar", keys: "Ctrl B", run: toggleSidebar },
    { id: "lock", labelKey: "shell.action.lockVault", icon: "lock", run: () => { core.vaultLock().then(vaultChanged, () => {}); } },
    { id: "shortcuts", labelKey: "shell.action.shortcuts", icon: "keyboard", keys: "Ctrl /", run: () => setShortcuts(true) },
  ], [core, setLang, toggleSidebar]);

  const mod = modules.find((m) => m.id === current)!;
  const assist = shell.assist;
  const owner = assist ? assistOwner(assist.runId) : "";
  const devices = assist?.devices?.length ?? 0;

  return (
    <CoreContext.Provider value={core}>
    <div className="app" data-collapsed={collapsed}>
      <Sidebar current={current} busy={busy} onSelect={select} collapsed={collapsed} onToggle={toggleSidebar} />
      <div className="main">
        <div className="titlebar">
          <nav className="crumb" aria-label={t("shell.where")}>
            {mod.group && <>{t(groups[mod.group].label)}<span className="sep" aria-hidden="true">›</span></>}<b>{t(mod.label)}</b>
          </nav>
          <button className="search-trigger" onClick={() => setPalette(true)}>
            <Icon name="search" /><span>{t("shell.search")}</span><kbd>Ctrl K</kbd>
          </button>
          <div className="titlebar-end">{chrome}</div>
        </div>
        {assist && (
          <div className="assist-strip" role="alert">
            <Icon name="alert" />
            {devices ? t("shell.assist.strip", { n: devices }) : t("shell.assist.strip.any")}
            {owner && <button className="sm" onClick={() => go(owner)}>{t("shell.assist.go")}</button>}
          </div>
        )}
        <div className="content">
          {status === "disconnected" && (
            <div role="alert" className="notice error">
              <Icon name="error" /><div className="notice-body">{t("shell.coreDown")} <code>systemctl --user status macuahuitld</code></div>
            </div>
          )}
          <NavContext.Provider value={nav}>
            <main>
              {modules.filter((m) => visited.has(m.id)).map((m) => (
                <div key={m.id} className="view" hidden={m.id !== current}>
                  <ModuleIdContext.Provider value={m.id}>
                    <BusyContext.Provider value={busySetter(m.id)}><Suspense fallback={<Loading />}>{m.view(core)}</Suspense></BusyContext.Provider>
                  </ModuleIdContext.Provider>
                </div>
              ))}
            </main>
          </NavContext.Provider>
        </div>
      </div>
      <StatusBar core={status} shell={shell} busy={[...busy]} onGo={go} onRecheck={recheck} onShortcuts={() => setShortcuts(true)} />
      {palette && <CommandPalette onGo={go} onClose={() => setPalette(false)} actions={actions} />}
      {shortcuts && <ShortcutsDialog onClose={() => setShortcuts(false)} />}
    </div>
    </CoreContext.Provider>
  );
}

// Mientras llega el código de una vista diferida: bloques estáticos, sin animación.
function Loading() {
  const t = useT();
  return <div className="skeleton" role="status" aria-label={t("shell.loading")}><i /><i /><i /></div>;
}
