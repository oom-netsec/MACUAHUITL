import type { CoreStatus } from "../lib/core";
import { Icon } from "../components/Icon";
import { useLang, useT } from "../lib/i18n";
import { useTheme } from "../lib/theme";
import { assistOwner, type ShellStatus } from "./useShellStatus";

interface Props {
  core: CoreStatus;
  shell: ShellStatus;
  busy: string[]; // módulos con algo en curso
  onGo: (id: string) => void;
  onRecheck: () => void;
  onShortcuts: () => void;
}

// Barra de estado (ADR 0009 §2): el único lugar del estado global. Cada segmento lleva a su módulo.
export function StatusBar({ core, shell, busy, onGo, onRecheck, onShortcuts }: Props) {
  const t = useT();
  const lang = useLang();
  const theme = useTheme();
  const vault = shell.vault;
  const owner = shell.assist ? assistOwner(shell.assist.runId) : "";

  return (
    <footer className="statusbar" aria-label={t("shell.statusbar")}>
      <div className="status-live" aria-live="polite">
        <button className="status-item" data-tone={core === "connected" ? "" : "bad"} onClick={onRecheck}>
          <span className="dot" aria-hidden="true" />{t(core === "connected" ? "shell.coreStatus.connected" : "shell.coreStatus.disconnected")}
        </button>
        {vault && (
          <button className="status-item" data-tone={vault === "unlocked" ? "" : "warn"} onClick={() => onGo("vault")}>
            <Icon name={vault === "unlocked" ? "unlock" : "lock"} size={13} />
            {t(vault === "unlocked" ? "status.vault.unlocked" : vault === "locked" ? "status.vault.locked" : "status.vault.absent")}
          </button>
        )}
        {busy.length > 0 && (
          <button className="status-item" onClick={() => onGo(busy[0])}>
            <Icon name="loader" size={13} />{t("status.running", { n: busy.length })}
          </button>
        )}
        {shell.patrolArmed > 0 && (
          <button className="status-item" onClick={() => onGo("patrol")}>
            <Icon name="patrol" size={13} />{t("status.patrol", { n: shell.patrolArmed })}
          </button>
        )}
        {shell.assist && (
          <button className="status-item" data-tone="critical" onClick={() => owner && onGo(owner)}>
            <Icon name="alert" size={13} />{t("status.assist")}
          </button>
        )}
      </div>
      <div className="end">
        <button className="status-item" aria-label={t("shell.action.shortcuts")} onClick={onShortcuts}><Icon name="keyboard" size={13} /></button>
        <button className="status-item" aria-label={`${t("status.prefs")}: ${lang.toUpperCase()} · ${t(`shell.theme.${theme}`)}`}
          onClick={() => onGo("settings")}>
          <Icon name="theme" size={13} />{lang.toUpperCase()} · {t(`shell.theme.${theme}`)}
        </button>
      </div>
    </footer>
  );
}
