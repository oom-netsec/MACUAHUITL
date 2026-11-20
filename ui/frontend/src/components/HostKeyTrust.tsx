import { useEffect, useRef, useState } from "react";
import { Check, Notice } from "./Field";
import { keygenCommands, type AcceptedKey, type HostKeyInfo } from "../lib/hostkeys";
import { isWindows } from "../lib/platform";
import { useT } from "../lib/i18n";
import { showHidden } from "../lib/safeText";

// Huella nueva o cambiada: el equipo, la huella, el tipo y la orden para compararla en el equipo. Nada se acepta sin un clic:
// un solo equipo, el botón; varios, una casilla por equipo (sin marcar) y el botón solo con alguna marcada. Lo aceptado va a
// onTrust y vale solo para ese reintento; aquí no se guarda. onTrust entrega PARES (equipo, huella): cada huella viaja atada
// al equipo que la presentó, nunca suelta. La selección es por huella: marcar una marca a la vista todas las filas que la
// presentan, y salen los pares de todas ellas. Una fila sin equipo no genera par (no se puede atar). Si alguna llave cambió, el botón
// pide además marcar que se entiende el riesgo.
export function HostKeyTrust({ items, busy, onTrust, autoFocus = true }: { items: HostKeyInfo[]; busy?: boolean; onTrust: (keys: AcceptedKey[]) => void; autoFocus?: boolean }) {
  const t = useT();
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [ack, setAck] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const opener = useRef<Element | null>(null);
  // El foco va al aviso (nunca al botón: un Enter de más aceptaría); quien lanzó la operación se recuerda para devolverle el foco.
  // autoFocus=false: no quitarle el foco a otra cosa viva (la Terminal dividida, donde se teclea en el otro panel).
  useEffect(() => {
    if (!autoFocus) return;
    opener.current = document.activeElement && document.activeElement !== document.body ? document.activeElement : null;
    root.current?.focus();
  }, []);
  const key = items.map((i) => `${i.host ?? ""}|${i.fp}${i.changed ? "!" : ""}`).join("\n"); // un arreglo nuevo con las mismas huellas no borra la selección
  useEffect(() => { setPicked(new Set()); setAck(false); }, [key]);
  const many = items.length > 1;
  const chosen = [...new Set(items.filter((i) => !many || picked.has(i.fp)).map((i) => i.fp))];
  const needAck = items.some((i) => i.changed && chosen.includes(i.fp));
  const pairs = items.filter((i) => i.host && chosen.includes(i.fp)).map((i) => ({ host: i.host!, fingerprint: i.fp }))
    .filter((p, n, all) => all.findIndex((q) => q.host === p.host && q.fingerprint === p.fingerprint) === n);
  const win = isWindows();
  return (
    <div className="hostkey-trust" ref={root} tabIndex={-1}>
      {items.map((hk, i) => {
        const kg = hk.keyType ? keygenCommands(hk.keyType) : null;
        const name = showHidden(hk.host ?? hk.fp);
        const [first, second] = win ? [["ssh.hostKey.onWin", kg?.windows], ["ssh.hostKey.onLinux", kg?.linux]] as const : [["ssh.hostKey.onLinux", kg?.linux], ["ssh.hostKey.onWin", kg?.windows]] as const;
        return (
          <div key={`${hk.fp}-${i}`} role="group" aria-label={name}>
            <Notice kind={hk.changed ? "error" : "warn"}>
              <p>{t(hk.changed ? "hostkey.changed.danger" : "hostkey.new")}</p>
              {(hk.host || hk.keyType) && <p>{hk.host && <span className="mono">{showHidden(hk.host)}</span>}{hk.host && hk.keyType && " · "}{hk.keyType && <span className="mono">{showHidden(hk.keyType)}</span>}</p>}
              <p><code>{showHidden(hk.fp)}</code></p>
              {kg && (
                <>
                  <p>{t("ssh.hostKey.compare")}</p>
                  <p>{t(first[0])} <code className="mono">{first[1]}</code></p>
                  <details><summary>{t("hostkey.otherSystem")}</summary><p>{t(second[0])} <code className="mono">{second[1]}</code></p></details>
                </>
              )}
              {many && <Check label={t("hostkey.pick", { host: name })} checked={picked.has(hk.fp)} onChange={(v) => setPicked((s) => { const n = new Set(s); if (v) n.add(hk.fp); else n.delete(hk.fp); return n; })} />}
            </Notice>
          </div>
        );
      })}
      {needAck && <Check label={t("hostkey.ack")} checked={ack} onChange={setAck} />}
      <button type="button" disabled={busy || pairs.length === 0 || (needAck && !ack)} onClick={() => { onTrust(pairs); if (opener.current instanceof HTMLElement && opener.current.isConnected) opener.current.focus(); }}>{t("hostkey.trust")}</button>
    </div>
  );
}
