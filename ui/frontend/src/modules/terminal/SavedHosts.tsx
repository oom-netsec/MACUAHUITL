import { useEffect, useId, useState } from "react";
import type { CoreAPI, Credential } from "../../lib/core";
import { useT } from "../../lib/i18n";
import type { Host } from "../inventory/api";
import { useHostsVersion } from "../inventory/signal";

// Conexión de un clic: un botón por host guardado. Manda solo el id; el núcleo pone dirección, puerto, credencial y orden de inicio.
// Sin credencial utilizable el botón queda deshabilitado y la razón se lee junto a él.
export function SavedHosts({ core, creds, busy, onConnect }: { core: CoreAPI; creds: Credential[]; busy: boolean; onConnect: (h: Host) => void }) {
  const t = useT();
  const hv = useHostsVersion();
  const id = useId();
  const [hosts, setHosts] = useState<Host[]>([]);
  useEffect(() => {
    let live = true;
    core.listHosts().then((l) => { if (live) setHosts(l); }, () => { if (live) setHosts([]); });
    return () => { live = false; };
  }, [core, hv]);
  if (hosts.length === 0) return null;
  return (
    <div className="saved-hosts" role="group" aria-label={t("ssh.saved")}>
      <h3>{t("ssh.saved")}</h3>
      <ul>
        {hosts.map((h) => {
          const ok = creds.some((c) => c.id === h.credentialId);
          return (
            <li key={h.id}>
              <button type="button" disabled={busy || !ok} aria-describedby={ok ? undefined : `${id}-${h.id}`} aria-label={t("ssh.connectHost", { name: h.name })} onClick={() => onConnect(h)}>{h.name}</button>
              <span className="meta mono"> {h.address}</span>
              {!ok && <span id={`${id}-${h.id}`} className="hint"> {t("ssh.saved.noCred")}</span>}
            </li>
          );
        })}
      </ul>
    </div>
  );
}
