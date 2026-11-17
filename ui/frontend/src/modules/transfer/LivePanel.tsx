// Panel en vivo de un servidor de transferencias (fase 45): quién está conectado y qué se mueve ahora.
import { useEffect, useRef, useState } from "react";
import { TransferProgress } from "../../components/Files";
import { StatusPill } from "../../components/Data";
import { useLang, useT } from "../../lib/i18n";
import type { Key } from "../../lib/i18n/es";
import type { TransferRejection, TransferSession, TransferSessions } from "./api";

const MAX_RECENT = 20;
// Unimplemented (núcleo viejo) y NotFound (servidor ya cerrado): insistir cada segundo no sirve.
const gone = (e: unknown) => /^(Unimplemented|NotFound)$/.test((e as { cause?: { code?: string } } | null)?.cause?.code ?? "") || /code = (Unimplemented|NotFound)/.test(String(e));
const causes = new Set(["not_found", "origin_denied", "write_disabled", "read_disabled", "method", "busy"]);
const stateOf = (s: TransferSession): "active" | "done" | "failed" => (s.state === "active" || s.state === "done" ? s.state : "failed"); // desconocido: como fallida
const groupKey = (r: TransferRejection) => `${r.ip}|${r.cause}`;
// «IP:puerto» o «[v6]:puerto» → solo la IP (v6 entre corchetes).
export const clientIP = (c: string) => (c.startsWith("[") && c.includes("]") ? c.slice(0, c.indexOf("]") + 1) : /^[^:]*:\d+$/.test(c) ? c.slice(0, c.lastIndexOf(":")) : c);

export function LivePanel({ serverId, open, fetchSessions, label }: { serverId: string; open: boolean; label?: string; fetchSessions: (id: string) => Promise<TransferSessions> }) {
  const t = useT();
  const lang = useLang();
  const [data, setData] = useState<TransferSessions | null>(null);
  const list = data?.sessions ?? null;
  const rejections: TransferRejection[] = data?.rejections ?? [];
  const [msg, setMsg] = useState("");
  const prevRej = useRef<Set<string> | null>(null); // grupos de rechazo de la lectura anterior
  const prev = useRef<Map<string, string> | null>(null); // null: aún no hay primera lectura (no se anuncia lo que ya estaba)
  useEffect(() => {
    if (!open) return;
    let alive = true;
    let busy = false; // una llamada a la vez: una respuesta vieja nunca pisa a una nueva
    const poll = () => {
      if (busy || document.visibilityState === "hidden") return;
      busy = true;
      fetchSessions(serverId).then((r) => alive && setData({ sessions: r?.sessions ?? [], rejections: r?.rejections ?? [] }), (e) => {
        if (!alive) return;
        setData(null); // fallo: el panel se oculta sin ruido
        if (gone(e)) clearInterval(h); // el núcleo no lo tiene: no insistir cada segundo
      }).finally(() => { busy = false; });
    };
    const h = setInterval(poll, 1000);
    poll();
    return () => { alive = false; clearInterval(h); };
  }, [open, serverId, fetchSessions]);
  useEffect(() => {
    if (!data) return;
    const known = prev.current, knownRej = prevRej.current;
    prev.current = new Map(data.sessions.map((s) => [s.id, stateOf(s)]));
    prevRej.current = new Set(data.rejections.map(groupKey));
    const parts: string[] = [];
    const changes = known ? data.sessions.filter((s) => known.get(s.id) !== stateOf(s)) : [];
    if (changes.length) parts.push(changes.map((s) => `${s.name}: ${t(`transfer.live.state.${stateOf(s)}` as Key)}`).join(". "));
    const fresh = knownRej ? data.rejections.filter((r) => !knownRej.has(groupKey(r))).length : 0; // un grupo nuevo, no cada rechazo: un flood no satura al lector de pantalla
    if (fresh) parts.push(t("transfer.live.rej.announce", { n: fresh }));
    if (parts.length) setMsg(parts.join(". "));
  }, [data, t]);
  if (!list) return null; // cerrado: se queda la última lectura
  const active = list.filter((s) => stateOf(s) === "active");
  const recent = list.filter((s) => stateOf(s) !== "active").sort((a, b) => b.ended - a.ended).slice(0, MAX_RECENT);
  const clients = [...new Set(active.map((s) => clientIP(s.client)).filter(Boolean))];
  const row = (s: TransferSession) => {
    const st = stateOf(s);
    const err = st === "failed" ? s.error || t("transfer.live.err.unknown") : undefined; // error ya viene traducido por el núcleo
    const eta = s.total > 0 && s.bytesPerSec > 0 ? Math.ceil((s.total - s.bytes) / s.bytesPerSec) : -1;
    return (
      <li key={s.id} className="live-session">
        <div className="meta">
          {st !== "done" && <><StatusPill tone={st === "active" ? "run" : "bad"} label={t(`transfer.live.state.${st}` as Key)} />{" "}</>/* la completa ya la marca TransferProgress */}
          {t(s.direction === "in" ? "transfer.live.in" : "transfer.live.out")} · {s.protocol.toUpperCase()} · <span className="mono">{clientIP(s.client)}</span>
        </div>
        <TransferProgress file={s.name} bytes={s.bytes} total={s.total} rateBps={s.bytesPerSec} etaSeconds={eta} done={st !== "active"} error={err} quietError />
      </li>
    );
  };
  return (
    <section className="live-panel" aria-label={label ? `${t("transfer.live.title")} · ${label}` : t("transfer.live.title")}>
      <h4>{t("transfer.live.title")} <StatusPill tone={active.length ? "run" : ""} label={t(active.length ? "transfer.live.busy" : "transfer.live.idle")} /></h4>
      <p className="meta">{t("transfer.live.clients")}: {clients.length ? <span className="mono">{clients.join(", ")}</span> : t("transfer.live.noClients")}</p>
      {active.length > 0 && <ul style={{ listStyle: "none", padding: 0 }}>{active.map(row)}</ul>}
      {recent.length > 0 && <><h5>{t("transfer.live.recent")}</h5><ul style={{ listStyle: "none", padding: 0 }}>{recent.map(row)}</ul></>}
      {rejections.length > 0 && (
        <>
          <h5>{t("transfer.live.rej.title")}</h5>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {rejections.map((r) => {
              const cause = causes.has(r.cause) ? t(`transfer.live.rej.${r.cause}` as Key) : r.reason || t("transfer.live.err.unknown");
              const tftp = r.protocol === "tftp"; // el origen UDP puede falsificarse
              return (
                <li key={`${r.ip}|${r.protocol}|${r.cause}`} className="live-session">
                  <div className="meta">
                    {r.protocol.toUpperCase()} · {tftp && <>{t("transfer.live.rej.from")} </>}<span className="mono">{r.ip}</span> · {cause}
                    {r.name && <> · <span className="mono">{r.name}</span></>} · <span>×{r.count}</span> · {new Date(r.last).toLocaleTimeString(lang)}
                  </div>
                </li>
              );
            })}
          </ul>
          {rejections.some((r) => r.protocol === "tftp") && <p className="meta">{t("transfer.live.rej.tftpNote")}</p>}
        </>
      )}
      <div role="status" aria-live="polite" className="sr">{msg}</div>
    </section>
  );
}
