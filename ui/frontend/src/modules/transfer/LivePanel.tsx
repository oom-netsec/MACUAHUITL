// Panel en vivo de un servidor de transferencias (fase 45): quién está conectado y qué se mueve ahora.
import { useEffect, useRef, useState } from "react";
import { TransferProgress } from "../../components/Files";
import { StatusPill } from "../../components/Data";
import { useT } from "../../lib/i18n";
import { es, type Key } from "../../lib/i18n/es";
import type { TransferRejection, TransferSession, TransferSessions } from "./api";

const MAX_RECENT = 20;
const unimplemented = (e: unknown) => (e as { cause?: { code?: string } } | null)?.cause?.code === "Unimplemented" || /code = Unimplemented/.test(String(e));
// «IP:puerto» o «[v6]:puerto» → solo la IP (v6 entre corchetes).
export const clientIP = (c: string) => (c.startsWith("[") && c.includes("]") ? c.slice(0, c.indexOf("]") + 1) : /^[^:]*:\d+$/.test(c) ? c.slice(0, c.lastIndexOf(":")) : c);

export function LivePanel({ serverId, open, fetchSessions }: { serverId: string; open: boolean; fetchSessions: (id: string) => Promise<TransferSessions> }) {
  const t = useT();
  const [data, setData] = useState<TransferSessions | null>(null);
  const list = data?.sessions ?? null;
  const rejections: TransferRejection[] = data?.rejections ?? [];
  const [msg, setMsg] = useState("");
  const prevRej = useRef<number | null>(null); // total de rechazos de la lectura anterior
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
        if (unimplemented(e)) clearInterval(h); // el núcleo no lo tiene: no insistir cada segundo
      }).finally(() => { busy = false; });
    };
    const h = setInterval(poll, 1000);
    poll();
    return () => { alive = false; clearInterval(h); };
  }, [open, serverId, fetchSessions]);
  useEffect(() => {
    if (!list) return;
    const known = prev.current;
    prev.current = new Map(list.map((s) => [s.id, s.state]));
    const changes = known ? list.filter((s) => known.get(s.id) !== s.state) : [];
    if (changes.length) setMsg(changes.map((s) => `${s.name}: ${t(`transfer.live.state.${s.state}` as Key)}`).join(". "));
  }, [list, t]);
  const rejTotal = rejections.reduce((n, r) => n + r.count, 0);
  useEffect(() => {
    if (!data) return;
    if (prevRej.current !== null && rejTotal !== prevRej.current) setMsg(t("transfer.live.rej.announce", { n: rejTotal }));
    prevRej.current = rejTotal;
  }, [data, rejTotal, t]);
  if (!open || !list) return null;
  const active = list.filter((s) => s.state === "active");
  const recent = list.filter((s) => s.state !== "active").sort((a, b) => b.ended - a.ended).slice(0, MAX_RECENT);
  const clients = [...new Set(active.map((s) => clientIP(s.client)).filter(Boolean))];
  const row = (s: TransferSession) => {
    const code = s.errorCode ? (`transfer.live.err.${s.errorCode}` as Key) : undefined;
    const err = s.state === "failed" ? (code && code in es ? t(code) : s.error ?? t("transfer.live.err.unknown")) : undefined;
    const eta = s.total > 0 && s.bytesPerSec > 0 ? Math.ceil((s.total - s.bytes) / s.bytesPerSec) : -1;
    return (
      <li key={s.id} className="live-session">
        <div className="meta">
          {s.state !== "done" && <><StatusPill tone={s.state === "active" ? "run" : "bad"} label={t(`transfer.live.state.${s.state}` as Key)} />{" "}</>/* la completa ya la marca TransferProgress */}
          {t(s.direction === "in" ? "transfer.live.in" : "transfer.live.out")} · {s.protocol.toUpperCase()} · <span className="mono">{clientIP(s.client)}</span>
        </div>
        <TransferProgress file={s.name} bytes={s.bytes} total={s.total} rateBps={s.bytesPerSec} etaSeconds={eta} done={s.state !== "active"} error={err} quietError />
      </li>
    );
  };
  return (
    <section className="live-panel" aria-label={t("transfer.live.title")}>
      <h4>{t("transfer.live.title")} <StatusPill tone={active.length ? "run" : ""} label={t(active.length ? "transfer.live.busy" : "transfer.live.idle")} /></h4>
      <p className="meta">{t("transfer.live.clients")}: {clients.length ? <span className="mono">{clients.join(", ")}</span> : t("transfer.live.noClients")}</p>
      {active.length > 0 && <ul style={{ listStyle: "none", padding: 0 }}>{active.map(row)}</ul>}
      {recent.length > 0 && <><h5>{t("transfer.live.recent")}</h5><ul style={{ listStyle: "none", padding: 0 }}>{recent.map(row)}</ul></>}
      {rejections.length > 0 && (
        <>
          <h5>{t("transfer.live.rej.title")}</h5>
          <ul style={{ listStyle: "none", padding: 0 }}>
            {rejections.map((r) => {
              const key = `transfer.live.rej.${r.cause}` as Key;
              const cause = r.cause !== "other" && key in es ? t(key) : r.reason || t("transfer.live.err.unknown");
              const tftp = r.protocol === "tftp"; // el origen UDP puede falsificarse
              return (
                <li key={`${r.ip}|${r.protocol}|${r.cause}`} className="live-session">
                  <div className="meta">
                    {r.protocol.toUpperCase()} · {tftp && <>{t("transfer.live.rej.from")} </>}<span className="mono">{r.ip}</span> · {cause}
                    {r.name && <> · <span className="mono">{r.name}</span></>} · <span>×{r.count}</span> · {new Date(r.last).toLocaleTimeString()}
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
