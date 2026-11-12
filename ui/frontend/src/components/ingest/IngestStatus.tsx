// Estado de la escucha (syslog, traps, flujos): conteo, archivo actual y aviso de descartes con su top de orígenes.
import { Icon } from "../../components/Icon";
import { useT } from "../../lib/i18n";
import type { SyslogDrops } from "../../modules/tools/api";
import { kindKey, type IngestKind } from "./ingestOpts";
import "./ingest.css";

const p2 = (n: number) => String(n).padStart(2, "0");
const hms = (ms: number) => { const d = new Date(ms); return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`; };

/** file: null si no se guarda; con perSource (plantilla con {origen}) hay un archivo por origen en folder. */
export type IngestFileInfo = { name: string; folder: string; perSource: boolean };

export function IngestStatusLine({ kind = "syslog", received, file }: { kind?: IngestKind; received: number; file: IngestFileInfo | null }) {
  const t = useT();
  const line = !file ? null
    : file.perSource ? t("syslog.file.perSource", { folder: file.folder, name: file.name || t("syslog.file.pending") })
    : file.name ? t("syslog.file", { name: file.name }) : t(kindKey(kind, "file.none"));
  return (
    <div role="group" aria-label={t("syslog.state")} className="syslog-status">
      <span>{t(kindKey(kind, "recv"), { n: received })}</span>
      {line && <span className="mono">{line}</span>}
    </div>
  );
}

// Solo la frase fija va en la región viva (se anuncia una vez); las cifras cambian cada segundo y quedan fuera para no leerse a cada rato.
export function IngestDropsBanner({ kind = "syslog", drops }: { kind?: IngestKind; drops: SyslogDrops }) {
  const t = useT();
  return (
    <div className="notice warn">
      <Icon name="alert" />
      <div className="notice-body">
      <p role="status" className="syslog-drops live">{t(kindKey(kind, "drops.live"))}</p>
      <p className="syslog-drops">
        {t(kindKey(kind, "drops"), { n: drops.total, src: drops.porOrigen, glob: drops.global, queue: drops.colaLlena, time: hms(drops.sinceMs) })}
      </p>
      {drops.top.length > 0 && (
        <details className="syslog-top">
          <summary>{t(kindKey(kind, "drops.top"))}</summary>
          <table aria-label={t(kindKey(kind, "drops.top"))}>
            <thead><tr><th scope="col">{t("syslog.col.source")}</th><th scope="col">{t("syslog.drops.count")}</th></tr></thead>
            <tbody>
              {drops.top.map((s) => (
                <tr key={s.source}><td className="mono">{s.source === "otros" ? t("syslog.drops.others") : s.source}</td><td className="mono">{s.count}</td></tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      </div>
    </div>
  );
}
