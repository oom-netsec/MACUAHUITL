import { Badge } from "../../components/Page";
import { RelativeTime, formatDateTime } from "../../components/Data";
import { formatBytes } from "../../components/Files";
import { useLang, useT } from "../../lib/i18n";
import type { BackupEntry } from "./api";

// Línea de tiempo de respaldos: un carril por equipo, del más nuevo al más viejo. Elegir dos respaldos los compara.
export function groupByDevice(list: BackupEntry[]): [string, BackupEntry[]][] {
  const m = new Map<string, BackupEntry[]>();
  for (const b of list) m.set(b.device, [...(m.get(b.device) ?? []), b]);
  return [...m].map(([d, l]) => [d, l.sort((x, y) => y.at.localeCompare(x.at))] as [string, BackupEntry[]]);
}

export function BackupTimeline({ backups, sel, onToggle, onView, onRestore }: {
  backups: BackupEntry[]; sel: string[]; onToggle: (id: string) => void; onView: (id: string) => void; onRestore: (b: BackupEntry) => void;
}) {
  const t = useT();
  const lang = useLang();
  return (
    <div className="timeline-groups">
      {groupByDevice(backups).map(([device, list]) => (
        <section key={device} className="timeline" aria-label={device}>
          <h4 className="mono">{device} <span className="meta">{t("backup.tl.count", { n: list.length })}</span></h4>
          <ol>
            {list.map((b) => (
              <li key={b.id} data-picked={sel.includes(b.id) || undefined}>
                <input type="checkbox" aria-label={t("backup.compareAria", { id: b.id })} checked={sel.includes(b.id)} onChange={() => onToggle(b.id)} />
                <span className="tl-when"><RelativeTime iso={b.at} /><span className="meta mono" title={b.at}>{formatDateTime(b.at, lang)}</span></span>
                <span className="tl-kind">{b.kind}</span>
                <span className="mono tl-size">{formatBytes(b.bytes)}</span>
                <Badge tone={b.masked ? "info" : "warn"}>{t(b.masked ? "backup.masked" : "backup.plain")}</Badge>
                <span className="row-actions">
                  <button className="sm" aria-label={t("backup.viewAria", { id: b.id })} onClick={() => onView(b.id)}>{t("backup.view")}</button>
                  <button className="sm inline" aria-label={t("backup.restoreAria", { id: b.id })} disabled={b.masked} title={b.masked ? t("backup.maskedNoRestore") : undefined} onClick={() => onRestore(b)}>{t("backup.restore")}</button>
                </span>
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  );
}
