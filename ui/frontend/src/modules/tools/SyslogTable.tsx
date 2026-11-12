// Syslog en vivo: tabla virtualizada con filtro rápido por severidad, pausa del desplazamiento automático y mensajes por minuto.
import { useEffect, useMemo, useRef, useState } from "react";
import { SeverityBadge } from "../../components/Data";
import { DataTable, type Column } from "../../components/DataTable";
import { Segmented } from "../../components/Segmented";
import { Sparkline } from "../../components/charts/Mini";
import { useLang, useT } from "../../lib/i18n";
import { inGroup, perMinute, type SevGroup, type SysMsg } from "./syslogStats";
import "./tools.css";

const GROUPS: SevGroup[] = ["all", "err", "warn", "notice", "info"];

export function SyslogTable({ msgs }: { msgs: SysMsg[] }) {
  const t = useT();
  const lang = useLang();
  const [group, setGroup] = useState<SevGroup>("all");
  const [frozen, setFrozen] = useState<SysMsg[] | null>(null); // pausa: la tabla deja de moverse, los mensajes se siguen guardando
  const wrap = useRef<HTMLDivElement>(null);
  const shown = frozen ?? msgs;
  const rows = useMemo(() => shown.filter((m) => inGroup(group, m.sev)), [shown, group]);
  const counts = useMemo(() => Object.fromEntries(GROUPS.map((g) => [g, shown.filter((m) => inGroup(g, m.sev)).length])) as Record<SevGroup, number>, [shown]);
  const spark = useMemo(() => perMinute(msgs), [msgs]);

  // Al fondo mientras no esté en pausa. shortcut: baja siempre al último; si se ordena por otra columna, el "último" es el de esa vista.
  useEffect(() => {
    if (frozen) return;
    const el = wrap.current?.querySelector<HTMLElement>('[role="table"]');
    if (!el) return;
    // Fuera del efecto: el desplazamiento hace que la tabla virtual se redibuje y React no admite eso en pleno efecto.
    const id = requestAnimationFrame(() => { el.scrollTop = el.scrollHeight; el.dispatchEvent(new Event("scroll")); });
    return () => cancelAnimationFrame(id);
  }, [rows.length, frozen]);

  const cols: Column<SysMsg>[] = [
    { id: "time", header: t("syslog.col.time"), value: (m) => m.at, render: (m) => new Date(m.at).toLocaleTimeString(lang), mono: true, width: 130, minWidth: 96 },
    { id: "from", header: t("syslog.col.source"), value: (m) => m.from, mono: true, width: 150, minWidth: 110 },
    { id: "sev", header: t("syslog.col.sev"), value: (m) => m.sev, render: (m) => (m.sev < 0 ? "—" : <SeverityBadge sev={m.sev} />), width: 180, minWidth: 170 },
    { id: "mnemonic", header: t("syslog.col.mnemonic"), value: (m) => m.mnemonic, mono: true, width: 270, minWidth: 110 },
    { id: "text", header: t("syslog.col.message"), value: (m) => m.text, mono: true, minWidth: 280 },
  ];
  return (
    <div ref={wrap}>
      <div className="syslog-bar">
        <Segmented legend={t("syslog.sevFilter")} value={group} onChange={setGroup}
          options={GROUPS.map((g): [SevGroup, string] => [g, `${t(`syslog.sev.${g}`)} (${counts[g]})`])} />
        <button className="sm" aria-pressed={!!frozen} onClick={() => setFrozen(frozen ? null : msgs)}>{t(frozen ? "syslog.resume" : "syslog.pause")}</button>
        {frozen && <span role="status" className="hint">{t("syslog.paused", { n: Math.max(0, (msgs.at(-1)?.id ?? 0) - (frozen.at(-1)?.id ?? 0)) })}</span>}
        <span className="spark-box">{t("syslog.perMinute")}<Sparkline values={spark} label={t("syslog.perMinute")} width={120} height={24} /></span>
      </div>
      <DataTable label={t("syslog.messages")} columns={cols} rows={rows} rowKey={(m) => String(m.id)} exportName={t("file.syslog")} height={420} />
    </div>
  );
}
