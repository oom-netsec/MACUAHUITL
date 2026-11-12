// Informe de capturas en gráficas: equipos con más tráfico, protocolos y conversaciones. El texto completo queda en la terminal.
import { CopyButton } from "../../components/Data";
import { DataTable, type Column } from "../../components/DataTable";
import { formatBytes } from "../../components/Files";
import { Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import type { PcapConv, PcapSummary } from "./pcapParse";
import "./tools.css";

export interface Bar { key: string; label: string; value: number; text: string; copy?: string }

// Barras proporcionales al mayor; el valor también va en texto en cada fila.
export function BarList({ label, items, compact }: { label: string; items: Bar[]; compact?: boolean }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className={compact ? "bars compact" : "bars"} aria-label={label}>
      {items.map((i) => (
        <li key={i.key}>
          <span className="bar-label mono">{i.label}{i.copy && <CopyButton value={i.copy} label={i.copy} />}</span>
          <span className="bar-track" aria-hidden="true"><span className="bar-fill" style={{ width: `${(i.value / max) * 100}%` }} /></span>
          <span className="bar-value mono">{i.text}</span>
        </li>
      ))}
    </ul>
  );
}

export function PcapReport({ p }: { p: PcapSummary }) {
  const t = useT();
  const txt = (packets: number, bytes: number) => `${formatBytes(bytes)} · ${t("pcap.packets", { n: packets })}`;
  const cols: Column<PcapConv>[] = [
    { id: "proto", header: t("pcap.col.proto"), value: (c) => c.proto, width: 90 },
    { id: "a", header: t("pcap.col.a"), value: (c) => c.a, mono: true },
    { id: "b", header: t("pcap.col.b"), value: (c) => c.b, mono: true },
    { id: "packets", header: t("pcap.col.packets"), value: (c) => c.packets, mono: true, width: 110 },
    { id: "bytes", header: t("pcap.col.bytes"), value: (c) => c.bytes, render: (c) => formatBytes(c.bytes), mono: true, width: 120 },
  ];
  return (
    <div className="tools-report">
      {p.talkers.length > 0 && (
        <Section title={t("pcap.talkers")}>
          <BarList label={t("pcap.talkers")} items={[...p.talkers].sort((a, b) => b.bytes - a.bytes).map((x) => ({ key: x.ip, label: x.ip, value: x.bytes, text: txt(x.packets, x.bytes), copy: x.ip }))} />
        </Section>
      )}
      {p.protocols.length > 0 && (
        <Section title={t("pcap.protocols")} description={t("pcap.protocols.hint")}>
          <BarList compact label={t("pcap.protocols")} items={[...p.protocols].sort((a, b) => b.bytes - a.bytes).map((x) => ({ key: x.proto, label: x.proto, value: x.bytes, text: txt(x.packets, x.bytes) }))} />
        </Section>
      )}
      {p.conversations.length > 0 && (
        <Section title={t("pcap.conversations")}>
          <DataTable label={t("pcap.conversations")} columns={cols} rows={p.conversations} rowKey={(c) => `${c.proto}|${c.a}|${c.b}`}
            exportName={t("file.conversaciones")} height={Math.min(360, 40 + 32 * p.conversations.length)} />
        </Section>
      )}
    </div>
  );
}
