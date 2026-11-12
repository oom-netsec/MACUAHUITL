// Galería de componentes base para revisar el sistema de diseño en la vista previa (?gallery=1). No entra al build de la app.
import { I18nProvider } from "../lib/i18n";
import { CoreContext } from "../app/activity";
import type { CoreAPI } from "../lib/core";
import { Page, Section, ResultPanel, EmptyState, Tabs } from "../components/Page";
import { Notice } from "../components/Field";
import { CopyButton, Duration, RelativeTime, SeverityBadge, StatusPill } from "../components/Data";
import { Meter, Sparkline } from "../components/charts/Mini";
import { LazyTimeChart } from "../components/charts/LazyTimeChart";
import { DiffView } from "../components/DiffView";
import { DataTable } from "../components/DataTable";
import { DropZone, ExportMenu, TransferProgress } from "../components/Files";
import { DeviceMenu } from "../components/DeviceMenu";
import { ErrorState } from "../components/Page";
import { NavContext } from "../app/activity";

const t0 = Math.floor(Date.now() / 1000) - 3600;
const times = Array.from({ length: 120 }, (_, i) => t0 + i * 30);
const wave = (base: number, amp: number, k: number) => times.map((_, i) => +(base + amp * Math.sin(i / k) + Math.random() * amp * 0.4).toFixed(1));
const cpu = [{ label: "CPU 5 s", values: wave(35, 25, 7) }, { label: "CPU 1 min", values: wave(30, 12, 15) }, { label: "CPU 5 min", values: wave(28, 6, 30) }];
const devs = Array.from({ length: 240 }, (_, i) => ({ name: `SW${String(i + 1).padStart(3, "0")}-ACC`, ip: `10.20.${i >> 6}.${(i * 3) & 255}`, state: i % 17 === 0 ? "caído" : "en línea", cpu: (i * 37) % 100 }));
const before = "hostname SW1\n!\ninterface GigabitEthernet1/0/14\n description CAJA-07\n switchport access vlan 10\n no shutdown\n!\n" + Array.from({ length: 12 }, (_, i) => `ip route 10.${i}.0.0 255.255.0.0 10.0.0.1`).join("\n") + "\nend";
const after = before.replace("switchport access vlan 10", "switchport access vlan 20").replace(" no shutdown", " no shutdown\n spanning-tree portfast");

export function Gallery({ core }: { core: CoreAPI }) {
  return (
    <I18nProvider>
      <CoreContext.Provider value={core}>
        <div className="content gallery">
          <Page title="Galería de componentes" description="Sistema de diseño (ADR 0009) con datos de ejemplo.">
            <Tabs label="Pestañas" value="a" onChange={() => {}} tabs={[["a", "Subred"], ["b", "VLSM"], ["c", "IPv6"]]} />
            <Section title="Estados">
              <p><StatusPill tone="ok" label="En línea" /> <StatusPill tone="warn" label="Degradado" /> <StatusPill tone="bad" label="Caído" /> <StatusPill tone="run" label="En curso" /> <SeverityBadge sev={2} /> <SeverityBadge sev={4} /> <SeverityBadge sev={6} /></p>
              <p className="mono">10.20.1.1 <CopyButton value="10.20.1.1" label="IP" /> · aaaa.bbbb.cccc <CopyButton value="aaaa.bbbb.cccc" label="MAC" /> · <RelativeTime iso={new Date(Date.now() - 180_000).toISOString()} /> · <Duration ms={8_100_000} /></p>
              <p><Sparkline values={cpu[0].values.slice(-30)} label="CPU" unit="%" /> <Meter value={42} label="CPU" unit="%" warn={70} crit={90} /> <Meter value={78} label="Memoria" unit="%" warn={70} crit={90} /> <Meter value={95} label="Disco" unit="%" warn={70} crit={90} /></p>
              <Notice kind="error">No se pudo conectar con SW1: tiempo de espera agotado.</Notice>
              <Notice kind="warn">La ventana termina en 10 minutos.</Notice>
              <Notice kind="ok">Respaldo guardado.</Notice>
              <Notice kind="info">Sin cambios desde la última ronda.</Notice>
            </Section>
            <Section title="Series de tiempo">
              <LazyTimeChart title="CPU de SW1-CORE" unit="%" times={times} series={cpu} syncKey="g" thresholds={[{ value: 80, label: "Umbral 80 %" }]}
                marks={[{ at: times[40], label: "Ronda 2" }, { at: times[80], label: "Ronda 3" }]} fileName="cpu-sw1" />
              <LazyTimeChart title="Gi1/0/1 entrada y salida" unit="Mbps" times={times} series={[{ label: "Entrada", values: wave(420, 180, 9) }, { label: "Salida", values: wave(260, 90, 11) }]} syncKey="g" fileName="gi1-0-1" />
            </Section>
            <Section title="Tabla de datos">
              <NavContext.Provider value={{ go: () => {}, inbox: {} }}>
                <DataTable label="Equipos" rows={devs} rowKey={(d) => d.name} selectable exportName="equipos" height={300}
                  actions={() => <button className="sm">Respaldar</button>}
                  columns={[
                    { id: "name", header: "Equipo", value: (d) => d.name, render: (d) => <DeviceMenu name={d.name} address={d.ip}><span>{d.name}</span></DeviceMenu> },
                    { id: "ip", header: "IP", value: (d) => d.ip, mono: true, render: (d) => <>{d.ip}<CopyButton value={d.ip} label="IP" /></> },
                    { id: "state", header: "Estado", value: (d) => d.state, render: (d) => <StatusPill tone={d.state === "caído" ? "bad" : "ok"} label={d.state} /> },
                    { id: "cpu", header: "CPU", value: (d) => d.cpu, render: (d) => <Meter value={d.cpu} label="CPU" unit="%" warn={70} crit={90} /> },
                  ]} />
              </NavContext.Provider>
            </Section>
            <Section title="Archivos">
              <DropZone label="Captura" accept={["pcap", "pcapng"]} onPaths={() => {}} />
              <TransferProgress file="cat9k_iosxe.17.09.04a.SPA.bin" bytes={412_000_000} total={1_180_000_000} rateBps={9_800_000} etaSeconds={78} onCancel={() => {}} />
              <TransferProgress file="running-SW1.cfg" bytes={18_204} total={18_204} rateBps={0} etaSeconds={0} done verified />
              <ExportMenu name="hallazgos" formats={[{ fmt: "csv", data: () => "" }, { fmt: "md", data: () => "" }, { fmt: "json", data: () => "" }]} />
              <ErrorState title="No se pudo cargar la flota" action={<button className="sm">Reintentar</button>}>El núcleo no respondió a tiempo.</ErrorState>
            </Section>
            <Section title="Diferencias">
              <DiffView before={before} after={after} label="running-config de SW1" />
            </Section>
            <ResultPanel title="Resultado" status={{ tone: "ok", label: "Completado" }} meta="12 s"><div className="panel-body">Contenido del panel.</div></ResultPanel>
            <EmptyState title="Sin ejecuciones todavía">Completar los datos y ejecutar (Ctrl+↵).</EmptyState>
          </Page>
        </div>
      </CoreContext.Provider>
    </I18nProvider>
  );
}
