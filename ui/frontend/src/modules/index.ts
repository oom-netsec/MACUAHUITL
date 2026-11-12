import type { IconName } from "../components/Icon";
import type { Key } from "../lib/i18n/es";
import { lazyView, type LazyViewFn } from "./lazy";

// Manifiesto de módulos (ADR 0008 §2): la barra lateral y el área de contenido salen de esta lista.
// Agregar un módulo a la app es una línea aquí (más sus archivos y las claves `nav.*` en i18n). Cada vista se
// carga bajo demanda con lazyView (ADR 0009 §6): su código se descarga la primera vez que se abre.
// Los que comparten `group` se muestran juntos en el panel flotante de ese grupo, en este orden.
export const groups = {
  access: { label: "nav.access", icon: "terminal" },
  diag: { label: "nav.diag", icon: "pulse" },
  analysis: { label: "nav.analysis", icon: "layers" },
  ops: { label: "nav.ops", icon: "ops" },
  utils: { label: "nav.utils", icon: "tools" },
} satisfies Record<string, { label: Key; icon: IconName }>;

export interface ModuleDef {
  id: string; // también es la clave de navegación entre módulos (useNav)
  label: Key;
  icon?: IconName; // solo los que van sueltos en la barra; los de un grupo no lo usan
  group?: keyof typeof groups;
  bottom?: boolean; // abajo de la barra, separado
  view: LazyViewFn;
}

export const modules: ModuleDef[] = [
  { id: "patrol", label: "nav.patrol", icon: "patrol", view: lazyView(() => import("./patrol/PatrolView"), "PatrolView") },
  { id: "terminal", label: "nav.ssh", group: "access", view: lazyView(() => import("./terminal/TerminalView"), "TerminalView") },
  { id: "console", label: "nav.console", group: "access", view: lazyView(() => import("./console/ConsoleView"), "ConsoleView") },
  { id: "transfer", label: "nav.transfer", group: "access", view: lazyView(() => import("./transfer/TransferView"), "TransferView") },
  { id: "ping", label: "nav.ping", group: "diag", view: lazyView(() => import("./diag/DiagView"), "DiagView", { tool: "ping" }) },
  { id: "traceroute", label: "nav.traceroute", group: "diag", view: lazyView(() => import("./diag/DiagView"), "DiagView", { tool: "traceroute" }) },
  { id: "nmap", label: "nav.nmap", group: "diag", view: lazyView(() => import("./diag/DiagView"), "DiagView", { tool: "nmap" }) },
  { id: "iperf3", label: "nav.iperf3", group: "diag", view: lazyView(() => import("./diag/DiagView"), "DiagView", { tool: "iperf3" }) },
  { id: "capture", label: "nav.capture", group: "diag", view: lazyView(() => import("./diag/DiagView"), "DiagView", { tool: "pcap" }) },
  { id: "pcap", label: "nav.pcap", group: "analysis", view: lazyView(() => import("./tools/ToolsView"), "PcapPanel") },
  { id: "acl", label: "nav.acl", group: "analysis", view: lazyView(() => import("./acl/AclView"), "AclView") },
  { id: "dns", label: "nav.dns", group: "analysis", view: lazyView(() => import("./tools/ToolsView"), "DnsPanel") },
  { id: "tls", label: "nav.tls", group: "analysis", view: lazyView(() => import("./tools/ToolsView"), "TlsPanel") },
  { id: "runs", label: "nav.runs", group: "analysis", view: lazyView(() => import("./analysis/AnalysisView"), "AnalysisView") },
  { id: "drift", label: "nav.drift", group: "analysis", view: lazyView(() => import("./drift/DriftView"), "DriftView") },
  { id: "cleaner", label: "nav.cleaner", group: "analysis", view: lazyView(() => import("./cleaner/CleanerView"), "CleanerView") },
  { id: "fleet", label: "nav.fleet", group: "analysis", view: lazyView(() => import("./fleet/FleetView"), "FleetView") },
  { id: "change", label: "nav.change", group: "ops", view: lazyView(() => import("./change/ChangeView"), "ChangeView") },
  { id: "adhoc", label: "nav.adhoc", group: "ops", view: lazyView(() => import("./adhoc/AdhocView"), "AdhocView") },
  { id: "ports", label: "nav.ports", group: "ops", view: lazyView(() => import("./ports/PortsView"), "PortsView") },
  { id: "snippets", label: "nav.snippets", group: "ops", view: lazyView(() => import("./snippets/SnippetsView"), "SnippetsView") },
  { id: "credrotate", label: "nav.credrotate", group: "ops", view: lazyView(() => import("./credrotate/CredRotateView"), "CredRotateView") },
  { id: "backup", label: "nav.backup", group: "ops", view: lazyView(() => import("./backup/BackupView"), "BackupView") },
  { id: "security", label: "nav.security", icon: "shield", view: lazyView(() => import("./security/SecurityView"), "SecurityView") },
  { id: "field", label: "nav.field", group: "utils", view: lazyView(() => import("./field/FieldView"), "FieldView") },
  { id: "calc", label: "nav.calc", group: "utils", view: lazyView(() => import("./calc/CalcView"), "CalcView") },
  { id: "visibility", label: "nav.visibility", icon: "eye", view: lazyView(() => import("./visibility/VisibilityView"), "VisibilityView") },
  { id: "syslog", label: "nav.syslog", icon: "syslog", view: lazyView(() => import("./tools/ToolsView"), "SyslogPanel") },
  { id: "forensic", label: "nav.forensic", group: "analysis", view: lazyView(() => import("./forensic/ForensicView"), "ForensicView") },
  { id: "vault", label: "nav.vault", icon: "lock", bottom: true, view: lazyView(() => import("./vault/VaultView"), "VaultView") },
  { id: "audit", label: "nav.audit", icon: "audit", bottom: true, view: lazyView(() => import("./audit/AuditView"), "AuditView") },
  { id: "scripts", label: "nav.scripts", group: "utils", view: lazyView(() => import("./scripts/ScriptsView"), "ScriptsView") },
  { id: "settings", label: "nav.settings", icon: "settings", bottom: true, view: lazyView(() => import("./settings/SettingsView"), "SettingsView") },
  { id: "hosts", label: "nav.hosts", group: "access", view: lazyView(() => import("./inventory/HostsView"), "HostsView") },
];
