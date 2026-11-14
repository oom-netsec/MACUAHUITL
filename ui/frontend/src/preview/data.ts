import type { CoreAPI } from "../lib/core";
import { dnsTraceSample, pcapSample, tlsSample } from "../modules/tools/samples";
import { fakeScripts } from "../modules/scripts/fake";
import type { ScriptItem } from "../modules/scripts/api";
import { fakeInventory, sampleDevices, sampleHostFields, sampleHostsImport } from "../modules/inventory/fake";
import { samplePlaybooks } from "../modules/patrol/fake";
import { sampleRestore } from "../modules/backup/fake";
import { fakeSettings } from "../modules/settings/fake";
import type { Host } from "../modules/inventory/api";

// Sample data (in English, the app's canonical language) so every view looks like real use; extended module by module.
export function sample(): Partial<CoreAPI> {
  const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
  const backups = backupSamples(ago);
  const settings = fakeSettings();
  return {
    ...fakeInventory(hostsEn),
    listDevices: async (q?: string) => { const n = (q ?? "").trim().toLowerCase(); return { ...devicesEn, devices: devicesEn.devices.filter((d) => !n || `${d.address} ${d.hostname} ${d.platform}`.toLowerCase().includes(n)) }; },
    previewHostsImport: async () => importEn,
    hostsImportFormat: async () => ({ fields: hostFieldsEn, maxRows: 1000, maxBytes: 5 << 20 }),
    hostsImportTemplate: async (format: "csv" | "json") => hostsTemplate(format),
    listPlaybooks: async () => playbooksEn,
    assistPlanRestore: async () => restoreEn,
    setCorePrefs: async (p: Parameters<typeof settings.setCorePrefs>[0]) => { const r = await settings.setCorePrefs(p); return r.note ? { ...r, note: "The change applies to what starts afterwards: jobs and listeners already running keep the folder they started with. Data in the previous folder is not moved." } : r; },
    getCorePrefs: settings.getCorePrefs,
    ...previewTerminal(),
    ...previewScriptsApi(),
    listCredentials: async () => [
      { id: "c1", label: "Core DC", username: "netops", hasEnable: true, hasSshKey: false },
      { id: "c2", label: "Branch access", username: "tac", hasEnable: false, hasSshKey: true },
      { id: "c3", label: "lab-admin", username: "lab", hasEnable: true, hasSshKey: true },
      { id: "c4", label: "ISE (RADIUS secret)", username: "-", hasEnable: false, hasSshKey: false },
      { id: "c5", label: "WAN edge", username: "wanops", hasEnable: true, hasSshKey: false },
    ],
    getRun: async () => [
      { target: "10.0.0.1:22", state: "DEVICE_STATE_COMPLETED", detail: "" },
      { target: "10.0.0.2:22", state: "DEVICE_STATE_RUNNING", detail: "" },
      { target: "10.0.0.3:22", state: "DEVICE_STATE_FAILED", detail: "timed out" },
    ],
    auditVerify: async () => ({ intact: true, firstBroken: 0, head: "7f3a9c01d4e2b685a0c7e1f93b24d86a5c10e7ab9d3f2468c1b05e7a94d3c2f8" }),
    listJobs: async () => [
      { id: "j0", name: "Nightly core backup", state: "armed", armedAt: ago(135), round: 3, rounds: 6, devicesTotal: 24, devicesOk: 22, devicesFailed: 1, outputDir: "/home/u/evidence/nightly-core",
        phases: [{ at: ago(140), kind: "JOB_PHASE_KIND_CREATED" }, { at: ago(135), kind: "JOB_PHASE_KIND_ARMED", detail: "24 devices" }] },
      { id: "j9", name: "TAC case 6942", state: "completed", round: 1, rounds: 1, devicesTotal: 3, devicesOk: 3, devicesFailed: 0, outputDir: "/home/u/evidence/tac-case-6942",
        phases: [{ at: ago(900), kind: "JOB_PHASE_KIND_COMPLETED", detail: "1 round" }] },
    ],
    // Tools, Cleaner, Fleet, Forensics, ACL and Runs (network utilities).
    toolsPcap: async () => pcapSample,
    toolsDns: async (r) => (r.mode === "trace" ? dnsTraceSample : "{}"),
    toolsTls: async () => tlsSample,
    cleanerRun: async (text) => ({ report: { changes: [], orphans: [{ line: 7, text: " ip access-group IN-MISSING in", why: "ACL IN-MISSING does not exist (ip access-group)" }] }, text: "3 empty lines removed\n\n1 ORPHANS (marked with a ! comment in the output)\nline 7:  ip access-group IN-MISSING in — ACL IN-MISSING does not exist (ip access-group)\n\nOrphans are only marked: the cleanup never removes them.",
      output: text.replace(/\n{2,}/g, "\n").replace(/^!\n(?=!)/gm, "") }),
    fleetPath: async () => ({ svg: "", result: { src: "10.1.10.20", dst: "172.31.0.1", arrived: false, warnings: [], hops: [
      { id: 0, parent: -1, device: "ACC1", route: "S* 0.0.0.0/0", status: "ok" as const, source: "show ip route", at: ago(40) },
      { id: 1, parent: 0, device: "DIST1", via: "10.1.0.1", out_if: "Te1/1/1", segment: { interface: "Vlan10", vlan: "10", l2: [{ device: "ACC2", port: "Gi1/0/24", source: "show mac address-table", at: ago(40) }] }, status: "ok" as const, source: "show ip route", at: ago(40) },
      { id: 2, parent: 1, device: "CORE1", via: "10.1.255.1", out_if: "Po1", ecmp: true, status: "ok" as const, source: "show ip route", at: ago(41) },
      { id: 3, parent: 1, device: "CORE2", via: "10.1.255.5", out_if: "Po2", ecmp: true, status: "ok" as const, source: "show ip route", at: ago(41) },
      { id: 4, parent: 2, device: "EDGE1", via: "10.2.0.1", out_if: "Te1/0/1", segment: { interface: "Te1/0/1", vlan: "300" }, status: "arrived" as const, reason: "destination connected", source: "show ip route", at: ago(42) },
      { id: 5, parent: 3, device: "10.2.0.5", via: "10.2.0.5", out_if: "Te1/0/2", status: "cut" as const, reason: "no evidence of the next device (hop 10.2.0.5 does not belong to any collected device)", at: "0001-01-01T00:00:00Z" },
    ] } }),
    fleetHealth: async () => ({ devices: 12, warnings: [], issues: [
      { device: "ACC1", port: "Gi1/0/9", severity: "critica" as const, problems: [{ kind: "err-disabled", evidence: "Gi1/0/9 err-disabled (psecure-violation)" }], source: "show interfaces status", at: ago(30) },
      { device: "ACC1", port: "Gi1/0/12", severity: "media" as const, problems: [{ kind: "crc", value: 412, evidence: "412 CRC" }], source: "show interfaces", at: ago(30) },
      { device: "ACC2", port: "Gi1/0/3", severity: "alta" as const, problems: [{ kind: "crc", value: 9120, evidence: "9120 CRC" }, { kind: "duplex", evidence: "half-duplex" }], source: "show interfaces", at: ago(32) },
      { device: "DIST1", port: "Te1/1/1", severity: "baja" as const, problems: [{ kind: "drops", value: 31, evidence: "31 output drops" }], source: "show interfaces", at: ago(33) },
    ] }),
    fleetSummary: async () => ({ devices: 12, checked: { cpu: 12, ntp: 12, reboot: 12, memory: 12, flash: 12 }, warnings: [], rows: [
      { device: "ACC1", check: "ntp", value: "not synchronized", source: "show ntp status", at: ago(30) },
      { device: "ACC2", check: "cpu", value: "92 %", source: "show processes cpu", at: ago(30) },
      { device: "ACC2", check: "flash", value: "97 % used", source: "dir flash:", at: ago(31) },
      { device: "DIST1", check: "reboot", value: "2 h ago", source: "show version", at: ago(33) },
    ] }),
    forensicFlapping: async () => ({ source: "show logging of job j0", interfaces: 3, transitions: 19, count: 3, window: "1m0s", warnings: [], counter_jumps: [],
      flaps: [
        { host: "ACC1_10.1.1.1", interface: "Gi1/0/3", layer: "link" as const, total: 9, peak: 8, episodes: 2, first: ago(50), last: ago(47), sequence: "down up down up down up down up down" },
        { host: "ACC2_10.1.1.2", interface: "Gi1/0/9", layer: "link" as const, total: 6, peak: 6, episodes: 1, first: ago(20), last: ago(19), sequence: "down up down up down up" },
        { host: "DIST1_10.1.0.1", interface: "Te1/1/2", layer: "lineproto" as const, total: 4, peak: 0, episodes: 0, no_time: true, sequence: "down down up down" },
      ] }),
    forensicLeaks: async () => ({ job: "j0", processes: 140, min_rounds: 3, min_growth: 1048576, warnings: [], leaks: [
      { host: "CORE1_10.1.255.1", process: "BGP Router", pid: 312, rounds: 5, from_round: 1, to_round: 5, series: [10485760, 11534336, 13631488, 17825792, 25165824], growth: 14680064, per_hour: 3670016 },
      { host: "DIST1_10.1.0.1", process: "IP Input", pid: 58, rounds: 4, from_round: 2, to_round: 5, series: [8388608, 8650752, 9437184, 10485760], growth: 2097152, per_hour: 700000 },
    ] }),
    aclImport: async () => ({ name: "EDGE-IN", rules: [
      { action: "permit", protocol: "tcp", source: "10.1.10.0/24", destination: "any", sourcePorts: "", destinationPorts: "eq 443", log: false, established: false, remark: "" },
      { action: "permit", protocol: "tcp", source: "10.1.10.0/24", destination: "172.31.0.0/16", sourcePorts: "", destinationPorts: "eq 22", log: true, established: false, remark: "" },
      { action: "deny", protocol: "ip", source: "any", destination: "172.31.0.5", sourcePorts: "", destinationPorts: "", log: true, established: false, remark: "" },
    ] }),
    aclAnalyze: async () => [{ index: 1, kind: "shadowed", detail: "rule 1 (permit) already covers everything this one matches" }],
    analysisRun: async () => ({ dir: "/outputs/j0", devices: ["ACC1_10.1.1.1", "DIST1_10.1.0.1"], rounds: [1, 2, 3], missing: [], warnings: [], findings: [
      { rule: "cpu-alta", title: "High CPU", severity: "alta" as const, device: "DIST1_10.1.0.1", round: 3, at: ago(20), command: "show processes cpu sorted", evidence: ["CPU utilization for five seconds: 95%/4%; one minute: 93%; five minutes: 91%"], detail: "5 min: 91% (threshold 80%)", explanation: "The average exceeds the threshold.", action: "Check the processes that use the most CPU." },
      { rule: "log-mallocfail", title: "Memory allocation failure", severity: "critica" as const, device: "ACC1_10.1.1.1", round: 2, at: ago(35), command: "show logging", evidence: ["%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed"], detail: "1 event", explanation: "The device ran out of free memory.", action: "Check show memory statistics." },
    ] }),
    analysisTimeline: async () => ({ dir: "/outputs/j0", warnings: [], events: [
      { at: ago(50), source: "syslog", device: "ACC1_10.1.1.1", severity: "media" as const, text: "%LINK-3-UPDOWN: Interface Gi1/0/3, changed state to down", kb: "%LINK-3-UPDOWN: The link went down." },
      { at: ago(49), source: "log-equipo", device: "ACC1_10.1.1.1", severity: "baja" as const, text: "%LINK-3-UPDOWN: Interface Gi1/0/3, changed state to up" },
      { at: ago(35), source: "hallazgo", device: "ACC1_10.1.1.1", severity: "critica" as const, text: "Memory allocation failure", note: "round 2" },
      { at: ago(20), source: "hallazgo", device: "DIST1_10.1.0.1", severity: "alta" as const, text: "High CPU: 5 min 91%" },
    ] }),
    // Changes: one window with full PRE and POST and a report with an OSPF regression.
    listChanges: async () => [
      { id: "ch1", name: "CRQ-48213 VTY timeout tuning", preJobId: "j20", preState: "completed", postJobId: "j21", postState: "completed" },
      { id: "ch2", name: "CRQ-48377 Migration to OSPF area 10", preJobId: "j22", preState: "completed", postJobId: "", postState: "" },
    ],
    changeReport: async () => ({ text: "", json: JSON.stringify({ devices: [
      { address: "10.20.0.1", hostname: "DIST-01", verdict: "regression",
        findings: [{ facet: "ospf", level: "regression", detail: "10.20.0.3 @ Gi1/0/24: FULL → INIT" }, { facet: "interfaces", level: "review", detail: "Gi1/0/24 input errors 0 → 214" }],
        config_diff: ["- line vty 0 15 > exec-timeout 0 0", "+ line vty 0 15 > exec-timeout 10 0", "+ interface GigabitEthernet1/0/24 > ip ospf cost 500"] },
      { address: "10.20.0.2", hostname: "DIST-02", verdict: "review", findings: [{ facet: "vlans", level: "review", detail: "VLAN 120 has no active ports" }], config_diff: ["+ line vty 0 15 > exec-timeout 10 0"] },
      { address: "10.20.0.4", hostname: "ACC-07", verdict: "ok", findings: [], config_diff: [] },
    ], note: "Fixtures not validated in the lab." }) }),
    // Batches: four devices by three commands, with one error cell and one empty cell.
    adhocResult: async () => adhocSample,
    // Visibility: polling, flows and traps emit sample events through the double (window.core.emitVis).
    snmpPollStart: async () => { visSnmp(); return "p1"; },
    flowsStart: async () => { visFlows(); return "f1"; },
    trapsStart: async () => { visTraps(); return "t1"; },
    // Security: output shaped like the core's reports (RADIUS, TACACS+ and PKI decoding).
    secRadius: async () => `RADIUS server 10.20.0.30:1812 (method PAP)

access-request: Access-Accept in 4.2 ms (attempt 1, Message-Authenticator valid)
  Reply-Message              Welcome, netops
  Tunnel-Private-Group-ID    120
  Filter-Id                  PERMIT-MGMT

status-server: Access-Reject in 2.8 ms (attempt 1, Message-Authenticator valid)
  Reply-Message              Unknown user

Findings:
  [warning] access-request: the response has no Message-Authenticator; the server is vulnerable to Blast-RADIUS (CVE-2024-3596). Update it and require Message-Authenticator.
`,
    secTacacs: async () => `TACACS+ server 10.20.0.31:49

authentication: PASS in 12.4 ms

authorization: PASS_ADD in 8.0 ms
  sent     service=shell
  sent     cmd=show running-config
  received priv-lvl=15

accounting-start: no response
  ! timed out

Findings:
  [error] accounting-start: the server did not answer
`,
    secPkiDecode: async () => `certificate: CN=ise01.lab.local,O=Lab
  Issuer           CN=Lab Issuing CA,O=Lab
  Serial           0A1B2C3D
  Validity         2026-01-10T00:00:00Z → 2026-11-20T00:00:00Z (14 days)
  Key              ECDSA P-256
  Signature        ECDSA-SHA256
  SAN              ise01.lab.local, 10.20.0.30
  SHA-1            3A:9F:12:C4:55:E0:7B:91:0D:AA:42:19:8E:67:B3:C0:D1:2F:44:08
  SHA-256          9C:41:0E:7A:B2:33:5D:E8:6F:01:AA:C7:19:84:D2:5B:3E:70:F6:2A:91:C8:04:BD:57:E3:1A:66:0F:D9:42:8B
  ! expires in 14 days

certificate: CN=Lab Issuing CA,O=Lab
  Issuer           CN=Lab Root CA,O=Lab
  Validity         2023-06-01T00:00:00Z → 2028-06-01T00:00:00Z (572 days)
  Key              ECDSA P-384
  CA               yes
  SHA-256          5B:22:AA:10:7E:C3:90:F4:61:08:DD:3C:A7:15:E9:42:B0:6D:81:2E:F7:93:0A:4C:D5:68:1B:E0:37:9A:C2:7F

certificate: CN=Lab Root CA,O=Lab
  Issuer           CN=Lab Root CA,O=Lab
  Validity         2016-01-01T00:00:00Z → 2026-10-01T00:00:00Z (-36 days)
  Key              RSA 4096
  CA               yes
  SHA-256          E1:0C:7D:42:93:BA:58:2F:A6:D4:11:C9:3B:80:6E:F5:27:9D:0A:B3:64:1E:C8:75:F2:49:8A:03:DB:5C:90:16
`,
    // Calculators: subnet and VLSM in the core's table format.
    calc: async (kind: string) => kind === "vlsm"
      ? { text: "", notes: ["Free space: 10.20.0.192/26"], tables: [{ title: "VLSM over 10.20.0.0/24",
        head: ["Name", "Hosts", "Prefix", "Mask", "First", "Last", "Broadcast", "Capacity", "Unused"],
        rows: [["sales", "100", "10.20.0.0/25", "255.255.255.128", "10.20.0.1", "10.20.0.126", "10.20.0.127", "126", "26"],
          ["voice", "50", "10.20.0.128/26", "255.255.255.192", "10.20.0.129", "10.20.0.190", "10.20.0.191", "62", "12"]] }] }
      : { text: "", notes: [], tables: [{ title: "Subnet 10.20.7.0/24", head: ["Field", "Value"],
        rows: [["Network", "10.20.7.0"], ["Broadcast", "10.20.7.255"], ["First usable", "10.20.7.1"], ["Last usable", "10.20.7.254"], ["Addresses", "256"], ["Usable hosts", "254"],
          ["Prefix", "/24"], ["Mask", "255.255.255.0"], ["Wildcard", "0.0.0.255"], ["Class", "A"], ["Type", "private (RFC 1918)"]] }] },
    // Backups: two devices with several snapshots; content and diff come from sample configurations.
    backupList: async () => ({ masked: false, backups }),
    backupGet: async (id: string) => { const i = Math.max(0, backups.findIndex((x) => x.id === id)); return { meta: backups[i], text: backupConfig(backups[i].device, i) }; },
    backupDiff: async (from: string, to: string) => ({ from: backups.find((x) => x.id === from) ?? backups[1], to: backups.find((x) => x.id === to) ?? backups[0], added: 0, removed: 0, changes: [], ignored: ["ntp clock-period 36029"], masked: false }),
  };
}

// English overrides of the module fakes (those feed the tests and stay in Spanish; the Spanish literals below are the source strings to replace): same shape, same counts.
const swap = <T,>(v: T, pairs: [string, string][]): T => {
  // Un par que no reemplaza nada es un literal que cambió en el fake: la captura saldría en español sin avisar.
  const all = JSON.stringify(v);
  for (const [p] of pairs) if (!all.includes(JSON.stringify(p).slice(1, -1))) console.warn(`preview swap: "${p}" no aparece en el fake`);
  const m = (x: unknown): unknown => typeof x === "string" ? pairs.reduce((r, [p, q]) => r.split(p).join(q), x) : Array.isArray(x) ? x.map(m) : x && typeof x === "object" ? Object.fromEntries(Object.entries(x).map(([k, y]) => [k, m(y)])) : x;
  return m(v) as T;
};
const hostsEn: Host[] = [
  { id: "a".repeat(32), name: "LAB-CORE", address: "10.9.0.1", port: 22, platform: "ios-xe", folder: "Lab", tags: ["core"], credentialId: "c".repeat(32), credentialLabel: "lab-admin", notes: "floor 2" },
  { id: "b".repeat(32), name: "LAB-AP", address: "ap1.lab", port: 2222, platform: "wlc", folder: "Lab", tags: [], credentialId: "", credentialLabel: "", notes: "" },
  { id: "d".repeat(32), name: "OFFICE-SW", address: "10.8.0.1", port: 22, platform: "", folder: "Office", tags: ["access", "dc-1"], credentialId: "", credentialLabel: "", notes: "" },
];
const devicesEn = swap(sampleDevices, [["CAIDO", "DOWN-SW"], ["SOLO-RESP", "BACKUP-ONLY"]]);
const importEn = swap(sampleHostsImport, [
  ["1 host(s) traen una etiqueta de credencial que no está en la bóveda (o está repetida) y quedarían sin credencial", "1 host(s) carry a credential label that is not in the vault (or is repeated) and would be left without a credential"],
  ['dirección "admin@10.0.0.9": use una IP o un nombre DNS', 'address "admin@10.0.0.9": use an IP or a DNS name (letters, digits and hyphens), without spaces, @, scheme, port or path'],
  ["tiene 3 columnas; se esperaban 8", "has 3 columns; 8 were expected"],
  ["NUEVO", "NEW-HOST"], ["OTRO-NOMBRE", "OTHER-NAME"], ["Oficina", "Office"], ["acceso", "access"], ["admin lab", "lab-admin"], ["no existe", "missing-cred"], ["OFI-SW", "OFFICE-SW"],
]);
const hostFieldsEn = swap(sampleHostFields, [
  ["Nombre del host: 1 a 64 caracteres, sin espacios en los extremos. No se repite (sin importar mayúsculas).", "Host name: 1 to 64 characters, no leading or trailing spaces. Not repeated (case-insensitive)."],
  ["IP o nombre DNS, sin usuario, esquema, puerto ni ruta. La dirección con el puerto no se repite.", "IP or DNS name, without user, scheme, port or path. The address with the port is not repeated."],
  ["Puerto SSH, de 1 a 65535. Vacío = 22.", "SSH port, from 1 to 65535. Empty = 22."],
  ["Plataforma: ios, ios-xe, nx-os, asa, iosxr, wlc. Vacío = sin definir.", "Platform: ios, ios-xe, nx-os, asa, iosxr, wlc. Empty = not set."],
  ["Carpeta de un solo nivel: 1 a 48 caracteres entre letras, números, espacio, _, . y -. Vacío = sin carpeta.", "Single-level folder: 1 to 48 characters among letters, digits, space, _, . and -. Empty = no folder."],
  ["Hasta 10 etiquetas de 1 a 24 caracteres entre a-z, 0-9 y -. En CSV separadas por «;»; en JSON, un arreglo.", "Up to 10 tags of 1 to 24 characters among a-z, 0-9 and -. In CSV separated by \";\"; in JSON, an array."],
  ["Etiqueta de una credencial de la bóveda local (nunca el usuario ni la contraseña).", "Label of a credential in the local vault (never the user or the password)."],
  ["Notas libres, hasta 2000 caracteres.", "Free notes, up to 2000 characters."],
  ["Piso 2", "Floor 2"], ["admin lab", "lab-admin"],
]);
const hostsTemplate = (format: "csv" | "json") => {
  const rows = [["SW-CORE", "10.0.0.1", "22", "ios-xe", "Lab", "core;dc-1", "lab-admin", "Floor 2"], ["SW-ACC1", "10.0.0.2", "22", "nx-os", "Lab", "access", "", ""], ["AP-1", "ap1.lab.example.com", "2222", "wlc", "Office", "wifi", "", ""]];
  const names = hostFieldsEn.map((f) => f.name);
  return { format, filename: `hosts-plantilla.${format}`, content: format === "csv" ? "\ufeff" + [names, ...rows].map((r) => r.join(",")).join("\n") + "\n"
    : JSON.stringify({ formato: "macuahuitl-hosts", version: 1, exportado: new Date().toISOString(), hosts: rows.map((r) => Object.fromEntries(names.map((n, i) => [n, r[i]]))) }, null, 2) };
};
const playbooksEn = swap(samplePlaybooks, [["TAC · Línea base", "TAC · Baseline"], ["TAC · Usuario sin red", "TAC · User with no connectivity"], ["L2 · VLAN y troncales", "L2 · VLANs, trunks and VTP"]]);
const restoreEn = swap(sampleRestore, [["PC-contabilidad", "PC-accounting"], ["PC-ventas", "PC-sales"]]);

type Ago = (min: number) => string;
const stamp = (iso: string) => iso.replace(/[-:]|\.\d+/g, "");
function backupSamples(ago: Ago) {
  const mk = (dev: string, min: number, bytes: number, masked = false) => {
    const at = ago(min);
    return { id: `${dev}/${stamp(at)}-running`, device: dev, kind: "running" as const, at, bytes, masked };
  };
  return [
    mk("SW1-CORE_10.20.0.1", 25, 18204), mk("SW1-CORE_10.20.0.1", 24 * 60 + 25, 18110), mk("SW1-CORE_10.20.0.1", 3 * 24 * 60 + 25, 17630, true),
    mk("R1-WAN_10.20.0.254", 40, 9420), mk("R1-WAN_10.20.0.254", 2 * 24 * 60 + 40, 9388),
  ];
}
// The older the backup, the further back the VLAN and port description (so the diff shows something).
function backupConfig(device: string, i: number) {
  const first = i === 0 || i === 3;
  return [`hostname ${device.split("_")[0]}`, "!", "interface GigabitEthernet1/0/14", ` description ${first ? "CASHIER-07" : "PC-accounting"}`, ` switchport access vlan ${first ? 20 : 10}`,
    " no shutdown", ...(first ? [" spanning-tree portfast"] : []), "!", "ntp clock-period 36029", "ntp server 10.0.0.2", "end", ""].join("\n");
}

const adhocDevs: [string, string][] = [["SW1-CORE", "10.20.0.1"], ["SW2-CORE", "10.20.0.2"], ["R1-WAN", "10.20.0.254"], ["ACC-07", "10.20.7.1"]];
const adhocCmds = ["show version | include uptime", "show ip interface brief", "show ntp status"];
const adhocOut = (d: string, c: string) => c.startsWith("show version") ? `${d} uptime is 47 weeks, 3 days, 4 hours, 12 minutes`
  : c.startsWith("show ip") ? "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0     10.20.0.1       YES NVRAM  up                    up\nGigabitEthernet0/1     unassigned      YES unset  administratively down down"
  : "Clock is synchronized, stratum 3, reference is 10.0.0.2";
const adhocRows = adhocDevs.flatMap(([device, address]) => adhocCmds.map((command) => {
  if (device === "ACC-07") return { device, address, command, ok: false, output: "", note: "Timed out opening the SSH session" };
  if (device === "R1-WAN" && command.includes("ntp")) return { device, address, command, ok: true, output: "" };
  return { device, address, command, ok: true, output: adhocOut(device, command) };
}));
const adhocSample = { state: "completed", done: true, text: adhocRows.map((r) => `== ${r.device} (${r.address}) ==\n$ ${r.command}\n${r.output || r.note || ""}`).join("\n\n"),
  csv: "device,address,command,status\n" + adhocRows.map((r) => `${r.device},${r.address},"${r.command}",${r.ok ? "ok" : "error"}`).join("\n"), markdown: "| Device | Command | Status |",
  report: { commands: adhocCmds, devices: adhocDevs.length, rows: adhocRows } };

const emitVis = (kind: string, e: unknown) => (window as unknown as { core?: { emitVis?: (k: string, e: unknown) => void } }).core?.emitVis?.(kind, e);
const IFS: [string, number, number][] = [["Gi1/0/1", 420, 260], ["Gi1/0/2", 90, 140], ["Gi1/0/24", 610, 330], ["Te1/1/1", 0, 0]];
function visSnmp() {
  const one = (k: number, back: number) => ({
    Time: new Date(Date.now() - back * 1000).toISOString(), System: { sysName: "SW1-CORE", sysDescr: "Cisco IOS XE Software, Version 17.09.04a" },
    Interfaces: IFS.map(([Name, i, o]) => ({ Name, Oper: i + o ? "up" : "down", InBps: i ? (i + 160 * Math.sin(k / 3) + (k % 5) * 12) * 1e6 : null, OutBps: o ? (o + 70 * Math.sin(k / 4 + 1)) * 1e6 : null, InErrors: Name === "Gi1/0/24" ? 3 : 0, OutErrors: 0 })),
  });
  setTimeout(() => { for (let k = 0; k < 30; k++) emitVis("snmp", { runId: "p1", json: JSON.stringify(one(k, (30 - k) * 10)) }); }, 60);
  let n = 30;
  setInterval(() => emitVis("snmp", { runId: "p1", json: JSON.stringify(one(n++, 0)) }), 5000);
}
function visFlows() {
  const t = (Key: string, MiB: number, Flows: number) => ({ Key, Bytes: Math.round(MiB * 1048576), Packets: Math.round(MiB * 700), Flows });
  setTimeout(() => emitVis("flows", { runId: "f1", json: JSON.stringify({ Flows: 1840, Bytes: 912 * 1048576, Errors: 0,
    Talkers: [t("10.20.7.15", 318, 410), t("10.20.3.40", 204.5, 220), t("10.20.0.9", 121, 96), t("172.16.4.2", 88.4, 310), t("10.20.7.44", 47.2, 150), t("192.0.2.77", 9.8, 40)],
    Conversations: [{ Key: "10.20.7.15 → 172.16.4.2", Bytes: 301 * 1048576, Packets: 210000, Flows: 38 }], Ports: [{ Key: "443/tcp", Bytes: 540 * 1048576, Packets: 400000, Flows: 900 }], Protocols: [{ Key: "tcp", Bytes: 800 * 1048576, Packets: 600000, Flows: 1500 }], Exporters: [] }) }), 60);
}
function visTraps() {
  const list: [string, string, string][] = [["10.20.0.1:5100", "linkDown", "linkDown GigabitEthernet1/0/24 oper down"], ["10.20.0.1:5100", "linkUp", "linkUp GigabitEthernet1/0/24 oper up"],
    ["10.20.0.254:5100", "authenticationFailure", "authenticationFailure from 192.0.2.77"], ["10.20.7.1:5101", "coldStart", "coldStart"], ["10.20.0.2:5100", "linkDown", "linkDown TenGigabitEthernet1/1/1 oper down"], ["10.20.0.2:5100", "linkUp", "linkUp TenGigabitEthernet1/1/1 oper up"]];
  list.forEach(([From, Name, Summary], k) => setTimeout(() => emitVis("traps", { runId: "t1", json: JSON.stringify({ From, Name, Summary, Version: "2c" }) }), 80 + k * 20));
}

// Sample device for the SSH terminal: banner, IOS prompt and an echo for a few known commands.
// Each open is a session (p1, p2…) with its own device; output has no colors so keyword highlighting shows.
function previewTerminal(): Partial<CoreAPI> {
  const core = () => (window as unknown as { core: { emitTerminal: (e: { runId: string; data?: string; opened?: string; recording?: string }) => void } }).core;
  const brief = "Interface              IP-Address      OK? Method Status                Protocol\r\nGigabitEthernet1/0/1   10.20.7.1       YES NVRAM  up                    up\r\nGigabitEthernet1/0/2   10.20.7.5       YES NVRAM  administratively down down\r\nGigabitEthernet1/0/24  unassigned      YES unset  down                  down\r\nVlan10                 10.20.10.1      YES NVRAM  up                    up\r\n";
  const out: Record<string, string> = {
    "show ip interface brief": brief,
    "show version": "Cisco IOS Software, C3560CX Software (C3560CX-UNIVERSALK9-M), Version 15.2(7)E3\r\nSW1 uptime is 41 weeks, 2 days, 3 hours, 12 minutes\r\n",
    "show logging": "*Nov  6 10:14:02.113: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet1/0/24, changed state to down\r\n*Nov  6 10:14:03.120: %LINK-3-UPDOWN: Interface GigabitEthernet1/0/24, changed state to down\r\n*Nov  6 10:15:40.007: %SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed\r\n*Nov  6 10:16:11.442: %SPANTREE-2-ROOTGUARD_BLOCK: Root guard blocking port GigabitEthernet1/0/3 on VLAN0010\r\n",
  };
  const hosts = new Map<string, string>();
  const lines = new Map<string, string>();
  let n = 0;
  return {
    terminalOpen: async (r) => {
      const id = `p${++n}`;
      const host = r.name.replace(/[^\w]/g, "").slice(0, 8).toUpperCase() || "SW1";
      hosts.set(id, host); lines.set(id, "");
      setTimeout(() => {
        core().emitTerminal({ runId: id, opened: `netops@${r.address}:22`, recording: `outputs/terminal/${r.address}.log` });
        core().emitTerminal({ runId: id, data: `\r\nUnauthorized access is prohibited.\r\n\r\n${host}#show ip interface brief\r\n${brief}${host}#show logging\r\n${out["show logging"]}${host}#` });
      }, 50);
      return id;
    },
    terminalSend: async (id: string, d: string) => {
      const host = hosts.get(id) ?? "SW1";
      const emit = (data: string) => core().emitTerminal({ runId: id, data });
      for (const ch of d) {
        const line = lines.get(id) ?? "";
        if (ch === "\r") { const o = out[line.trim()]; emit("\r\n" + (o ?? (line.trim() ? "% Invalid input detected at '^' marker.\r\n" : "")) + `${host}#`); lines.set(id, ""); }
        else if (ch === "\x7f") { if (line) { lines.set(id, line.slice(0, -1)); emit("\b \b"); } }
        else if (ch === "\x03") { lines.set(id, ""); emit(`^C\r\n${host}#`); }
        else if (ch >= " ") { lines.set(id, line + ch); emit(ch); }
      }
    },
  };
}

// Sample scripts: a slice of the library (read-only diagnostics and config templates) and three of the user's own, two favorites.
function previewScripts(): ScriptItem[] {
  const t0 = Date.UTC(2026, 10, 7, 12, 0, 0);
  const mk = (id: string, name: string, p: Partial<ScriptItem>): ScriptItem => ({ id, name, tech: "diagnostico", platform: "ios-xe", description: "", commands: [], tags: [], origin: "usuario", createdMs: t0, updatedMs: t0, readOnly: false, favorite: false, pinned: false, collections: [], ...p });
  const lib = (id: string, name: string, p: Partial<ScriptItem>) => mk(`lib-${id}`, name, { origin: "biblioteca", ...p });
  return [
    lib("l2-stp", "L2 · STP", { tech: "l2", readOnly: true, favorite: true, description: "Root, ports and spanning-tree topology.", commands: ["show spanning-tree summary", "show spanning-tree root", "show spanning-tree blockedports"], tags: ["stp"] }),
    lib("l2-vlan", "L2 · VLANs and trunks", { tech: "l2", readOnly: true, description: "Active VLANs and trunks.", commands: ["show vlan brief", "show interfaces trunk"], tags: ["vlan", "trunk"] }),
    lib("l3-ospf", "L3 · OSPF", { tech: "l3", readOnly: true, description: "OSPF neighbors, interfaces and database.", commands: ["show ip ospf neighbor", "show ip ospf interface brief", "show ip ospf database"], tags: ["ospf"] }),
    lib("seg-ssh", "Security · SSH", { tech: "seguridad", readOnly: true, commands: ["show ip ssh", "show ssh"], tags: ["ssh"] }),
    lib("cfg-vlan-acceso", "Config · VLAN and access port", { tech: "l2", description: "Template not validated in the lab.", commands: ["configure terminal", "vlan 10", " name USERS", "interface GigabitEthernet1/0/10", " switchport mode access", " switchport access vlan 10", "end"], tags: ["vlan", "access"] }),
    lib("cfg-ntp", "Config · NTP", { tech: "gestion", commands: ["configure terminal", "ntp server 192.0.2.10", "end"], tags: ["ntp"] }),
    lib("nxos-vpc", "NX-OS · vPC", { tech: "l2", platform: "nx-os", commands: ["show vpc", "show vpc peer-keepalive"], tags: ["vpc"] }),
    mk("a".repeat(32), "My OSPF", { tech: "l3", readOnly: true, favorite: true, description: "Quick neighbor check.", commands: ["show ip ospf neighbor"], tags: ["ospf"] }),
    mk("e".repeat(32), "CDP and LLDP neighbors", { tech: "diagnostico", readOnly: true, favorite: true, commands: ["show cdp neighbors", "! comment", "show lldp neighbors"], tags: ["cdp", "lldp"] }),
    mk("f".repeat(32), "Unused ports", { tech: "gestion", description: "Lists and shuts down unused ports (review first).", commands: ["show interfaces status | include notconnect", "configure terminal", "interface range Gi1/0/20 - 24", " shutdown", "end"], tags: ["ports"] }),
  ];
}

// Scripts with sample collections and pins (the in-memory API is seeded through its own calls).
function previewScriptsApi() {
  const api = fakeScripts(previewScripts());
  void (async () => {
    const mk = async (name: string, description: string, ids: string[]) => { const c = await api.saveCollection({ name, description }); await api.setCollectionScripts(c.id, ids); };
    await mk("Campus", "", ["lib-l2-vlan", "lib-l2-stp", "e".repeat(32), "lib-seg-ssh"]);
    await mk("WAN edge", "", ["lib-l3-ospf", "a".repeat(32)]);
    await mk("Lab", "", ["lib-cfg-vlan-acceso", "lib-cfg-ntp", "f".repeat(32)]);
    for (const id of ["lib-l2-stp", "lib-l3-ospf", "e".repeat(32)]) await api.setScriptPinned(id, true);
  })();
  return api;
}
