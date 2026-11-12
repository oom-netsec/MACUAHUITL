import type { CoreAPI } from "../lib/core";
import { dnsTraceSample, pcapSample, tlsSample } from "../modules/tools/samples";
import { fakeScripts } from "../modules/scripts/fake";
import type { ScriptItem } from "../modules/scripts/api";

// Datos de ejemplo para que cada vista se vea como en uso real; se amplía módulo por módulo.
export function sample(): Partial<CoreAPI> {
  const ago = (min: number) => new Date(Date.now() - min * 60_000).toISOString();
  const backups = backupSamples(ago);
  return {
    ...previewTerminal(),
    ...previewScriptsApi(),
    listCredentials: async () => [
      { id: "c1", label: "Core DC", username: "netops", hasEnable: true, hasSshKey: false },
      { id: "c2", label: "Acceso sucursales", username: "tac", hasEnable: false, hasSshKey: true },
      { id: "c3", label: "Laboratorio", username: "lab", hasEnable: true, hasSshKey: true },
      { id: "c4", label: "ISE (secreto RADIUS)", username: "-", hasEnable: false, hasSshKey: false },
      { id: "c5", label: "WAN edge", username: "wanops", hasEnable: true, hasSshKey: false },
    ],
    getRun: async () => [
      { target: "10.0.0.1:22", state: "DEVICE_STATE_COMPLETED", detail: "" },
      { target: "10.0.0.2:22", state: "DEVICE_STATE_RUNNING", detail: "" },
      { target: "10.0.0.3:22", state: "DEVICE_STATE_FAILED", detail: "tiempo agotado" },
    ],
    auditVerify: async () => ({ intact: true, firstBroken: 0, head: "7f3a9c01d4e2b685a0c7e1f93b24d86a5c10e7ab9d3f2468c1b05e7a94d3c2f8" }),
    listJobs: async () => [
      { id: "j0", name: "Respaldo nocturno core", state: "armed", armedAt: ago(135), round: 3, rounds: 6, devicesTotal: 24, devicesOk: 22, devicesFailed: 1, outputDir: "/home/u/evidencia/nocturno-core",
        phases: [{ at: ago(140), kind: "JOB_PHASE_KIND_CREATED" }, { at: ago(135), kind: "JOB_PHASE_KIND_ARMED", detail: "24 equipos" }] },
      { id: "j9", name: "Caso TAC 6942", state: "completed", round: 1, rounds: 1, devicesTotal: 3, devicesOk: 3, devicesFailed: 0, outputDir: "/home/u/evidencia/caso-6942",
        phases: [{ at: ago(900), kind: "JOB_PHASE_KIND_COMPLETED", detail: "1 ronda" }] },
    ],
    // Herramientas, Limpiador, Flota, Forense, ACL y Corridas (utilidades de redes).
    toolsPcap: async () => pcapSample,
    toolsDns: async (r) => (r.mode === "trace" ? dnsTraceSample : "{}"),
    toolsTls: async () => tlsSample,
    cleanerRun: async (text) => ({ report: { changes: [], orphans: [{ line: 7, text: " ip access-group IN-FALTA in", why: "ACL IN-FALTA no existe (ip access-group)" }] }, text: "3 líneas vacías quitadas\n\n1 HUÉRFANA",
      output: text.replace(/\n{2,}/g, "\n").replace(/^!\n(?=!)/gm, "") }),
    fleetPath: async () => ({ svg: "", result: { src: "10.1.10.20", dst: "172.31.0.1", arrived: false, warnings: [], hops: [
      { id: 0, parent: -1, device: "ACC1", route: "S* 0.0.0.0/0", status: "ok" as const, source: "show ip route", at: ago(40) },
      { id: 1, parent: 0, device: "DIST1", via: "10.1.0.1", out_if: "Te1/1/1", segment: { interface: "Vlan10", vlan: "10", l2: [{ device: "ACC2", port: "Gi1/0/24", source: "show mac address-table", at: ago(40) }] }, status: "ok" as const, source: "show ip route", at: ago(40) },
      { id: 2, parent: 1, device: "CORE1", via: "10.1.255.1", out_if: "Po1", ecmp: true, status: "ok" as const, source: "show ip route", at: ago(41) },
      { id: 3, parent: 1, device: "CORE2", via: "10.1.255.5", out_if: "Po2", ecmp: true, status: "ok" as const, source: "show ip route", at: ago(41) },
      { id: 4, parent: 2, device: "EDGE1", via: "10.2.0.1", out_if: "Te1/0/1", segment: { interface: "Te1/0/1", vlan: "300" }, status: "arrived" as const, reason: "destino conectado", source: "show ip route", at: ago(42) },
      { id: 5, parent: 3, device: "10.2.0.5", via: "10.2.0.5", out_if: "Te1/0/2", status: "cut" as const, reason: "sin evidencia del siguiente equipo", at: "0001-01-01T00:00:00Z" },
    ] } }),
    fleetHealth: async () => ({ devices: 12, warnings: [], issues: [
      { device: "ACC1", port: "Gi1/0/9", severity: "critica" as const, problems: [{ kind: "err-disabled", evidence: "Gi1/0/9 err-disabled (psecure-violation)" }], source: "show interfaces status", at: ago(30) },
      { device: "ACC1", port: "Gi1/0/12", severity: "media" as const, problems: [{ kind: "crc", value: 412, evidence: "412 CRC" }], source: "show interfaces", at: ago(30) },
      { device: "ACC2", port: "Gi1/0/3", severity: "alta" as const, problems: [{ kind: "crc", value: 9120, evidence: "9120 CRC" }, { kind: "duplex", evidence: "half-duplex" }], source: "show interfaces", at: ago(32) },
      { device: "DIST1", port: "Te1/1/1", severity: "baja" as const, problems: [{ kind: "drops", value: 31, evidence: "31 output drops" }], source: "show interfaces", at: ago(33) },
    ] }),
    fleetSummary: async () => ({ devices: 12, checked: { cpu: 12, ntp: 12, reboot: 12, memory: 12, flash: 12 }, warnings: [], rows: [
      { device: "ACC1", check: "ntp", value: "no sincronizado", source: "show ntp status", at: ago(30) },
      { device: "ACC2", check: "cpu", value: "92 %", source: "show processes cpu", at: ago(30) },
      { device: "ACC2", check: "flash", value: "97 % usado", source: "dir flash:", at: ago(31) },
      { device: "DIST1", check: "reboot", value: "hace 2 h", source: "show version", at: ago(33) },
    ] }),
    forensicFlapping: async () => ({ source: "show logging del trabajo j0", interfaces: 3, transitions: 19, count: 3, window: "1m0s", warnings: [], counter_jumps: [],
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
    aclAnalyze: async () => [{ index: 1, kind: "shadowed", detail: "la regla 1 ya cubre este tráfico" }],
    analysisRun: async () => ({ dir: "/outputs/j0", devices: ["ACC1_10.1.1.1", "DIST1_10.1.0.1"], rounds: [1, 2, 3], missing: [], warnings: [], findings: [
      { rule: "cpu-alta", title: "CPU alta", severity: "alta" as const, device: "DIST1_10.1.0.1", round: 3, at: ago(20), command: "show processes cpu sorted", evidence: ["CPU utilization for five seconds: 95%/4%; one minute: 93%; five minutes: 91%"], detail: "5 min: 91 % (umbral 80 %)", explanation: "El promedio supera el umbral.", action: "Revisa los procesos que más CPU usan." },
      { rule: "log-mallocfail", title: "Falla de asignación de memoria", severity: "critica" as const, device: "ACC1_10.1.1.1", round: 2, at: ago(35), command: "show logging", evidence: ["%SYS-2-MALLOCFAIL: Memory allocation of 65536 bytes failed"], detail: "1 evento", explanation: "El equipo se quedó sin memoria libre.", action: "Revisa show memory statistics." },
    ] }),
    analysisTimeline: async () => ({ dir: "/outputs/j0", warnings: [], events: [
      { at: ago(50), source: "syslog", device: "ACC1_10.1.1.1", severity: "media" as const, text: "%LINK-3-UPDOWN: Interface Gi1/0/3, changed state to down", kb: "%LINK-3-UPDOWN: El enlace bajó." },
      { at: ago(49), source: "log-equipo", device: "ACC1_10.1.1.1", severity: "baja" as const, text: "%LINK-3-UPDOWN: Interface Gi1/0/3, changed state to up" },
      { at: ago(35), source: "hallazgo", device: "ACC1_10.1.1.1", severity: "critica" as const, text: "Falla de asignación de memoria", note: "ronda 2" },
      { at: ago(20), source: "hallazgo", device: "DIST1_10.1.0.1", severity: "alta" as const, text: "CPU alta: 5 min 91 %" },
    ] }),
    // Cambios: una ventana con PRE y POST completos y un reporte con una regresión de OSPF.
    listChanges: async () => [
      { id: "ch1", name: "CRQ-48213 Ajuste de timeouts VTY", preJobId: "j20", preState: "completed", postJobId: "j21", postState: "completed" },
      { id: "ch2", name: "CRQ-48377 Migración a OSPF área 10", preJobId: "j22", preState: "completed", postJobId: "", postState: "" },
    ],
    changeReport: async () => ({ text: "", json: JSON.stringify({ devices: [
      { address: "10.20.0.1", hostname: "DIST-01", verdict: "regression",
        findings: [{ facet: "ospf", level: "regression", detail: "10.20.0.3 @ Gi1/0/24: FULL → INIT" }, { facet: "interfaces", level: "review", detail: "Gi1/0/24 errores de entrada 0 → 214" }],
        config_diff: ["- line vty 0 15 > exec-timeout 0 0", "+ line vty 0 15 > exec-timeout 10 0", "+ interface GigabitEthernet1/0/24 > ip ospf cost 500"] },
      { address: "10.20.0.2", hostname: "DIST-02", verdict: "review", findings: [{ facet: "vlans", level: "review", detail: "VLAN 120 sin puertos activos" }], config_diff: ["+ line vty 0 15 > exec-timeout 10 0"] },
      { address: "10.20.0.4", hostname: "ACC-07", verdict: "ok", findings: [], config_diff: [] },
    ], note: "Fixtures sin validar en laboratorio." }) }),
    // Lotes: cuatro equipos por tres comandos, con una celda con error y otra vacía.
    adhocResult: async () => adhocSample,
    // Visibilidad: el sondeo, los flujos y los traps emiten eventos de ejemplo por el doble (window.core.emitVis).
    snmpPollStart: async () => { visSnmp(); return "p1"; },
    flowsStart: async () => { visFlows(); return "f1"; },
    trapsStart: async () => { visTraps(); return "t1"; },
    // Seguridad: salidas con la forma de los informes del núcleo (RADIUS, TACACS+ y decodificación de PKI).
    secRadius: async () => `Servidor RADIUS 10.20.0.30:1812 (método PAP)

access-request: Access-Accept en 4.2 ms (intento 1, Message-Authenticator válido)
  Reply-Message              Bienvenido, netops
  Tunnel-Private-Group-ID    120
  Filter-Id                  PERMIT-MGMT

status-server: Access-Reject en 2.8 ms (intento 1, Message-Authenticator válido)
  Reply-Message              Usuario desconocido

Hallazgos:
  [aviso] access-request: la respuesta no trae Message-Authenticator; el servidor es vulnerable a Blast-RADIUS
`,
    secTacacs: async () => `Servidor TACACS+ 10.20.0.31:49

authentication: PASS en 12.4 ms

authorization: PASS_ADD en 8.0 ms
  enviado  service=shell
  enviado  cmd=show running-config
  recibido priv-lvl=15

accounting-start: sin respuesta
  ! tiempo de espera agotado

Hallazgos:
  [error] accounting-start: el servidor no respondió
`,
    secPkiDecode: async () => `certificado: CN=ise01.lab.local,O=Lab
  Emisor           CN=Lab Issuing CA,O=Lab
  Serie            0A1B2C3D
  Validez          2026-01-10T00:00:00Z → 2026-11-20T00:00:00Z (14 días)
  Llave            ECDSA P-256
  Firma            ECDSA-SHA256
  SAN              ise01.lab.local, 10.20.0.30
  SHA-1            3A:9F:12:C4:55:E0:7B:91:0D:AA:42:19:8E:67:B3:C0:D1:2F:44:08
  SHA-256          9C:41:0E:7A:B2:33:5D:E8:6F:01:AA:C7:19:84:D2:5B:3E:70:F6:2A:91:C8:04:BD:57:E3:1A:66:0F:D9:42:8B
  ! vence en 14 días

certificado: CN=Lab Issuing CA,O=Lab
  Emisor           CN=Lab Root CA,O=Lab
  Validez          2023-06-01T00:00:00Z → 2028-06-01T00:00:00Z (572 días)
  Llave            ECDSA P-384
  CA               sí
  SHA-256          5B:22:AA:10:7E:C3:90:F4:61:08:DD:3C:A7:15:E9:42:B0:6D:81:2E:F7:93:0A:4C:D5:68:1B:E0:37:9A:C2:7F

certificado: CN=Lab Root CA,O=Lab
  Emisor           CN=Lab Root CA,O=Lab
  Validez          2016-01-01T00:00:00Z → 2026-10-01T00:00:00Z (-36 días)
  Llave            RSA 4096
  CA               sí
  SHA-256          E1:0C:7D:42:93:BA:58:2F:A6:D4:11:C9:3B:80:6E:F5:27:9D:0A:B3:64:1E:C8:75:F2:49:8A:03:DB:5C:90:16
`,
    // Calculadoras: subred y VLSM con el formato de las tablas del núcleo.
    calc: async (kind: string) => kind === "vlsm"
      ? { text: "", notes: ["Espacio libre: 10.20.0.192/26"], tables: [{ title: "VLSM sobre 10.20.0.0/24",
        head: ["Nombre", "Hosts", "Prefijo", "Máscara", "Primera", "Última", "Broadcast", "Capacidad", "Sobrante"],
        rows: [["ventas", "100", "10.20.0.0/25", "255.255.255.128", "10.20.0.1", "10.20.0.126", "10.20.0.127", "126", "26"],
          ["voz", "50", "10.20.0.128/26", "255.255.255.192", "10.20.0.129", "10.20.0.190", "10.20.0.191", "62", "12"]] }] }
      : { text: "", notes: [], tables: [{ title: "Subred 10.20.7.0/24", head: ["Campo", "Valor"],
        rows: [["Red", "10.20.7.0"], ["Broadcast", "10.20.7.255"], ["Primera usable", "10.20.7.1"], ["Última usable", "10.20.7.254"], ["Direcciones", "256"], ["Hosts usables", "254"],
          ["Prefijo", "/24"], ["Máscara", "255.255.255.0"], ["Wildcard", "0.0.0.255"], ["Clase", "A"], ["Tipo", "privada (RFC 1918)"]] }] },
    // Respaldos: dos equipos con varias tomas; el contenido y la diferencia salen de configuraciones de ejemplo.
    backupList: async () => ({ masked: false, backups }),
    backupGet: async (id: string) => { const i = Math.max(0, backups.findIndex((x) => x.id === id)); return { meta: backups[i], text: backupConfig(backups[i].device, i) }; },
    backupDiff: async (from: string, to: string) => ({ from: backups.find((x) => x.id === from) ?? backups[1], to: backups.find((x) => x.id === to) ?? backups[0], added: 0, removed: 0, changes: [], ignored: ["ntp clock-period 36029"], masked: false }),
  };
}

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
// Cuanto más viejo el respaldo, más atrás la VLAN y la descripción del puerto (para que la diferencia muestre algo).
function backupConfig(device: string, i: number) {
  const first = i === 0 || i === 3;
  return [`hostname ${device.split("_")[0]}`, "!", "interface GigabitEthernet1/0/14", ` description ${first ? "CAJA-07" : "PC-contabilidad"}`, ` switchport access vlan ${first ? 20 : 10}`,
    " no shutdown", ...(first ? [" spanning-tree portfast"] : []), "!", "ntp clock-period 36029", "ntp server 10.0.0.2", "end", ""].join("\n");
}

const adhocDevs: [string, string][] = [["SW1-CORE", "10.20.0.1"], ["SW2-CORE", "10.20.0.2"], ["R1-WAN", "10.20.0.254"], ["ACC-07", "10.20.7.1"]];
const adhocCmds = ["show version | include uptime", "show ip interface brief", "show ntp status"];
const adhocOut = (d: string, c: string) => c.startsWith("show version") ? `${d} uptime is 47 weeks, 3 days, 4 hours, 12 minutes`
  : c.startsWith("show ip") ? "Interface              IP-Address      OK? Method Status                Protocol\nGigabitEthernet0/0     10.20.0.1       YES NVRAM  up                    up\nGigabitEthernet0/1     unassigned      YES unset  administratively down down"
  : "Clock is synchronized, stratum 3, reference is 10.0.0.2";
const adhocRows = adhocDevs.flatMap(([device, address]) => adhocCmds.map((command) => {
  if (device === "ACC-07") return { device, address, command, ok: false, output: "", note: "Tiempo de espera agotado al abrir la sesión SSH" };
  if (device === "R1-WAN" && command.includes("ntp")) return { device, address, command, ok: true, output: "" };
  return { device, address, command, ok: true, output: adhocOut(device, command) };
}));
const adhocSample = { state: "completed", done: true, text: adhocRows.map((r) => `== ${r.device} (${r.address}) ==\n$ ${r.command}\n${r.output || r.note || ""}`).join("\n\n"),
  csv: "equipo,direccion,comando,estado\n" + adhocRows.map((r) => `${r.device},${r.address},"${r.command}",${r.ok ? "ok" : "error"}`).join("\n"), markdown: "| Equipo | Comando | Estado |",
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
    ["10.20.0.254:5100", "authenticationFailure", "authenticationFailure desde 192.0.2.77"], ["10.20.7.1:5101", "coldStart", "coldStart"], ["10.20.0.2:5100", "linkDown", "linkDown TenGigabitEthernet1/1/1 oper down"], ["10.20.0.2:5100", "linkUp", "linkUp TenGigabitEthernet1/1/1 oper up"]];
  list.forEach(([From, Name, Summary], k) => setTimeout(() => emitVis("traps", { runId: "t1", json: JSON.stringify({ From, Name, Summary, Version: "2c" }) }), 80 + k * 20));
}

// Equipo de ejemplo para la terminal SSH: banner, prompt de IOS y un eco con algunos comandos conocidos.
// Cada apertura es una sesión (p1, p2…) con su propio equipo; la salida va sin colores para que se vea el resaltado de palabras clave.
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

// Scripts de ejemplo: una muestra de la biblioteca (diagnóstico de solo lectura y plantillas de configuración) y tres propios, dos favoritos.
function previewScripts(): ScriptItem[] {
  const t0 = Date.UTC(2026, 10, 7, 12, 0, 0);
  const mk = (id: string, name: string, p: Partial<ScriptItem>): ScriptItem => ({ id, name, tech: "diagnostico", platform: "ios-xe", description: "", commands: [], tags: [], origin: "usuario", createdMs: t0, updatedMs: t0, readOnly: false, favorite: false, pinned: false, collections: [], ...p });
  const lib = (id: string, name: string, p: Partial<ScriptItem>) => mk(`lib-${id}`, name, { origin: "biblioteca", ...p });
  return [
    lib("l2-stp", "L2 · STP", { tech: "l2", readOnly: true, favorite: true, description: "Raíz, puertos y topología de spanning-tree.", commands: ["show spanning-tree summary", "show spanning-tree root", "show spanning-tree blockedports"], tags: ["stp"] }),
    lib("l2-vlan", "L2 · VLAN y trunks", { tech: "l2", readOnly: true, description: "VLAN activas y trunks.", commands: ["show vlan brief", "show interfaces trunk"], tags: ["vlan", "trunk"] }),
    lib("l3-ospf", "L3 · OSPF", { tech: "l3", readOnly: true, description: "Vecinos, interfaces y base de OSPF.", commands: ["show ip ospf neighbor", "show ip ospf interface brief", "show ip ospf database"], tags: ["ospf"] }),
    lib("seg-ssh", "Seguridad · SSH", { tech: "seguridad", readOnly: true, commands: ["show ip ssh", "show ssh"], tags: ["ssh"] }),
    lib("cfg-vlan-acceso", "Config · VLAN y puerto de acceso", { tech: "l2", description: "Plantilla sin validar en laboratorio.", commands: ["configure terminal", "vlan 10", " name USUARIOS", "interface GigabitEthernet1/0/10", " switchport mode access", " switchport access vlan 10", "end"], tags: ["vlan", "acceso"] }),
    lib("cfg-ntp", "Config · NTP", { tech: "gestion", commands: ["configure terminal", "ntp server 192.0.2.10", "end"], tags: ["ntp"] }),
    lib("nxos-vpc", "NX-OS · vPC", { tech: "l2", platform: "nx-os", commands: ["show vpc", "show vpc peer-keepalive"], tags: ["vpc"] }),
    mk("a".repeat(32), "Mi OSPF", { tech: "l3", readOnly: true, favorite: true, description: "Revisión rápida de vecinos.", commands: ["show ip ospf neighbor"], tags: ["ospf"] }),
    mk("e".repeat(32), "Vecinos CDP y LLDP", { tech: "diagnostico", readOnly: true, favorite: true, commands: ["show cdp neighbors", "! comentario", "show lldp neighbors"], tags: ["cdp", "lldp"] }),
    mk("f".repeat(32), "Puertos sin uso", { tech: "gestion", description: "Lista y apaga puertos sin uso (revisar antes).", commands: ["show interfaces status | include notconnect", "configure terminal", "interface range Gi1/0/20 - 24", " shutdown", "end"], tags: ["puertos"] }),
  ];
}

// Scripts con colecciones y fijados de ejemplo (la API en memoria se siembra con sus propias llamadas).
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
