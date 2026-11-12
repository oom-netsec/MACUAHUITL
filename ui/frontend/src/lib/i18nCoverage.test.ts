/// <reference types="vite/client" />
import { parseAst } from "rolldown/parseAst";
import { es } from "./i18n/es";
import { en } from "./i18n/en";

// Guardia del idioma: es.ts y en.ts tienen las mismas claves y ningún .tsx de la interfaz
// lleva texto visible fijo. Los términos técnicos (lista blanca) no se traducen.

const vars = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join(",");

test("es.ts y en.ts tienen las mismas claves, con las mismas variables", () => {
  const ke = Object.keys(es).sort();
  const kn = Object.keys(en).sort();
  expect(ke.filter((k) => !kn.includes(k)), "faltan en en.ts").toEqual([]);
  expect(kn.filter((k) => !ke.includes(k)), "faltan en es.ts").toEqual([]);
  const e = es as Record<string, string>;
  const n = en as Record<string, string>;
  expect(ke.filter((k) => vars(e[k]) !== vars(n[k])), "variables distintas").toEqual([]);
});

// Términos que no se traducen (siglas, protocolos, herramientas, comandos y nombres propios).
const TECH = [
  "SSH", "VLAN", "ACL", "ACLs", "Ping", "ping", "nmap", "iperf3", "PCAP", "pcap", "pcapng", "TLS", "SNI", "DNS", "DNSSEC", "DoT", "DoH",
  "SNMP", "NTP", "Syslog", "syslog", "IOS", "IOS-XE", "NX-OS", "CLI", "Traceroute", "TFTP", "BPF", "TCP", "UDP", "ICMP", "IP", "IPv4", "IPv6",
  "CIDR", "MAC", "MTU", "VRF", "OSPF", "BGP", "EIGRP", "CDP", "LLDP", "ARP", "HTTP", "HTTPS", "URL", "SHA-256", "SHA256", "JSON", "CSV", "ZIP", "zip",
  "BIN", "RTT", "TTL", "AAA", "RADIUS", "TACACS", "SPF", "DMARC", "CAA", "PTR", "NXDOMAIN", "EDNS", "UTF-8", "ASCII", "RS-232", "COM", "USB",
  "Patrol", "MACUAHUITL", "enable", "Wireshark", "dumpcap", "show", "Cisco", "Linux", "Wails", "gRPC", "NAT", "QoS", "STP", "SVI", "PoE",
  "Telnet", "RTO", "MSS", "SYN", "RST", "FIN", "ACK", "TAC", "ISE", "WLC", "HSRP", "VRRP", "GLBP", "PDF", "XML", "YAML", "TXT", "CRC",
  "baud", "bps", "Mbps", "Kbps", "GB", "MB", "KB", "ms", "ASN", "SOA", "CNAME", "AAAA", "SSID", "DHCP", "FTP", "SFTP", "SCP",
  "Ctrl-C", "Ctrl-Z", "Ctrl", "BREAK", "RTS", "CTS", "XON", "XOFF", "ROMMON", "Tab", "Hash", "MD5", "SHA-512", "nftables", "PRE", "POST", "ip", "Markdown", "CSR", "CN", "O", "OU", "L", "ST", "PEM", "PKCS", "NAS-IP-Address", "NAS-Identifier", "NAS-Port-Type", "Service-Type", "Called-Station-Id",
  "Get", "Walk", "gNMI", "Bytes", "MPLS", "EXP", "Local-pref", "AS_PATH", "Origin", "MED", "Router-ID", "Originator-ID", "eBGP", "Flash", "DRAM", "PID",
];
const techRe = new RegExp(`(?<![\\p{L}\\d])(?:${[...TECH].sort((a, b) => b.length - a.length).map((t) => t.replace(/\./g, "\\.")).join("|")})(?![\\p{L}\\d])`, "gu");
const hasWords = (s: string) => /\p{L}/u.test(s.replace(techRe, ""));
// Prosa: acentos, signos de apertura o dos palabras seguidas (se ignoran los términos técnicos).
const isProse = (s: string) => {
  if (/^(show|ping|traceroute) /.test(s)) return false; // comandos de IOS
  const t = s.replace(techRe, "");
  return /[áéíóúñüÁÉÍÓÚÑ¿¡…]/.test(t) || /\p{L}{2,}\s+\p{L}{2,}/u.test(t);
};

// Atributos cuyo valor es texto visible: aquí cualquier palabra cuenta.
const VISIBLE = new Set(["placeholder", "title", "aria-label", "aria-description", "alt", "label", "legend", "hint", "summary", "caption", "tooltip", "heading", "description", "emptyText", "text"]);
// Propiedades de objeto/tupla de opciones que se muestran tal cual.
const VISIBLE_PROPS = new Set(["label", "title", "placeholder", "legend", "hint", "text", "message", "heading", "description", "caption"]);
// Elementos cuyo contenido es literal (comandos, salida): no se traduce.
const LITERAL_TAGS = new Set(["code", "kbd"]);

type Node = { type: string; [k: string]: any }; // eslint-disable-line @typescript-eslint/no-explicit-any

function walk(n: Node, parents: Node[], f: (n: Node, parents: Node[]) => void) {
  f(n, parents);
  for (const [k, v] of Object.entries(n)) {
    if (k === "type" || k === "loc" || k === "range") continue;
    const next = [...parents, n];
    if (Array.isArray(v)) v.forEach((c) => c && typeof c.type === "string" && walk(c, next, f));
    else if (v && typeof v === "object" && typeof v.type === "string") walk(v, next, f);
  }
}

export function findHardcoded(src: string, file: string): string[] {
  const ast = parseAst(src, { lang: "tsx" }, file) as unknown as Node;
  const line = (n: Node) => src.slice(0, n.start).split("\n").length;
  const out: string[] = [];
  const add = (n: Node, what: string) => out.push(`${file}:${line(n)} ${JSON.stringify(what)}`);
  const strOf = (n: Node): string | null =>
    n.type === "Literal" && typeof n.value === "string" ? n.value
      : n.type === "TemplateLiteral" ? n.quasis.map((q: Node) => q.value.cooked).join("{}") : null;
  walk(ast, [], (n, parents) => {
    const p = parents[parents.length - 1];
    if (n.type === "JSXText") {
      if (parents.some((a) => a.type === "JSXElement" && LITERAL_TAGS.has(a.openingElement.name.name))) return;
      if (hasWords(n.value)) add(n, n.value.trim());
      return;
    }
    const s = strOf(n);
    if (s === null || !p) return;
    if (p.type === "ImportDeclaration" || p.type === "ExportAllDeclaration" || p.type === "ExportNamedDeclaration") return;
    if (p.type === "TSLiteralType" || p.type === "TSImportType" || p.type === "ExpressionStatement") return;
    if (p.type === "Property" && p.key === n) return;
    if (p.type === "CallExpression" && p.callee.name === "t") return;
    // Sube por ?:, && y || hasta el contenedor JSX que lo muestra.
    let i = parents.length - 1;
    while (i > 0 && (parents[i].type === "ConditionalExpression" || parents[i].type === "LogicalExpression")) i--;
    const box = parents[i].type === "JSXExpressionContainer" ? parents[i] : null;
    const attr = p.type === "JSXAttribute" ? p : box && parents[i - 1]?.type === "JSXAttribute" ? parents[i - 1] : null;
    if (box && !attr) return void (hasWords(s) && add(n, s)); // hijo {cond ? "a" : "b"}
    if (attr) {
      const name = attr.name.type === "JSXIdentifier" ? attr.name.name : "";
      if (VISIBLE.has(name) ? hasWords(s) : isProse(s) && !["className", "style", "role", "d", "viewBox"].includes(name)) add(n, s);
      return;
    }
    if (p.type === "Property" && VISIBLE_PROPS.has(p.key.name ?? p.key.value) && hasWords(s)) return void add(n, s);
    // Texto suelto en el flujo de una vista (avisos, estados, opciones): se detecta por su aspecto de prosa.
    if (isProse(s)) add(n, s);
  });
  return out;
}

// Fuentes de la interfaz (sin pruebas), leídas como texto por Vite.
const sources = import.meta.glob<string>(["../modules/**/*.tsx", "../components/**/*.tsx", "../app/**/*.tsx", "!**/*.test.tsx"], { query: "?raw", import: "default", eager: true });

test("detecta texto fijo en JSX, atributos y avisos", () => {
  const bad = findHardcoded(
    `export const A = () => { const [m, setM] = useState(""); setM("Dato inválido"); return <div title="Cerrar"><b>Hola mundo</b><input placeholder="Nombre" /><span>{ok ? "Listo" : "Error"}</span></div>; };`,
    "x.tsx",
  );
  expect(bad.length).toBe(6);
  const good = findHardcoded(`export const A = () => <div className="row muted" title={t("a")}><code>show ip route</code><b>SSH</b> · <i>{n}</i></div>;`, "y.tsx");
  expect(good).toEqual([]);
});

test("ningún .tsx de la interfaz tiene texto visible fijo", () => {
  expect(Object.keys(sources).length).toBeGreaterThan(40); // la búsqueda encontró las fuentes
  const found = Object.entries(sources).flatMap(([f, src]) => findHardcoded(src, f));
  expect(found).toEqual([]);
});
