import { parsePcap } from "./pcapParse";

// Misma forma que pcapan.Report.Text() (internal/pcapan/text.go).
const REPORT = `Captura: /home/x/cap.pcapng
Paquetes: 26 · Bytes: 4096 · Duración: 3s · Desde 2026-11-06T18:00:00Z

== TCP
  Handshakes completos: 2 · RTT de handshake min/prom/máx: 1ms / 2ms / 3ms

== Conversaciones con más bytes
  tcp  10.0.0.5:51000 ↔ 10.0.0.9:443  12 paquetes  9000 bytes
  udp  10.0.0.5:5353 ↔ 8.8.8.8:53  4 paquetes  400 bytes
  tcp  10.0.0.7:22 ↔ 10.0.0.5:50111  6 paquetes  600 bytes

== Equipos con más tráfico
  10.0.0.5  22 paquetes  10000 bytes
  10.0.0.9  12 paquetes  9000 bytes
`;

test("extrae equipos con más tráfico, conversaciones y protocolos", () => {
  const p = parsePcap(REPORT)!;
  expect(p.talkers).toEqual([{ ip: "10.0.0.5", packets: 22, bytes: 10000 }, { ip: "10.0.0.9", packets: 12, bytes: 9000 }]);
  expect(p.conversations).toHaveLength(3);
  expect(p.conversations[1]).toEqual({ proto: "udp", a: "10.0.0.5:5353", b: "8.8.8.8:53", packets: 4, bytes: 400 });
  expect(p.protocols).toEqual([{ proto: "tcp", packets: 18, bytes: 9600 }, { proto: "udp", packets: 4, bytes: 400 }]);
});

test("un texto que no es el informe devuelve null", () => {
  expect(parsePcap("26 paquetes\nRST: 1")).toBeNull();
  expect(parsePcap("")).toBeNull();
});

test("ignora líneas con otro formato dentro de la sección", () => {
  const p = parsePcap("== Equipos con más tráfico\n  10.0.0.1  3 paquetes  30 bytes\n  basura\n")!;
  expect(p.talkers).toEqual([{ ip: "10.0.0.1", packets: 3, bytes: 30 }]);
  expect(p.conversations).toEqual([]);
});

// Misma forma con la interfaz en inglés (catálogo pcap.* del núcleo, con plural).
test("lee el informe en inglés, con singular y plural", () => {
  const p = parsePcap(`== Top conversations by bytes
  tcp  10.0.0.5:51000 ↔ 10.0.0.9:443  12 packets  9000 bytes
  udp  10.0.0.5:5353 ↔ 8.8.8.8:53  1 packet  1 byte

== Top talkers
  10.0.0.5  13 packets  9001 bytes
`)!;
  expect(p.conversations).toHaveLength(2);
  expect(p.conversations[1]).toEqual({ proto: "udp", a: "10.0.0.5:5353", b: "8.8.8.8:53", packets: 1, bytes: 1 });
  expect(p.talkers).toEqual([{ ip: "10.0.0.5", packets: 13, bytes: 9001 }]);
});
