import { captureCount, parseIperf, parseNmap, parsePing, parseTraceroute, pingStats } from "./parse";

// Salidas con la forma de iputils-ping, traceroute, iperf3 y nmap en Linux (sin validar en laboratorio).
const PING = `PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.412 ms
64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=0.520 ms
no answer yet for icmp_seq=3
64 bytes from 10.0.0.1: icmp_seq=4 ttl=64 time=0.301 ms
64 bytes from 10.0.0.1: icmp_seq=6 ttl=64 time=1.25 ms
From 10.0.0.254 icmp_seq=7 Destination Host Unreachable

--- 10.0.0.1 ping statistics ---
7 packets transmitted, 4 received, +1 errors, 42% packet loss, time 6008ms
rtt min/avg/max/mdev = 0.301/0.620/1.250/0.380 ms`.split("\n");

test("parsePing lee RTT y TTL y marca como perdidos los huecos y los avisos explícitos", () => {
  const r = parsePing(PING);
  expect(r.replies).toEqual([
    { seq: 1, rtt: 0.412, ttl: 64 }, { seq: 2, rtt: 0.52, ttl: 64 }, { seq: 4, rtt: 0.301, ttl: 64 }, { seq: 6, rtt: 1.25, ttl: 64 },
  ]);
  expect(r.lost).toEqual([3, 5, 7]); // 3 explícito, 5 hueco, 7 inalcanzable
});

test("parsePing: una respuesta tardía quita al paquete de los perdidos y macOS usa 'Request timeout'", () => {
  const r = parsePing(["Request timeout for icmp_seq 2", "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=9.8 ms", "64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=1002 ms"]);
  expect(r.lost).toEqual([]);
  expect(parsePing(["Request timeout for icmp_seq 2"]).lost).toEqual([2]);
});

test("parsePing ignora líneas que no son de ping", () => {
  expect(parsePing(["PING x", "", "ping: unknown host x"])).toEqual({ replies: [], lost: [] });
});

test("pingStats calcula mín, prom, máx, jitter y pérdida", () => {
  const s = pingStats({ replies: [{ seq: 1, rtt: 0.4 }, { seq: 2, rtt: 0.5 }, { seq: 3, rtt: 0.3 }], lost: [4] })!;
  expect(s.min).toBe(0.3);
  expect(s.max).toBe(0.5);
  expect(s.avg).toBeCloseTo(0.4, 5);
  expect(s.jitter).toBeCloseTo(0.15, 5);
  expect(s.lossPct).toBe(25);
  expect(s.received).toBe(3);
  expect(s.sent).toBe(4);
  expect(pingStats({ replies: [], lost: [] })).toBeNull();
  expect(pingStats({ replies: [], lost: [1, 2] })!.lossPct).toBe(100);
});

const TRACE = `traceroute to dns.google (8.8.8.8), 30 hops max, 60 byte packets
 1  _gateway (192.168.1.1)  0.412 ms  0.388 ms  0.401 ms
 2  * * *
 3  10.20.0.1 (10.20.0.1)  8.221 ms  8.190 ms 10.20.0.5 (10.20.0.5)  9.003 ms
 4  * 192.0.2.9 (192.0.2.9)  12.0 ms *
 5  dns.google (8.8.8.8)  14.2 ms  13.9 ms  14.8 ms`.split("\n");

test("parseTraceroute separa saltos, hosts, RTT y sondas sin respuesta", () => {
  const h = parseTraceroute(TRACE);
  expect(h).toHaveLength(5);
  expect(h[0]).toEqual({ hop: 1, host: "_gateway", address: "192.168.1.1", rtts: [0.412, 0.388, 0.401], stars: 0 });
  expect(h[1]).toEqual({ hop: 2, host: "", address: "", rtts: [], stars: 3 });
  expect(h[2].address).toBe("10.20.0.1"); // el primer host del salto
  expect(h[2].rtts).toEqual([8.221, 8.19, 9.003]);
  expect(h[3]).toEqual({ hop: 4, host: "192.0.2.9", address: "192.0.2.9", rtts: [12], stars: 2 });
  expect(h[4].host).toBe("dns.google");
});

test("parseTraceroute con -n (solo IP) y anotaciones de error", () => {
  const h = parseTraceroute([" 1  10.0.0.1  0.5 ms  0.4 ms  0.6 ms", " 2  10.0.0.9  3.1 ms !H  *  *"]);
  expect(h[0]).toMatchObject({ host: "10.0.0.1", address: "10.0.0.1", rtts: [0.5, 0.4, 0.6] });
  expect(h[1]).toMatchObject({ address: "10.0.0.9", rtts: [3.1], stars: 2 });
});

const IPERF = `Connecting to host 10.0.0.2, port 5201
[  5] local 10.0.0.1 port 54321 connected to 10.0.0.2 port 5201
[ ID] Interval           Transfer     Bitrate         Retr  Cwnd
[  5]   0.00-1.00   sec   112 MBytes   941 Mbits/sec    0    412 KBytes
[  5]   1.00-2.00   sec   111 MBytes   930 Mbits/sec    3    398 KBytes
[  5]   2.00-3.00   sec  98.2 MBytes   824000 Kbits/sec    1    380 KBytes
- - - - - - - - - - - - - - - - - - - - - - - - -
[ ID] Interval           Transfer     Bitrate         Retr
[  5]   0.00-3.00   sec   321 MBytes   898 Mbits/sec    4             sender
[  5]   0.00-3.04   sec   320 MBytes   883 Mbits/sec                  receiver

iperf Done.`.split("\n");

test("parseIperf toma una muestra por intervalo (sin el resumen) y normaliza a Mbps", () => {
  const r = parseIperf(IPERF);
  expect(r.points).toEqual([{ end: 1, mbps: 941, retr: 0 }, { end: 2, mbps: 930, retr: 3 }, { end: 3, mbps: 824, retr: 1 }]);
  expect(r.sender).toBe(898);
  expect(r.receiver).toBe(883);
});

test("parseIperf con flujos paralelos usa solo las filas [SUM] y entiende Gbits y bits", () => {
  const r = parseIperf([
    "[  5]   0.00-1.00   sec  56.0 MBytes   470 Mbits/sec", "[  7]   0.00-1.00   sec  56.0 MBytes   470 Mbits/sec",
    "[SUM]   0.00-1.00   sec   112 MBytes   1.88 Gbits/sec", "[SUM]   1.00-2.00   sec   112 MBytes   500000 bits/sec",
  ]);
  expect(r.points).toEqual([{ end: 1, mbps: 1880, retr: undefined }, { end: 2, mbps: 0.5, retr: undefined }]);
});

const NMAP = `Starting Nmap 7.94SVN ( https://nmap.org ) at 2026-11-06 18:00 CST
Nmap scan report for sw-core-1 (10.0.0.1)
Host is up (0.00045s latency).
Not shown: 995 closed tcp ports (conn-refused)
PORT     STATE         SERVICE
22/tcp   open          ssh
80/tcp   open          http
443/tcp  filtered      https
161/udp  open|filtered snmp

Nmap scan report for 10.0.0.2
Host is up (0.0011s latency).
All 1000 scanned ports on 10.0.0.2 are in ignored states.

Nmap done: 2 IP addresses (2 hosts up) scanned in 1.52 seconds`.split("\n");

test("parseNmap lee puertos con estado y servicio, por host", () => {
  const h = parseNmap(NMAP);
  expect(h).toHaveLength(2);
  expect(h[0].host).toBe("sw-core-1 (10.0.0.1)");
  expect(h[0].ports).toEqual([
    { port: 22, proto: "tcp", state: "open", service: "ssh" },
    { port: 80, proto: "tcp", state: "open", service: "http" },
    { port: 443, proto: "tcp", state: "filtered", service: "https" },
    { port: 161, proto: "udp", state: "open|filtered", service: "snmp" },
  ]);
  expect(h[0].hidden).toEqual({ n: 995, state: "closed" });
  expect(h[1].ports).toEqual([]);
});

test("parseNmap tolera un servicio con versión y un host caído", () => {
  const h = parseNmap(["Nmap scan report for 10.9.9.9", "PORT   STATE SERVICE VERSION", "22/tcp open  ssh     Cisco SSH 1.25 (protocol 2.0)", "3389/tcp closed ms-wbt-server"]);
  expect(h[0].ports[0]).toEqual({ port: 22, proto: "tcp", state: "open", service: "ssh" });
  expect(h[0].ports[1].service).toBe("ms-wbt-server");
});

test("captureCount lee el contador de dumpcap y de tcpdump", () => {
  expect(captureCount(["File: /tmp/x.pcapng", "Packets: 12", "Packets: 40"])).toBe(40);
  expect(captureCount(["Packets captured: 77"])).toBe(77);
  expect(captureCount(["134 packets captured", "134 packets received by filter"])).toBe(134);
  expect(captureCount(["nada"])).toBeNull();
});

test("parsePing: los últimos paquetes sin respuesta cuentan como perdidos al llegar el resumen", () => {
  const r = parsePing([
    "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=1.0 ms",
    "64 bytes from 10.0.0.1: icmp_seq=2 ttl=64 time=1.2 ms",
    "--- 10.0.0.1 ping statistics ---",
    "4 packets transmitted, 2 received, 50% packet loss, time 3004ms",
  ]);
  expect(r.lost).toEqual([3, 4]);
  expect(pingStats(r)?.lossPct).toBe(50);
});
