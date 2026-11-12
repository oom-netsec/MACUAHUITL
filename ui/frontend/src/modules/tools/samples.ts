// Salidas de ejemplo con la forma real del núcleo (pcapan.Report.Text, dnsq.TraceResult y tlsinspect.Report en JSON). Sin validar en laboratorio.
export const pcapSample = `Captura: /home/netops/casos/6942/uplink.pcapng
Paquetes: 18452 · Bytes: 9650000 · Duración: 2m3s · Desde 2026-11-06T18:00:00Z

== TCP
  Handshakes completos: 212 · RTT de handshake min/prom/máx: 1ms / 4ms / 31ms
  Retransmisiones: 37 · Ventana cero: 0

== DNS
  Consultas: 640 · Respuestas: 631

== Conversaciones con más bytes
  tcp  10.10.1.25:51844 ↔ 10.20.0.9:443  9120 paquetes  6400000 bytes
  tcp  10.10.1.31:49222 ↔ 10.20.0.14:445  4210 paquetes  2100000 bytes
  udp  10.10.1.25:50111 ↔ 10.20.0.2:53  1280 paquetes  220000 bytes
  icmp 10.10.1.1 ↔ 10.20.0.9  400 paquetes  39200 bytes
  tcp  10.10.1.40:40100 ↔ 10.20.0.7:22  300 paquetes  28400 bytes

== Equipos con más tráfico
  10.10.1.25  10400 paquetes  6620000 bytes
  10.20.0.9  9520 paquetes  6439200 bytes
  10.20.0.14  4210 paquetes  2100000 bytes
  10.10.1.31  4210 paquetes  2100000 bytes
  10.20.0.2  1280 paquetes  220000 bytes
`;

const ns = (n: number) => n * 1e6;
export const dnsTraceSample = JSON.stringify({
  Name: "www.example.com.", Type: "A", RCode: "NOERROR", CNAMEs: [], Warnings: [],
  Final: ["www.example.com.\t300\tIN\tA\t93.184.216.34"],
  Steps: [
    { Zone: ".", Server: "a.root-servers.net.", ServerIP: "198.41.0.4", RTT: ns(18), RCode: "NOERROR", AA: false, ReferralZone: "com.", Referral: ["a.gtld-servers.net.", "b.gtld-servers.net."], Glue: {}, Answer: null },
    { Zone: "com.", Server: "a.gtld-servers.net.", ServerIP: "192.5.6.30", RTT: ns(24), RCode: "NOERROR", AA: false, ReferralZone: "example.com.", Referral: ["a.iana-servers.net.", "b.iana-servers.net."], Glue: {}, Answer: null },
    { Zone: "example.com.", Server: "a.iana-servers.net.", ServerIP: "199.43.135.53", RTT: ns(41), RCode: "NOERROR", AA: true, ReferralZone: "", Referral: null, Glue: {}, Answer: ["www.example.com.\t300\tIN\tA\t93.184.216.34"] },
  ],
}, null, 2);

const day = 86_400_000;
const cert = (subject: string, issuer: string, days: number, sha: string, isCA: boolean, san: string[] = []) => ({
  Subject: subject, Issuer: issuer, SANs: san, NotBefore: new Date(Date.now() - 200 * day).toISOString(), NotAfter: new Date(Date.now() + days * day + day / 2).toISOString(),
  KeyType: "RSA", KeyBits: 2048, SigAlg: "SHA256-RSA", SHA256: sha, IsCA: isCA,
});
export const tlsSample = JSON.stringify({
  Target: "ise.lab:443", SNI: "ise.lab", Version: "TLS 1.3", Cipher: "TLS_AES_256_GCM_SHA384", ALPN: "h2", Accepted: ["TLS 1.2", "TLS 1.3"],
  Verified: true, NameMatches: true, DaysLeft: 19, Findings: [{ Severity: "aviso", Code: "vence-pronto", Detail: "el certificado vence en 19 días" }],
  Chain: [
    cert("CN=ise.lab", "CN=Lab Issuing CA", 19, "9f:86:d0:81:88:4c:7d:65:9a:2f:ea:a0:c5:5a:d0:15:a3:bf:4f:1b:2b:0b:82:2c:d1:5d:6c:15:b0:f0:0a:08", false, ["ise.lab", "ise-01.lab"]),
    cert("CN=Lab Issuing CA", "CN=Lab Root CA", 900, "2c:26:b4:6b:68:ff:c6:8f:f9:9b:45:3c:1d:30:41:34:13:42:2d:70:64:83:be:a8:d6:d7:4b:2b:a6:2e:5b:2a", true),
    cert("CN=Lab Root CA", "CN=Lab Root CA", 3400, "5f:cf:e6:51:59:fb:3f:d4:d0:07:45:36:66:8d:3d:e3:32:73:81:dc:4a:bd:7a:7c:b9:0b:0a:6a:f4:2c:7a:2d", true),
  ],
}, null, 2);
