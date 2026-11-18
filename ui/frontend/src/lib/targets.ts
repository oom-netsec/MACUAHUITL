import type { Host } from "../modules/inventory/api";

// Acepta IPs, nombres y CIDR separados por comas, espacios o saltos de línea; sin duplicados.
export function parseTargets(text: string): string[] {
  return [...new Set(text.split(/[\s,;]+/).filter(Boolean))];
}

// "host", "host:puerto" (un solo ':') o "[ipv6]:puerto" / "[ipv6]"; una IPv6 sin corchetes va sin puerto. Puerto 0 = el de omisión.
export function parseTarget(s: string): { address: string; port: number } {
  const b = /^\[([^\]]+)\](?::(\d+))?$/.exec(s);
  if (b) return { address: b[1], port: b[2] ? Number(b[2]) : 0 };
  const i = s.lastIndexOf(":");
  if (i > 0 && s.indexOf(":") === i && /^\d+$/.test(s.slice(i + 1))) return { address: s.slice(0, i), port: Number(s.slice(i + 1)) };
  return { address: s, port: 0 };
}

// Destino de una petición de plan desde lo que escribió el ingeniero (el puerto se omite si no lo puso).
export function planTarget(equipo: string, credentialId: string) {
  const t = parseTarget(equipo.trim());
  return { name: equipo.trim(), address: t.address, ...(t.port ? { port: t.port } : {}), credentialId };
}

// Dirección con puerto para mostrar: IPv6 entre corchetes.
export const addrPort = (h: Pick<Host, "address" | "port">) => (h.address.includes(":") ? `[${h.address}]:${h.port}` : `${h.address}:${h.port}`);
// «host», «host:puerto» o «[ipv6]:puerto» como lo entiende parseTarget; el puerto nunca se pierde.
export const targetOf = (h: Pick<Host, "address" | "port">) => (h.port === 22 || !h.port ? h.address : addrPort(h));
