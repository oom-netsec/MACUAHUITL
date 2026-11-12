import type { PortInfo } from "../metrics/api";
import type { FrontPort } from "./api";

const KNOWN = ["connected", "notconnect", "disabled", "err-disabled", "monitoring"] as const;

// PortInfo del núcleo → puerto de la vista de frente. Troncales, enrutados y miembros de un port-channel se ven
// pero no se eligen: el cambio asistido solo toca puertos de acceso. Un estado que el panel no colorea
// (inactive, suspended…) se dibuja como sin conexión y conserva su texto en la descripción.
export function toFront(p: PortInfo): FrontPort {
  const known = (KNOWN as readonly string[]).includes(p.status);
  return {
    name: p.name, module: p.module, slot: p.stack, port: p.number,
    status: known ? (p.status as FrontPort["status"]) : "notconnect",
    mode: p.channel ? "channel" : p.vlan === "routed" ? "routed" : p.trunk ? "trunk" : "access",
    channel: p.channel || undefined,
    vlan: p.vlan, speed: p.speed, duplex: p.duplex, type: p.type,
    description: [p.description, known ? "" : p.status].filter(Boolean).join(" · "),
  };
}
