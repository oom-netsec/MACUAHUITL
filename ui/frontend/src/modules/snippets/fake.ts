import { vi } from "vitest";
import type { PortsPlanResult } from "../ports/api";
import type { SnippetTemplate } from "./api";

export const sampleSnippetPlan: PortsPlanResult = {
  planId: "s1",
  plan: {
    function: "snippet-trunk",
    devices: [{
      device: "SW1",
      pre: ["show running-config interface GigabitEthernet1/0/48"],
      apply: ["interface GigabitEthernet1/0/48", "switchport trunk allowed vlan add 30"],
      rollback: ["interface GigabitEthernet1/0/48", "switchport trunk allowed vlan remove 30"],
      post: ["show running-config interface GigabitEthernet1/0/48"],
      expect: [{ command: "show running-config interface GigabitEthernet1/0/48", line: "30", present: true }],
    }],
  },
};

// Plantillas de ejemplo con la forma (y los valores sugeridos) que da el núcleo: interfaces, choices, decimales, bools, vlan_id e ipv4.
const ports = { name: "interfaces", label: "Puertos", type: "interfaces", required: true, help: "Lista separada por comas o rangos como Gi1/0/1-4; solo puertos físicos." } as const;
export const sampleTemplates: SnippetTemplate[] = [
  {
    id: "speed-duplex", tech: "l2", name: "Velocidad y duplex de puertos", platforms: ["ios", "ios-xe"],
    fields: [
      ports,
      { name: "speed", label: "Velocidad", type: "choice", choices: ["auto", "10", "100", "1000"], help: "Vacío no la toca. auto la devuelve a negociación." },
      { name: "duplex", label: "Duplex", type: "choice", choices: ["auto", "full", "half"], help: "Vacío no lo toca." },
    ],
  },
  {
    id: "storm-control", tech: "l2", name: "Storm-control de puertos", platforms: ["ios", "ios-xe"],
    fields: [
      ports,
      { name: "broadcast", label: "Umbral de difusión (%)", type: "decimal", max: 100, help: "0.00-100.00; vacío no lo toca." },
      { name: "multicast", label: "Umbral de multicast (%)", type: "decimal", max: 100 },
      { name: "unicast", label: "Umbral de unicast (%)", type: "decimal", max: 100 },
      { name: "action", label: "Acción al superarlo", type: "choice", choices: ["shutdown", "trap"], help: "Vacío no la toca. shutdown y trap son independientes: se pueden tener las dos." },
    ],
  },
  {
    id: "port-security", tech: "l2", name: "Port-security en puertos de acceso", platforms: ["ios", "ios-xe"],
    fields: [
      ports,
      { name: "maximum", label: "Máximo de direcciones MAC", type: "int", min: 1, max: 3072, defaultValue: "1" },
      { name: "violation", label: "Acción ante violación", type: "choice", choices: ["protect", "restrict", "shutdown"], defaultValue: "shutdown" },
      { name: "aging_time", label: "Envejecimiento (minutos)", type: "int", min: 0, max: 1440, help: "0 = no envejece." },
    ],
  },
  {
    id: "svi", tech: "l3", name: "Interfaz VLAN (SVI) con dirección IP", platforms: ["ios", "ios-xe"],
    fields: [
      { name: "vlan", label: "VLAN", type: "vlan_id", required: true },
      { name: "description", label: "Descripción", type: "text", max: 200 },
      { name: "address", label: "Dirección IP", type: "ipv4", required: true },
      { name: "mask", label: "Máscara", type: "ipv4_mask", required: true, defaultValue: "255.255.255.0", help: "Contigua, de /8 a /30." },
    ],
  },
  {
    id: "trunk", tech: "l2", name: "Agregar o quitar una VLAN de un trunk", platforms: ["ios", "ios-xe"],
    fields: [
      { name: "interface", label: "Trunk", type: "interface", required: true, help: "Puerto físico o Port-channel que ya sea trunk." },
      { name: "op", label: "Operación", type: "choice", required: true, choices: ["add", "remove"], defaultValue: "add", help: "Nunca reemplaza la lista permitida." },
      { name: "vlan", label: "VLAN", type: "vlan_id", required: true },
    ],
  },
  {
    id: "vlan", tech: "l2", name: "Crear, nombrar o borrar una VLAN", platforms: ["ios", "ios-xe"],
    fields: [
      { name: "id", label: "VLAN", type: "vlan_id", required: true, min: 2, help: "2-4094; las reservadas 1002-1005 no se tocan." },
      { name: "name", label: "Nombre", type: "text", pattern: "^[A-Za-z0-9_.-]+$", max: 32, help: "Letras, números, _ . -; sin espacios. Vacío crea la VLAN con su nombre por omisión." },
      { name: "remove", label: "Borrar la VLAN", type: "bool", defaultValue: "false", help: "Solo una VLAN activa, sin puertos, SVI ni trunk nativo; no lleva nombre." },
      { name: "accept_vtp", label: "Aceptar que se propague por VTP", type: "bool", defaultValue: "false" },
      { name: "accept_trunk", label: "Aceptar borrar una VLAN que viaja por trunks", type: "bool", defaultValue: "false" },
    ],
  },
];

// Plan con avisos (notes) como el de port-security: la reversa no saca un puerto de err-disabled.
export const samplePortSecurityPlan: PortsPlanResult = {
  planId: "s2",
  plan: {
    function: "snippet-port-security",
    devices: [{
      device: "SW1",
      pre: ["show running-config interface GigabitEthernet1/0/5"],
      apply: ["interface GigabitEthernet1/0/5", "switchport port-security", "switchport port-security maximum 2", "switchport port-security violation shutdown"],
      rollback: ["interface GigabitEthernet1/0/5", "no switchport port-security violation shutdown", "no switchport port-security maximum 2", "no switchport port-security"],
      post: ["show port-security interface GigabitEthernet1/0/5"],
      expect: [{ command: "show port-security interface GigabitEthernet1/0/5", line: "Port Security : Enabled", present: true }],
      notes: [
        "Con violation shutdown, una violación deja el puerto en err-disabled.",
        "La reversa no saca un puerto de err-disabled: hay que hacer shutdown y no shutdown a mano.",
      ],
      notesStructured: [{ key: "assist.note.errdisabled" }, { key: "assist.note.port_mode_same", args: { port: "Gi1/0/5", mode: "access" } }],
    }],
  },
};

export const fakeSnippets = () => ({
  assistPlanSnippet: vi.fn(async () => sampleSnippetPlan),
  listSnippetTemplates: vi.fn(async () => sampleTemplates),
  planTemplateSnippet: vi.fn(async (r: { id: string }) => (r.id === "port-security" ? samplePortSecurityPlan : sampleSnippetPlan)),
});
