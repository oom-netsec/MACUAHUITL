// Contrato del módulo Snippets con el puente (ui/bridge/assist.go). Planear solo lee; la ejecución usa el contrato de Puertos.
import type { PortsPlanResult } from "../ports/api";

type Target = { name: string; address: string; port?: number; credentialId: string };

export interface SnippetRequest {
  target: Target;
  vlan?: { id: number; name?: string; acceptVtp?: boolean };
  trunk?: { interface: string; op: "add" | "remove"; vlan: number };
  svi?: { vlan: number; description?: string; address: string; mask: string };
  template?: { id: string; values: Record<string, string> };
  writeMemory?: boolean;
  acceptedHostKeyFingerprints?: string[];
}

// Catálogo de plantillas (fase 28b). protojson omite los ceros: min/max/required/pattern/choices/defaultValue/help pueden faltar.
// El mapeo de cada type a un control está en docs/plans/contratos-front.md; la validación de la UI es solo ayuda, la autoritativa es la del núcleo.
export type SnippetFieldType = "text" | "int" | "decimal" | "bool" | "choice" | "ipv4" | "ipv4_mask" | "interface" | "interfaces" | "vlan_id" | "secret";
export interface SnippetField {
  name: string;
  label: string;
  type: SnippetFieldType;
  required?: boolean;
  min?: number;
  max?: number;
  pattern?: string;
  choices?: string[];
  defaultValue?: string;
  help?: string;
}
export interface SnippetTemplate { id: string; tech: string; name: string; platforms: string[]; fields: SnippetField[] }

// planTemplateSnippet: values lleva todo el formulario por nombre de campo; un valor vacío cuenta como ausente.
export interface TemplateSnippetRequest {
  target: Target;
  id: string;
  values: Record<string, string>;
  writeMemory?: boolean;
  acceptedHostKeyFingerprints?: string[];
}

export interface SnippetsAPI {
  assistPlanSnippet(r: SnippetRequest): Promise<PortsPlanResult>;
  listSnippetTemplates(platform?: string): Promise<SnippetTemplate[]>;
  planTemplateSnippet(r: TemplateSnippetRequest): Promise<PortsPlanResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const snippetsWails = (call: Call): SnippetsAPI => {
  const plan = async (r: SnippetRequest): Promise<PortsPlanResult> => JSON.parse(await call<string>("AssistPlanSnippet", JSON.stringify(r)));
  return {
    assistPlanSnippet: plan,
    listSnippetTemplates: async (platform = "") => (JSON.parse(await call<string>("AssistListSnippetTemplates", platform)).templates ?? []) as SnippetTemplate[],
    planTemplateSnippet: ({ id, values, ...rest }) => plan({ ...rest, template: { id, values } }),
  };
};
