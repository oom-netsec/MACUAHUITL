// Contrato del módulo Rotar credenciales con el puente (ui/bridge/assist.go). El secreto nuevo va solo en la petición; nunca vuelve.
import type { PortsPlanResult } from "../ports/api";

export interface CredRotateRequest {
  target: { name: string; address: string; port?: number; credentialId: string };
  user: string;
  newSecret?: string; // vacío = lo genera el núcleo (exige updateCredentialId)
  updateCredentialId?: string;
  writeMemory?: boolean;
  acceptedHostKeyFingerprints?: string[];
}

export interface CredRotateAPI {
  assistPlanCredRotate(r: CredRotateRequest): Promise<PortsPlanResult>;
}

type Call = <T>(method: string, ...args: unknown[]) => Promise<T>;

export const credRotateWails = (call: Call): CredRotateAPI => ({
  assistPlanCredRotate: async (r) => JSON.parse(await call<string>("AssistPlanCredRotate", JSON.stringify(r))),
});
