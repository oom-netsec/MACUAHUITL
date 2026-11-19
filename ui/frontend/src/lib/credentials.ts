import type { Credential } from "../modules/vault/api";

// Las credenciales de llave solo valen para hosts linux/windows abiertos por host_id: los selectores de credencial sueltos no las ofrecen.
// Vive en lib para que components/ la use sin importar código de un módulo (solo tipos).
export const passwordCreds = (l: Credential[]): Credential[] => l.filter((c) => c.kind !== "key");
