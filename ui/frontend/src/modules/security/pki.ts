// Tipos y listas que comparten las tarjetas de PKI.
export const algorithms: [string, string][] = [["p256", "ECDSA P-256"], ["p384", "ECDSA P-384"], ["rsa2048", "RSA 2048"], ["rsa3072", "RSA 3072"], ["rsa4096", "RSA 4096"]];
export type Pem = { pem: string; key: string; text: string };
