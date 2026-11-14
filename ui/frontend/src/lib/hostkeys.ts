import type { ErrInfo } from "./coreError";

// Huellas SSH aceptadas a mano. El núcleo las compara como "SHA256:<base64>"; quien pega solo el base64
// (lo que muestran muchos equipos y ssh-keygen -l) no debe quedar fuera sin aviso.
const BARE = /^[A-Za-z0-9+/]{43}=?$/;

export function parseFingerprints(text: string): string[] {
  const out = text.split(/[\s,;]+/).filter(Boolean)
    .map((f) => (/^sha256:/i.test(f) ? `SHA256:${f.slice(7)}` : BARE.test(f) ? `SHA256:${f}` : ""))
    .filter(Boolean);
  return [...new Set(out)];
}

// Huella del error del núcleo cuando la llave del equipo es nueva o cambió: del reason (transport.hostkey.*) si viene;
// si no, del texto, que el núcleo manda en español o en inglés según el idioma de la interfaz.
export function hostKeyFromError(msg: string, info?: ErrInfo): { fp: string; changed: boolean } | null {
  // El reason puede venir directo o como causa de un error que lo envuelve (metadata.cause_reason).
  const reason = [info?.reason, info?.metadata.cause_reason].find((r) => r && /^transport\.hostkey\.(unknown|changed)$/.test(r));
  if (reason && info?.metadata.fingerprint) return { fp: info.metadata.fingerprint, changed: reason.endsWith("changed") };
  const m = /(?:llave de host (desconocida|cambiada)|(unknown|changed) host key).*?(SHA256:[A-Za-z0-9+/=]+)/.exec(msg);
  return m ? { fp: m[3], changed: (m[1] ?? m[2]) === "cambiada" || m[2] === "changed" } : null;
}
