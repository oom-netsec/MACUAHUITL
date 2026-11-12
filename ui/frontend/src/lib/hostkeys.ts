// Huellas SSH aceptadas a mano. El núcleo las compara como "SHA256:<base64>"; quien pega solo el base64
// (lo que muestran muchos equipos y ssh-keygen -l) no debe quedar fuera sin aviso.
const BARE = /^[A-Za-z0-9+/]{43}=?$/;

export function parseFingerprints(text: string): string[] {
  const out = text.split(/[\s,;]+/).filter(Boolean)
    .map((f) => (/^sha256:/i.test(f) ? `SHA256:${f.slice(7)}` : BARE.test(f) ? `SHA256:${f}` : ""))
    .filter(Boolean);
  return [...new Set(out)];
}

// Huella del error del núcleo cuando la llave del equipo es nueva o cambió.
export function hostKeyFromError(msg: string): { fp: string; changed: boolean } | null {
  const m = /llave de host (desconocida|cambiada).*?(SHA256:[A-Za-z0-9+/=]+)/.exec(msg);
  return m ? { fp: m[2], changed: m[1] === "cambiada" } : null;
}
