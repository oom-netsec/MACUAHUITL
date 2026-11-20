import { errInfo, type ErrInfo } from "./coreError";

// Huellas SSH aceptadas a mano. El núcleo las compara como "SHA256:<base64>"; quien pega solo el base64
// (lo que muestran muchos equipos y ssh-keygen -l) no debe quedar fuera sin aviso.
const BARE = /^[A-Za-z0-9+/]{43}=?$/;

export function parseFingerprints(text: string): string[] {
  const out = text.split(/[\s,;]+/).filter(Boolean)
    .map((f) => (/^sha256:/i.test(f) ? `SHA256:${f.slice(7)}` : BARE.test(f) ? `SHA256:${f}` : ""))
    .filter(Boolean);
  return [...new Set(out)];
}

// Huella aceptada atada al equipo que la mostró: lo que el núcleo espera en acceptedHostKeys.
export interface AcceptedKey { host: string; fingerprint: string }

// La dirección tal como el núcleo la normaliza: sin puerto o con 22 va sola; una IPv6 va entre corchetes.
export function hostOfTarget(t: { address: string; port?: number }): string {
  const a = t.address.includes(":") ? `[${t.address}]` : t.address;
  return t.port && t.port !== 22 ? `${a}:${t.port}` : a;
}

// Con varios equipos una huella sin equipo no se manda: valdría para cualquiera. Acepta «HUELLA», «EQUIPO=HUELLA» o
// «EQUIPO:PUERTO=HUELLA» (la sintaxis de mctl --accept), separadas por espacios, comas o punto y coma.
// Con un solo equipo la huella sola se empareja con él. ambiguous = hay huellas sueltas y no hay un único equipo.
export function resolveAccepted(text: string, targets: { address: string; port?: number }[]): { keys: AcceptedKey[]; ambiguous: boolean } {
  const keys: AcceptedKey[] = [];
  let loose = false;
  for (const tok of text.split(/[\s,;]+/).filter(Boolean)) {
    const eq = tok.indexOf("=");
    const whole = parseFingerprints(tok)[0];
    if (whole) { loose = true; if (targets.length === 1) keys.push({ host: hostOfTarget(targets[0]), fingerprint: whole }); continue; }
    const fp = eq > 0 ? parseFingerprints(tok.slice(eq + 1))[0] : undefined;
    if (fp) keys.push({ host: tok.slice(0, eq), fingerprint: fp });
  }
  return { keys, ambiguous: loose && targets.length !== 1 };
}

// Huella del error del núcleo cuando la llave del equipo es nueva o cambió: del reason (transport.hostkey.*) si viene;
// si no, del texto, que el núcleo manda en español o en inglés según el idioma de la interfaz.
export interface HostKeyInfo { fp: string; changed: boolean; keyType?: string; host?: string }

// Orden para ver la huella en el propio equipo y compararla: el archivo es ssh_host_<tipo>_key.pub (ed25519, ecdsa o rsa).
export function keygenCommands(keyType: string): { linux: string; windows: string } | null {
  const k = /^ssh-ed25519/.test(keyType) ? "ed25519" : /^ecdsa-sha2-/.test(keyType) ? "ecdsa" : /^(rsa-sha2-|ssh-rsa$)/.test(keyType) ? "rsa" : "";
  return k ? { linux: `ssh-keygen -lf /etc/ssh/ssh_host_${k}_key.pub`, windows: `ssh-keygen -lf C:\\ProgramData\\ssh\\ssh_host_${k}_key.pub` } : null;
}

export function hostKeyFromError(msg: string, info?: ErrInfo): HostKeyInfo | null {
  // El reason puede venir directo o como causa de un error que lo envuelve (metadata.cause_reason).
  const reason = [info?.reason, info?.metadata.cause_reason].find((r) => r && /^transport\.hostkey\.(unknown|changed)$/.test(r));
  if (reason && info?.metadata.fingerprint) return { fp: info.metadata.fingerprint, changed: reason.endsWith("changed"), keyType: info.metadata.key_type || undefined, host: info.metadata.host || undefined };
  const m = /(?:llave de host (desconocida|cambiada)|(unknown|changed) host key).*?(SHA256:[A-Za-z0-9+/=]+)/.exec(msg);
  return m ? { fp: m[3], changed: (m[1] ?? m[2]) === "cambiada" || m[2] === "changed" } : null;
}

// Equipos que el Login Test rechazó por su llave de host (huella nueva o cambiada). Lo demás (auth, TCP…) no se acepta con una huella.
interface LoginRow { target: string; passed: boolean; failedStep: string; fingerprint: string; reason?: string; args?: Record<string, string> }
const HK_REASON = /^transport\.hostkey\.(unknown|changed)$/;
// Paso HOST_KEY sin reason reconocible: se trata como llave cambiada (pide la casilla «Entiendo que cambió»).
// El par va con el destino del Login Test (target), como pide el contrato; args.host es metadata que un envoltorio podría pisar.
export function hostKeysFromLogin(rows: LoginRow[]): HostKeyInfo[] {
  // El reason puede venir directo o como causa de otro (args.cause_reason), igual que en hostKeyFromError.
  const hk = (l: LoginRow) => [l.reason, l.args?.cause_reason].find((r) => r && HK_REASON.test(r));
  return rows
    .filter((l) => !l.passed && l.fingerprint && (hk(l) || l.failedStep.endsWith("HOST_KEY")))
    .map((l) => ({ fp: l.fingerprint, changed: hk(l) ? hk(l)!.endsWith("changed") : true, host: l.target, keyType: l.args?.key_type || undefined }));
}

// Huella pendiente que devuelve el núcleo (PendingHostKey): host es el texto exacto que vuelve en acceptedKeys.
export interface PendingKey { host: string; fingerprint: string; keyType?: string; changed?: boolean }

// changed: protojson omite false (ausente = false); un valor que no sea booleano falla cerrado (cambiado).
// El puente y la metadata del error son datos externos: se descarta lo que no tenga host y huella.
export function pendingToInfo(raw: unknown): HostKeyInfo[] {
  if (!Array.isArray(raw)) return [];
  return raw.slice(0, 256).flatMap((k: unknown) => {
    const o = (k && typeof k === "object" ? k : {}) as Record<string, unknown>;
    const { host, fingerprint, keyType, changed } = o;
    return typeof host === "string" && host && typeof fingerprint === "string" && fingerprint
      ? [{ host, fp: fingerprint, changed: changed !== undefined && changed !== false, keyType: typeof keyType === "string" && keyType ? keyType : undefined }] : [];
  });
}

// Las huellas que trae el error de ArmJob: metadata.host_keys es un arreglo JSON de PendingHostKey. JSON roto = ninguna.
export function hostKeysFromErr(e: unknown): HostKeyInfo[] {
  try { return pendingToInfo(JSON.parse(errInfo(e)?.metadata.host_keys ?? "")); } catch { return []; }
}
