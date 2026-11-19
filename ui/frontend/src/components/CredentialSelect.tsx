import { useEffect, useState } from "react";
import { useNav } from "../app/activity";
import type { CoreAPI } from "../lib/core";
import { useT } from "../lib/i18n";
import { useVaultVersion } from "../lib/vaultSignal";
import { passwordCreds } from "../lib/credentials";
import type { Credential } from "../modules/vault/api";
import { Notice, Select, errorText, type Width } from "./Field";

// loading: aún sin respuesta; absent/locked: no hay lista que ofrecer; open: la lista se leyó (puede estar vacía);
// error: el núcleo no respondió (el texto va en `error` del hook; no es lo mismo que una bóveda cerrada).
export type VaultGate = "loading" | "absent" | "locked" | "open" | "error";

// Credenciales de la bóveda, con recarga cuando la bóveda cambia. Por omisión solo las de contraseña; con `keys` también las de llave.
export function useCredentials(core: CoreAPI, { keys }: { keys?: boolean } = {}): { creds: Credential[]; vault: VaultGate; error: string } {
  const vv = useVaultVersion();
  const [s, setS] = useState<{ creds: Credential[]; vault: VaultGate; error: string }>({ creds: [], vault: "loading", error: "" });
  useEffect(() => {
    let live = true; // una respuesta vieja no pisa a una nueva
    // El estado dice si la bóveda no existe o está cerrada; si ni eso responde (núcleo caído), queda en error.
    core.vaultStatus().then(async (v) => {
      if (v.state !== "unlocked") return live ? setS({ creds: [], vault: v.state === "absent" ? "absent" : "locked", error: "" }) : undefined;
      try {
        const l = await core.listCredentials();
        if (live) setS({ creds: keys ? l : passwordCreds(l), vault: "open", error: "" });
      } catch (e) {
        // ¿se cerró entre el estado y la lista? Si sigue abierta, el fallo es otro y se dice como error.
        const now = await core.vaultStatus().catch(() => null);
        if (live) setS(now && now.state !== "unlocked" ? { creds: [], vault: now.state === "absent" ? "absent" : "locked", error: "" } : { creds: [], vault: "error", error: errorText(e) });
      }
    }, (e) => { if (live) setS({ creds: [], vault: "error", error: errorText(e) }); });
    return () => { live = false; };
  }, [core, vv, keys]);
  return s;
}

type Props = {
  creds: Credential[]; value: string; onChange: (id: string) => void;
  label?: string; hint?: string; error?: string; w?: Width;
  optional?: boolean; // la primera opción es «ninguna» y es el valor por defecto
  vault: VaultGate; // del hook: la regla del valor por defecto solo corre con la lista ya leída
  vaultError?: string; // texto del hook cuando vault = error
  notice?: boolean; // false: la vista ya avisa de la bóveda por su cuenta
  extra?: [string, string]; // valor que no está en la lista (p. ej. credencial oculta con la bóveda cerrada) pero debe conservarse
};

export function CredentialSelect({ creds, value, onChange, label, hint, error, w = "md", optional, vault, vaultError, notice = true, extra }: Props) {
  const t = useT();
  const go = useNav();
  // Regla única del valor por defecto: se conserva el actual si sigue disponible; si no, solo se preelige cuando hay UNA credencial.
  // Con varias queda vacío y el usuario elige: probar la equivocada contra N equipos bloquea cuentas (TACACS) o cambia configuración.
  // Mientras carga, o con la bóveda cerrada, no se sabe si el valor existe: no se toca (editar un host no pierde su credencial).
  useEffect(() => {
    if (vault !== "open") return;
    if (value && (creds.some((c) => c.id === value) || extra?.[0] === value)) return;
    const d = !optional && creds.length === 1 ? creds[0].id : "";
    if (d !== value) onChange(d);
  }, [vault, creds, value, optional, extra, onChange]);
  const closed = notice && (vault === "absent" || vault === "locked");
  // Con la lista sin leer, un valor ya elegido se conserva y se muestra como tal: el select no dice «ninguna» mientras se manda otra cosa.
  const kept: [string, string][] = vault !== "open" && value && !creds.some((c) => c.id === value) && extra?.[0] !== value ? [[value, t("hosts.cred.hidden")]] : [];
  return (
    <>
      <Select label={label ?? t("assist.cred")} hint={hint} error={error} w={w} value={value} onChange={onChange} placeholder={optional ? undefined : t("cred.pick")}
        options={[...(optional ? [["", t("cred.none")] as [string, string]] : []), ...creds.map((c) => [c.id, `${c.label} (${c.username})`] as [string, string]), ...(extra ? [extra] : []), ...kept]} />
      {notice && vault === "error" && <div className="cred-notice"><Notice kind="error">{t("cred.vault.error", { error: vaultError ?? "" })}</Notice></div>}
      {closed && (
        <div className="cred-notice">
          <Notice kind="info">
            {t(vault === "absent" ? "cred.vault.absent" : "cred.vault.locked")}
            <button type="button" className="inline" onClick={() => go("vault")}>{t(vault === "absent" ? "vault.create" : "vault.unlock")}</button>
          </Notice>
        </div>
      )}
    </>
  );
}
