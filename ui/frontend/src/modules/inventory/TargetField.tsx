import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, TextArea } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { parseTargets, targetOf } from "../../lib/targets";
import type { Host } from "./api";
import { HostPicker, useHosts } from "./HostPicker";

// «Elegir de la libreta» abre el HostPicker bajo el campo; sin hosts guardados no se ofrece. Va aquí y no en components/ porque usa el módulo inventory (ADR 0008).
function Pick({ core, onPick }: { core: CoreAPI; onPick: (h: Host) => void }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  if (useHosts(core).length === 0) return null;
  return (
    <>
      <button type="button" className="quiet" aria-expanded={open} onClick={() => setOpen(!open)}>{t("hosts.pick.open")}</button>
      {open && <HostPicker core={core} onPick={(h) => { onPick(h); setOpen(false); }} />}
    </>
  );
}

// Un equipo («host», «host:puerto» o «[ipv6]:puerto»). Elegir de la libreta lo rellena y avisa su credencial, si la tiene.
export function TargetField({ core, value, onChange, onPickCredential }: { core: CoreAPI; value: string; onChange: (v: string) => void; onPickCredential?: (credentialId: string) => void }) {
  const t = useT();
  return (
    <div>
      <Field label={t("assist.device")} value={value} onChange={onChange} w="lg" mono />
      <Pick core={core} onPick={(h) => { onChange(targetOf(h)); if (h.credentialId) onPickCredential?.(h.credentialId); }} />
    </div>
  );
}

// Varios equipos separados por comas, espacios o saltos de línea. Elegir de la libreta agrega el host (una vez) al final.
export function TargetsField({ core, value, onChange, onPickCredential, hint, rows = 3 }: { core: CoreAPI; value: string; onChange: (v: string) => void; onPickCredential?: (credentialId: string) => void; hint?: string; rows?: number }) {
  const t = useT();
  return (
    <div>
      <TextArea label={t("adhoc.devices")} hint={hint} value={value} onChange={onChange} rows={rows} mono />
      <Pick core={core} onPick={(h) => {
        const tg = targetOf(h);
        if (!parseTargets(value).includes(tg)) onChange(value.trim() ? `${value.trimEnd()}\n${tg}` : tg);
        if (h.credentialId) onPickCredential?.(h.credentialId);
      }} />
    </div>
  );
}
