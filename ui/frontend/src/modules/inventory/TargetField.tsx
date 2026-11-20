import { useId, useRef, useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field, TextArea } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { parseTargets, targetOf } from "../../lib/targets";
import type { Host } from "./api";
import { hasStartCommand } from "./hostForm";
import { HostPicker, useHosts } from "./HostPicker";

// Los equipos con orden de inicio (linux/windows) no son de red: Patrol y los asistentes los rechazan, así que no se ofrecen.
// Tampoco los de Telnet: esas tareas conectan siempre por SSH (marcarían al puerto 23 y fallarían).
const managed = (h: Host) => !hasStartCommand(h.platform) && h.protocol !== "telnet";

// «Elegir de la libreta» abre el HostPicker bajo el campo; sin hosts utilizables no se ofrece. Queda abierto al elegir (con flechas el primer change no es la decisión): «Listo» lo cierra y devuelve el foco al botón. Va aquí y no en components/ porque usa el módulo inventory (ADR 0008).
function Pick({ core, onPick }: { core: CoreAPI; onPick: (h: Host) => void }) {
  const t = useT();
  const id = useId();
  const btn = useRef<HTMLButtonElement>(null);
  const [open, setOpen] = useState(false);
  const hosts = useHosts(core);
  if (!hosts.some(managed)) return null;
  return (
    <>
      <button ref={btn} type="button" className="quiet" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}>{t("hosts.pick.open")}</button>
      <div id={id}>
        {open && <>
          <HostPicker core={core} hosts={hosts} filter={managed} onPick={onPick} />
          <button type="button" className="quiet" onClick={() => { setOpen(false); btn.current?.focus(); }}>{t("hosts.pick.done")}</button>
        </>}
      </div>
    </>
  );
}

// La credencial que vino de la libreta puede cambiar con el siguiente host de la libreta; una elegida a mano no se pisa.
export function useBookCredential(creds: { id: string }[], credId: string, setCredId: (id: string) => void) {
  const fromBook = useRef(false);
  return {
    onPickCredential: (id: string) => { if ((!credId || fromBook.current) && creds.some((c) => c.id === id)) { fromBook.current = true; setCredId(id); } },
    onChange: (id: string) => { fromBook.current = false; setCredId(id); },
  };
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
