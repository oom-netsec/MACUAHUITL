// Estado compartido de los receptores (syslog, traps, flujos): formulario de opciones con sus errores, archivo y descartes, y el juntado de eventos.
import { useState } from "react";
import type { SyslogDrops } from "../../modules/tools/api";
import { useT } from "../../lib/i18n";
import { optErrorText, type OptMessages } from "./IngestOptions";
import type { ErrInfo } from "../../lib/coreError";
import { buildOpts, coreFieldError, emptyForm, mapStartError, perSourceTemplate, validateOpts, type IngestKind, type OptForm, type OptKey } from "./ingestOpts";

/** Lo que se pidió al iniciar: la línea de estado y el aviso de tope dependen de eso y no de lo que se edite después. */
export interface IngestRun { save: boolean; perSource: boolean; maxFiles: number }

export function useIngestOpts(kind: IngestKind, save: boolean) {
  const t = useT();
  const [form, setForm] = useState<OptForm>(emptyForm);
  const [open, setOpen] = useState(false);
  const [startErr, setStartErr] = useState<OptMessages>({}); // error de inicio que nombró el núcleo, junto a su campo
  const [file, setFile] = useState(""); // archivo actual (último rotatedPath)
  const [folder, setFolder] = useState("");
  const [drops, setDrops] = useState<SyslogDrops | null>(null);
  const [run, setRun] = useState<IngestRun>({ save: false, perSource: false, maxFiles: 20 });

  const touch = (k: OptKey) => setStartErr((s) => ({ ...s, [k]: undefined })); // corregir un campo limpia su error de inicio
  const setOpt = (k: OptKey, v: string) => { setForm((f) => ({ ...f, [k]: v })); touch(k); };
  const live: OptMessages = Object.fromEntries(Object.entries(validateOpts(form, save, kind)).map(([k, c]) => [k, optErrorText(t, k as OptKey, c)]));
  const errors = { ...live, ...Object.fromEntries(Object.entries(startErr).filter(([, v]) => v)) } as OptMessages;

  return {
    form, setOpt, touch, errors, open, setOpen, file, folder, drops, run,
    /** Antes de iniciar: false (y abre las opciones) si algún campo no pasa la validación. */
    check: () => {
      setStartErr({});
      if (!Object.keys(validateOpts(form, save, kind)).length) return true;
      setOpen(true);
      return false;
    },
    /** Limpia lo de la escucha anterior y anota lo que se pide ahora; devuelve las opciones que se mandan. */
    begin: () => {
      setFile(""); setFolder(""); setDrops(null);
      setRun({ save, perSource: perSourceTemplate(form.nameTemplate), maxFiles: Number(form.maxFiles.trim()) || 20 });
      return buildOpts(form, save, kind);
    },
    /** Ya escucha: las opciones no se editan, deja lugar a los resultados. */
    started: () => setOpen(false),
    /** rotatedPath, drops y la carpeta del primer evento; true si el evento era de esos. */
    meta: (e: { outputPath?: string; rotatedPath?: string; drops?: SyslogDrops; listening?: string }) => {
      if (e.listening) { if (e.outputPath) setFolder(e.outputPath); return true; }
      if (e.rotatedPath) { setFile(e.rotatedPath.split(/[\\/]/).pop() ?? ""); return true; }
      if (e.drops) { setDrops(e.drops); return true; }
      return false;
    },
    /** Un error de inicio (rechazo o done{error}): si nombra un campo, va junto a él y devuelve true; si no, lo maneja quien llama. */
    mapError: (msg: string, info?: ErrInfo) => {
      // Con motivo del núcleo se usa su metadata; el texto en español solo es respaldo para errores sin cause.
      const c = info && coreFieldError(info, t);
      const k = c ? c[0] : info?.reason ? null : mapStartError(msg);
      if (!k) return false;
      setStartErr({ [k]: c?.[1] || msg.replace(/^(syslogd|snmp traps|snmp|flows|traps|ingest): /, "") });
      if (k !== "addr") setOpen(true);
      return true;
    },
  };
}
