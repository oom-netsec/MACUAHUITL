import { useState } from "react";
import { Field, Select, type Width } from "./Field";
import { useCoreLoad } from "../lib/useCoreLoad";
import { useT } from "../lib/i18n";
import type { CoreAPI } from "../lib/core";

const ALL = "0.0.0.0";

// IP de las interfaces arriba, con su nombre: de ahí sale la lista de «Escuchar en».
export function useLocalIPs(core: CoreAPI) {
  const [ips, setIps] = useState<[string, string][]>([]);
  const [err, clear] = useCoreLoad((live) => core.listInterfaces().then((l) => {
    if (live()) setIps((l ?? []).filter((i) => i.up).flatMap((i) => i.addresses.map((a) => [a.replace(/\/\d+$/, ""), i.name] as [string, string])));
  }), [core]);
  return { ips, err, clear };
}

// «host:puerto» ↔ partes; el IPv6 va entre corchetes solo al unir.
export function splitHostPort(s: string): { host: string; port: string } {
  const i = s.lastIndexOf(":");
  return i < 0 ? { host: s, port: "" } : { host: s.slice(0, i).replace(/^\[|\]$/g, ""), port: s.slice(i + 1) };
}
export const joinListen = (host: string, port: string) => (host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`);

// Un solo «Escuchar en»: IP local o «Todas». Elegir «Todas» solo marca `any`; lo que se envía lo decide la vista (con any, 0.0.0.0).
// `port`/`onPort` (opcionales) añaden el campo de puerto al lado, para las vistas que mandan «host:puerto».
export function ListenField({ label, hint, value, onChange, any, onAny, ips, port, onPort, portError, w = "md" }: {
  label: string; hint?: string; value: string; onChange: (v: string) => void; any: boolean; onAny: (v: boolean) => void;
  ips: readonly (readonly [string, string])[]; port?: string; onPort?: (v: string) => void; portError?: string; w?: Width;
}) {
  const t = useT();
  return (
    <>
      <Select label={label} hint={hint} w={w} keepUnknown value={any ? ALL : value}
        onChange={(v) => (v === ALL ? onAny(true) : (onAny(false), onChange(v)))}
        options={[...(value || any ? [] : [["", t("common.select")] as [string, string]]), ...ips.map(([ip, n]) => [ip, `${ip} · ${n}`] as [string, string]), [ALL, t("listen.all")]]} />
      {port !== undefined && onPort && <Field label={t("transfer.port")} value={port} onChange={onPort} w="xs" mono inputMode="numeric" error={portError} />}
    </>
  );
}
