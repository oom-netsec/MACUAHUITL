// Archivos (ADR 0009): soltar o elegir, descargar y exportar con el nombre sugerido, y progreso de transferencia.
import { useContext, useEffect, useId, useRef, useState } from "react";
import { CoreContext } from "../app/activity";
import { useT } from "../lib/i18n";
import type { Key } from "../lib/i18n/es";
import { Icon } from "./Icon";
import { Notice } from "./Field";
import { StatusPill } from "./Data";

export function formatBytes(n: number): string {
  const u = ["B", "KiB", "MiB", "GiB", "TiB"];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${Number.isInteger(n) ? n : n.toFixed(1)} ${u[i]}`;
}

// Zona para soltar archivos (rutas vía ui/main.go) o elegirlos con el diálogo nativo.
export function DropZone({ label, accept, multiple = true, onPaths }: { label: string; accept?: string[]; multiple?: boolean; onPaths: (paths: string[]) => void }) {
  const t = useT();
  const core = useContext(CoreContext);
  const id = `drop-${useId().replace(/[^a-z0-9]/gi, "")}`;
  const [rejected, setRejected] = useState<string[]>([]);
  const cb = useRef(onPaths);
  cb.current = onPaths;
  const ok = (p: string) => !accept?.length || accept.some((ext) => p.toLowerCase().endsWith(`.${ext}`));
  useEffect(() => core?.onFilesDropped((e) => {
    if (e.target !== id) return;
    const good = e.paths.filter(ok);
    setRejected(e.paths.filter((p) => !ok(p)).map((p) => p.split("/").pop() ?? p));
    if (good.length) cb.current(multiple ? good : good.slice(0, 1));
  }), [core, id]);
  const pick = async () => {
    const p = await core?.pickPath({ title: label, filters: accept?.length ? [{ name: label, pattern: accept.map((x) => `*.${x}`).join(";") }] : undefined }).catch(() => ""); // diálogo que no abrió: nada elegido
    if (p) { setRejected([]); cb.current([p]); }
  };
  return (
    <div id={id} className="dropzone" role="group" aria-label={label} data-file-drop-target>
      <Icon name="upload" size={20} />
      <span>{t("files.drop")}</span>
      {accept?.length ? <span className="meta">{accept.map((x) => `.${x}`).join(" · ")}</span> : null}
      <button type="button" onClick={pick}>{t("files.pick")}</button>
      {rejected.length > 0 && <Notice kind="error">{t("files.rejected", { list: rejected.join(", ") })}</Notice>}
    </div>
  );
}

type Fmt = "csv" | "md" | "json" | "txt" | "cfg" | "png";
const encOf = (f: Fmt) => (f === "png" ? "base64" : "utf8") as "utf8" | "base64";

export function DownloadButton({ name, data, label, encoding = "utf8" }: { name: string; data: () => string | Promise<string>; label: string; encoding?: "utf8" | "base64" }) {
  const core = useContext(CoreContext);
  const [busy, setBusy] = useState(false);
  return (
    <button type="button" className="sm" aria-busy={busy} disabled={busy}
      onClick={async () => { setBusy(true); try { await core?.saveFile(name, await data(), encoding); } catch { /* el diálogo o la escritura fallaron: nada que guardar */ } finally { setBusy(false); } }}>
      <Icon name="download" size={14} />{label}
    </button>
  );
}

export function ExportMenu({ name, formats }: { name: string; formats: { fmt: Fmt; data: () => string | Promise<string> }[] }) {
  const t = useT();
  const core = useContext(CoreContext);
  const [open, setOpen] = useState(false);
  const menu = useId();
  const box = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    if (!open) return;
    box.current?.querySelector<HTMLButtonElement>("[role=menuitem]")?.focus();
    const out = (e: PointerEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("pointerdown", out);
    return () => document.removeEventListener("pointerdown", out);
  }, [open]);
  const onKey = (e: React.KeyboardEvent) => {
    const items = [...(box.current?.querySelectorAll<HTMLButtonElement>("[role=menuitem]") ?? [])];
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    if (e.key === "ArrowDown" || e.key === "ArrowUp") { e.preventDefault(); items[(i + (e.key === "ArrowDown" ? 1 : -1) + items.length) % items.length]?.focus(); }
    if (e.key === "Escape") { e.preventDefault(); setOpen(false); }
  };
  return (
    <span className="menu-wrap" ref={box} onKeyDown={onKey}>
      <button type="button" className="sm" aria-haspopup="menu" aria-expanded={open} aria-controls={open ? menu : undefined} onClick={() => setOpen((o) => !o)}>
        <Icon name="download" size={14} />{t("files.export")}
      </button>
      {open && (
        <div className="popover menu" role="menu" id={menu}>
          {formats.map((f) => (
            <button key={f.fmt} role="menuitem" className="quiet" onClick={async () => {
              setOpen(false);
              try { await core?.saveFile(`${name}.${f.fmt}`, await f.data(), encOf(f.fmt)); } catch { /* sin archivo */ }
            }}>{t(`files.fmt.${f.fmt}` as Key)}</button>
          ))}
        </div>
      )}
    </span>
  );
}

export function TransferProgress({ file, bytes, total, rateBps, etaSeconds, done, verified, error, onCancel }: {
  file: string; bytes: number; total: number; rateBps: number; etaSeconds: number; done?: boolean; verified?: boolean; error?: string; onCancel?: () => void;
}) {
  const t = useT();
  const pct = total > 0 ? Math.round((bytes / total) * 100) : undefined;
  const parts = [total > 0 ? t("files.of", { a: formatBytes(bytes), b: formatBytes(total) }) : formatBytes(bytes)];
  if (pct !== undefined) parts.push(`${pct} %`);
  if (!done && rateBps > 0) parts.push(`${formatBytes(rateBps)}/s`);
  if (!done && etaSeconds >= 0) parts.push(t("files.eta", { s: etaSeconds }));
  return (
    <div className="transfer">
      <div className="transfer-head">
        <span className="mono transfer-file">{file}</span>
        {done && !error && <StatusPill tone={verified === false ? "warn" : "ok"} label={t(verified ? "files.verified" : verified === false ? "files.unverified" : "files.done")} />}
        {!done && onCancel && <button className="quiet sm" aria-label={t("files.cancel", { file })} onClick={onCancel}><Icon name="close" size={14} /></button>}
      </div>
      <div className="progress" role="progressbar" aria-label={file} aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct} data-state={error ? "bad" : done ? "ok" : "run"}>
        <span style={{ width: `${pct ?? 100}%` }} />
      </div>
      <span className="meta mono">{parts.join(" · ")}</span>
      {error && <Notice kind="error">{error}</Notice>}
    </div>
  );
}
