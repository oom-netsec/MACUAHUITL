import { useState, type ReactNode } from "react";
import type { CoreAPI } from "../../lib/core";
import { Notice, errorText } from "../../components/Field";
import { useT } from "../../lib/i18n";
import type { CollectionsImportPreview, CollectionsImportResult, ImportKind, ImportPreview, ImportResult } from "./api";
import { CollectionsImportPanel } from "./CollectionsImportPanel";
import { ImportPanel, Warnings } from "./ImportPanel";
import { colName } from "./text";

// Import en dos pasos (elegir archivo → vista previa con decisiones → aplicar) de scripts o de colecciones, para la vista
// de Scripts y para Ajustes → Datos. `start` abre el diálogo; `node` lleva avisos, vista previa y resultado donde la vista lo ponga.
export function useImportFlow(core: CoreAPI, kind: ImportKind, onChanged: () => void): { start: () => Promise<void>; node: ReactNode } {
  const t = useT();
  const [sp, setSp] = useState<ImportPreview | null>(null);
  const [cp, setCp] = useState<CollectionsImportPreview | null>(null);
  const [names, setNames] = useState<{ scripts: Map<string, string>; cols: Map<string, string> }>({ scripts: new Map(), cols: new Map() });
  const [err, setErr] = useState("");
  const [msg, setMsg] = useState("");
  const [warns, setWarns] = useState<string[]>([]); // avisos del resultado de aplicar (p. ej. un «lib-*» que no se importó)

  const start = async () => {
    setErr(""); setMsg(""); setWarns([]);
    try {
      const path = await core.pickPath({ title: t(kind === "scripts" ? "scripts.import.file" : "scripts.cimport.preview"), filters: [{ name: "JSON", pattern: "*.json" }] });
      if (!path) return;
      const [p, all, cols] = await Promise.all([kind === "scripts" ? core.previewScriptsImport(path) : core.previewCollectionsImport(path), core.listScripts(), core.listCollections()]);
      setNames({ scripts: new Map(all.map((s) => [s.id, s.name])), cols: new Map(cols.map((c) => [c.id, colName(t, c)])) });
      if (kind === "scripts") setSp(p as ImportPreview); else setCp(p as CollectionsImportPreview);
    } catch (e) { setErr(errorText(e)); }
  };
  const close = (text?: string, w: string[] = []) => {
    setSp(null); setCp(null);
    if (text) { setMsg(text); setWarns(w); onChanged(); }
  };
  const expired = () => { close(); setErr(t("scripts.import.expired")); };

  const node = (
    <>
      {err && <Notice kind="error">{err}</Notice>}
      {msg && <Notice kind="ok">{msg}</Notice>}
      <Warnings list={warns} />
      {sp && <ImportPanel preview={sp} nameOf={(id) => names.scripts.get(id) ?? id} onApply={core.applyScriptsImport} onExpired={expired}
        onClose={(r?: ImportResult) => close(r && t("scripts.import.done", { created: String(r.created), replaced: String(r.replaced), renamed: String(r.renamed), skipped: String(r.skipped) }))} />}
      {cp && <CollectionsImportPanel preview={cp} colNameOf={(id) => names.cols.get(id) ?? id} scriptNameOf={(id) => names.scripts.get(id) ?? id} onApply={core.applyCollectionsImport} onExpired={expired}
        onClose={(r?: CollectionsImportResult) => close(r && t("scripts.cimport.done", { c: r.collectionsCreated, r: r.collectionsReplaced, n: r.collectionsRenamed, m: r.collectionsMerged, s: r.collectionsSkipped, sc: r.scriptsCreated, sr: r.scriptsReplaced, sn: r.scriptsRenamed, ss: r.scriptsSkipped }), r?.warnings)} />}
    </>
  );
  return { start, node };
}
