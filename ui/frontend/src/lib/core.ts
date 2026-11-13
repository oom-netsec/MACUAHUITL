// Contrato entre la UI y el puente Go (ui/bridge). La UI nunca recibe secretos.
import { Call, Clipboard, Dialogs, Events } from "@wailsio/runtime";
import { tr } from "./i18n";
import { errorText } from "../components/Field";
import { fileExists } from "./coreError";
import { portsWails, type PortsAPI } from "../modules/ports/api";
import { snippetsWails, type SnippetsAPI } from "../modules/snippets/api";
import { credRotateWails, type CredRotateAPI } from "../modules/credrotate/api";
import { backupWails, type BackupAPI } from "../modules/backup/api";
import { terminalWails, type TerminalAPI } from "../modules/terminal/api";
import { vaultWails, type VaultAPI } from "../modules/vault/api";
import { auditWails, type AuditAPI } from "../modules/audit/api";
import { patrolWails, type PatrolAPI } from "../modules/patrol/api";
import { diagWails, type DiagAPI } from "../modules/diag/api";
import { aclWails, type AclAPI } from "../modules/acl/api";
import { toolsWails, type ToolsAPI } from "../modules/tools/api";
import { securityWails, type SecurityAPI } from "../modules/security/api";
import { changeWails, type ChangeAPI } from "../modules/change/api";
import { visibilityWails, type VisibilityAPI } from "../modules/visibility/api";
import { analysisWails, type AnalysisAPI } from "../modules/analysis/api";
import { calcWails, type CalcAPI } from "../modules/calc/api";
import { consoleWails, type ConsoleAPI } from "../modules/console/api";
import { fieldWails, type FieldAPI } from "../modules/field/api";
import { fleetWails, type FleetAPI } from "../modules/fleet/api";
import { adhocWails, type AdhocAPI } from "../modules/adhoc/api";
import { driftWails, type DriftAPI } from "../modules/drift/api";
import { cleanerWails, type CleanerAPI } from "../modules/cleaner/api";
import { forensicWails, type ForensicAPI } from "../modules/forensic/api";
import { transferWails, type TransferAPI } from "../modules/transfer/api";
import { metricsWails, type MetricsAPI } from "../modules/metrics/api";
import { inventoryWails, type InventoryAPI } from "../modules/inventory/api";
import { scriptsWails, type ScriptsAPI } from "../modules/scripts/api";
import { settingsWails, type SettingsAPI } from "../modules/settings/api";
import { packsWails, type PacksAPI } from "../modules/packs/api";

export type CoreStatus = "connected" | "disconnected";

// Diálogo nativo de archivos (GTK). Devuelve "" si se cancela.
export interface PickOptions { title: string; directory?: boolean; filters?: { name: string; pattern: string }[] }

// Los tipos de cada área viven en su api.ts; se reexportan aquí para no cambiar los imports existentes.
export type * from "../modules/vault/api";
export type * from "../modules/patrol/api";
export type * from "../modules/diag/api";
export type * from "../modules/acl/api";
export type * from "../modules/tools/api";
export type * from "../modules/security/api";
export type * from "../modules/change/api";
export type * from "../modules/visibility/api";
export type * from "../modules/analysis/api";
export type * from "../modules/calc/api";
export type * from "../modules/field/api";
export type * from "../modules/console/api";
export type * from "../modules/fleet/api";
export type * from "../modules/adhoc/api";
export type * from "../modules/drift/api";
export type * from "../modules/cleaner/api";
export type * from "../modules/transfer/api";
export type * from "../modules/metrics/api";
export type * from "../modules/inventory/api";
export type * from "../modules/scripts/api";
export type * from "../modules/settings/api";
export type * from "../modules/packs/api";

// Lo compartido por todos los módulos: estado del núcleo, preferencias, diálogo de archivos y portapapeles.
export interface BaseAPI {
  coreStatus(): Promise<CoreStatus>;
  onStatus(cb: (s: CoreStatus) => void): () => void;
  getPreference(key: string): Promise<string>;
  setPreference(key: string, value: string): Promise<void>;
  pickPath(o: PickOptions): Promise<string>;
  copyText(text: string): Promise<void>;
  // Diálogo nativo de guardar con el nombre sugerido; el puente escribe el archivo. Devuelve la ruta o "" si se cancela.
  // Contrato pendiente en el puente (docs/plans/contratos-front.md).
  saveFile(name: string, data: string, encoding: "utf8" | "base64"): Promise<string>;
  // Archivos soltados en la ventana sobre una zona [data-file-drop-target] (ui/main.go): rutas y el id de la zona.
  onFilesDropped(cb: (e: { target: string; paths: string[] }) => void): () => void;
  // Diálogo nativo de guardar solo para elegir la ruta (un registro que se reescribe): confirma la sobrescritura
  // y deja el archivo creado, vacío. Devuelve la ruta o "" si se cancela o falla.
  pickSavePath(name: string): Promise<string>;
  // Escribe en una ruta absoluta que la persona ya eligió (puente WriteFile).
  writeFile(path: string, data: string, encoding: "utf8" | "base64", overwrite: boolean): Promise<void>;
  // Texto del portapapeles (Ctrl+Mayús+V en la terminal: WebKitGTK no manda el evento paste).
  pasteText(): Promise<string>;
  // Pegar varias líneas en una terminal ejecuta cada una: pregunta antes, con el equipo y una vista previa. true = pegar.
  // Con `script` (el nombre de un script de la bóveda) el diálogo dice cuántas líneas se ejecutan: todas menos la última.
  confirmPaste(text: string, host: string, script?: string): Promise<boolean>;
}

// Cada módulo aporta su parte del contrato (ADR 0008): una línea aquí y otra en wailsCore.
export interface CoreAPI extends
  BaseAPI,
  VaultAPI,
  AuditAPI,
  PatrolAPI,
  DiagAPI,
  AclAPI,
  ToolsAPI,
  SecurityAPI,
  ChangeAPI,
  VisibilityAPI,
  AnalysisAPI,
  CalcAPI,
  FieldAPI,
  ConsoleAPI,
  FleetAPI,
  AdhocAPI,
  DriftAPI,
  CleanerAPI,
  PortsAPI,
  SnippetsAPI,
  CredRotateAPI,
  BackupAPI,
  TerminalAPI,
  ForensicAPI,
  TransferAPI,
  MetricsAPI,
  InventoryAPI,
  ScriptsAPI,
  SettingsAPI,
  PacksAPI {}

const svc = "github.com/oom-netsec/MACUAHUITL/ui/bridge.Bridge.";
const call = <T,>(m: string, ...a: unknown[]) => Call.ByName(svc + m, ...a) as Promise<T>;

const confirmReplace = async (path: string) => {
  const yes = tr("files.replace.yes");
  return (await Dialogs.Question({ Title: tr("files.replace.title"), Message: tr("files.replace.msg", { path }), Buttons: [{ Label: yes }, { Label: tr("files.replace.no"), IsCancel: true, IsDefault: true }] })) === yes;
};

export const wailsCore: CoreAPI = {
  coreStatus: () => call("Status"),
  onStatus: (cb) => Events.On("core:status", (e) => cb(e.data as CoreStatus)),
  getPreference: (k) => call("GetPreference", k),
  setPreference: (k, v) => call("SetPreference", k, v),
  // Solo del runtime de Wails, sin pasar por el puente: el núcleo recibe la ruta igual que si se escribiera.
  pickPath: async (o) => {
    const r = await Dialogs.OpenFile({
      Title: o.title, CanChooseFiles: !o.directory, CanChooseDirectories: !!o.directory, CanCreateDirectories: !!o.directory,
      Filters: o.filters?.map((f) => ({ DisplayName: f.name, Pattern: f.pattern })),
    }).catch(() => "");
    return typeof r === "string" ? r : (r[0] ?? "");
  },
  copyText: (t) => Clipboard.SetText(t),
  // El diálogo nativo da la ruta y el puente escribe. El diálogo GTK3 de Wails no confirma la sobrescritura:
  // el puente se niega y aquí se pregunta. Cancelar devuelve ""; un fallo se muestra y también devuelve "".
  saveFile: async (name, data, encoding) => {
    try {
      const path = await Dialogs.SaveFile({ Filename: name, CanCreateDirectories: true });
      if (!path) return "";
      try {
        await call("WriteFile", path, data, encoding, false);
      } catch (e) {
        if (!fileExists(e)) throw e;
        if (!(await confirmReplace(path))) return "";
        await call("WriteFile", path, data, encoding, true);
      }
      return path;
    } catch (e) {
      await Dialogs.Error({ Title: tr("files.saveError"), Message: errorText(e) }).catch(() => {});
      return "";
    }
  },
  onFilesDropped: (cb) => Events.On("ui:files-dropped", (e) => cb(e.data as { target: string; paths: string[] })),
  // Igual que saveFile, pero solo la ruta: se crea vacío para fallar ya si no se puede escribir y para confirmar el reemplazo.
  pickSavePath: async (name) => {
    try {
      const path = await Dialogs.SaveFile({ Filename: name, CanCreateDirectories: true });
      if (!path) return "";
      try {
        await call("WriteFile", path, "", "utf8", false);
      } catch (e) {
        if (!fileExists(e)) throw e;
        if (!(await confirmReplace(path))) return "";
      }
      return path;
    } catch (e) {
      await Dialogs.Error({ Title: tr("files.saveError"), Message: errorText(e) }).catch(() => {});
      return "";
    }
  },
  writeFile: (path, data, encoding, overwrite) => call("WriteFile", path, data, encoding, overwrite),
  pasteText: () => Clipboard.Text(),
  confirmPaste: async (text, host, script) => {
    const lines = text.replace(/[\r\n]+$/, "").split(/\r\n|\r|\n/);
    const preview = lines.slice(0, 5).map((l) => (l.length > 80 ? `${l.slice(0, 80)}…` : l)).join("\n") + (lines.length > 5 ? "\n…" : "");
    const yes = tr("paste.yes");
    return (await Dialogs.Question({ Title: tr("paste.title"), Message: script ? tr("paste.script", { name: script, n: lines.length, run: lines.length - 1, host, preview }) : tr("paste.msg", { n: lines.length, host, preview }), Buttons: [{ Label: yes }, { Label: tr("paste.no"), IsCancel: true, IsDefault: true }] })) === yes;
  },
  ...vaultWails(call),
  ...auditWails(call),
  ...patrolWails(call),
  ...diagWails(call),
  ...aclWails(call),
  ...toolsWails(call),
  ...securityWails(call),
  ...changeWails(call),
  ...visibilityWails(call),
  ...analysisWails(call),
  ...calcWails(call),
  ...fieldWails(call),
  ...consoleWails(call),
  ...fleetWails(call),
  ...adhocWails(call),
  ...driftWails(call),
  ...cleanerWails(call),
  ...portsWails(call),
  ...snippetsWails(call),
  ...credRotateWails(call),
  ...backupWails(call),
  ...terminalWails(call),
  ...forensicWails(call),
  ...transferWails(call),
  ...metricsWails(call),
  ...inventoryWails(call),
  ...scriptsWails(call),
  ...settingsWails(call),
  ...packsWails(call),
};
