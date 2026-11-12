import { Window } from "@wailsio/runtime";
import { Icon } from "../components/Icon";
import { useT } from "../lib/i18n";

// Ventana sin marco: estos botones reemplazan a los de GTK.
export function WindowControls() {
  const t = useT();
  return (
    <div className="window-controls">
      <button aria-label={t("window.minimise")} onClick={() => Window.Minimise()}><Icon name="minimise" size={14} /></button>
      <button aria-label={t("window.maximise")} onClick={() => Window.ToggleMaximise()}><Icon name="maximise" size={14} /></button>
      <button aria-label={t("window.close")} className="close" onClick={() => Window.Close()}><Icon name="close" size={14} /></button>
    </div>
  );
}
