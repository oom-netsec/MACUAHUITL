import { Check } from "../../components/Field";
import type { CoreAPI } from "../../lib/core";
import { Page, Section } from "../../components/Page";
import { DataSection } from "./DataSection";
import { StorageSection } from "./StorageSection";
import { LanguageSwitch, useT } from "../../lib/i18n";
import { PaletteSwatch, paletteName } from "../../components/Terminal";
import { ThemeSwitch } from "../../components/ThemeSwitch";
import { PALETTES } from "../../lib/termHighlight";
import { setTermPrefs, useTermPrefs } from "../../lib/termPrefs";
import "./settings.css";

// Ajustes: reúne las preferencias que ya existían (tema, idioma, terminal) con las mismas tiendas de siempre.
export function SettingsView({ core }: { core: CoreAPI }) {
  const t = useT();
  const { palette, hl, srm } = useTermPrefs();
  return (
    <Page title={t("settings.title")} description={t("settings.desc")}>
      <Section title={t("settings.appearance")} description={t("settings.appearance.desc")}>
        <ThemeSwitch />
      </Section>
      <Section title={t("settings.language")} description={t("settings.language.desc")}>
        <LanguageSwitch />
      </Section>
      <Section title={t("settings.terminal")} description={t("settings.terminal.desc")}>
        <fieldset className="settings-palettes">
          <legend>{t("term.palette")}</legend>
          {PALETTES.map((p) => (
            <label key={p.id}>
              <input type="radio" name="term-palette" value={p.id} checked={p.id === palette} onChange={() => setTermPrefs({ palette: p.id })} />
              <PaletteSwatch p={p} />
              <span>{paletteName(t, p)}</span>
            </label>
          ))}
        </fieldset>
        <div className="settings-checks">
          <Check label={t("ssh.hl")} checked={hl} onChange={(v) => setTermPrefs({ hl: v })} />
          <Check label={t("term.screenReader")} checked={srm} onChange={(v) => setTermPrefs({ srm: v })} />
        </div>
      </Section>
      <Section title={t("settings.storage")} description={t("settings.storage.desc")}>
        <StorageSection core={core} />
      </Section>
      <Section title={t("settings.data")} description={t("settings.data.desc")}>
        <DataSection core={core} />
      </Section>
    </Page>
  );
}
