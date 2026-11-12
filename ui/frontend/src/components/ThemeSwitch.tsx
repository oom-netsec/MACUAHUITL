import { Segmented } from "./Segmented";
import { useT } from "../lib/i18n";
import { setTheme, useTheme, type Theme } from "../lib/theme";
import type { Key } from "../lib/i18n/es";

const options: [Theme, Key][] = [["system", "shell.theme.system"], ["light", "shell.theme.light"], ["dark", "shell.theme.dark"]];

export function ThemeSwitch() {
  const t = useT();
  return <Segmented legend={t("shell.theme")} value={useTheme()} onChange={setTheme} options={options.map(([v, k]) => [v, t(k)])} />;
}
