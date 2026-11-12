import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Page, Tabs } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { CrashSection } from "./CrashSection";
import { DebugSection } from "./DebugSection";
import { FlapSection } from "./FlapSection";
import { LeakSection } from "./LeakSection";
import { MsgSection } from "./MsgSection";
import { PatternsSection } from "./PatternsSection";

// Forense de logs y fallas (Fase 17): todo es de solo lectura; nunca habla con los equipos.
const sections = ["msg", "crash", "patterns", "flap", "debug", "leak"] as const;
type Section = (typeof sections)[number];

export function ForensicView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sec, setSec] = useState<Section>("msg");
  return (
    <Page title={t("forensic.title")} description={t("forensic.desc")}
      tabs={<Tabs label={t("forensic.sections")} value={sec} onChange={setSec} tabs={sections.map((s) => [s, t(`forensic.sec.${s}`)])} />}>
      {sec === "msg" && <MsgSection core={core} />}
      {sec === "crash" && <CrashSection core={core} />}
      {sec === "patterns" && <PatternsSection core={core} />}
      {sec === "flap" && <FlapSection core={core} />}
      {sec === "debug" && <DebugSection core={core} />}
      {sec === "leak" && <LeakSection core={core} />}
    </Page>
  );
}
