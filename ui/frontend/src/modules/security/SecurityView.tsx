import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Page, TabPanels, Tabs } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { CaCard } from "./CaCard";
import { CsrCard } from "./CsrCard";
import { DecodeCard } from "./DecodeCard";
import { ExportCard } from "./ExportCard";
import { IkePanel } from "./IkePanel";
import { RadiusPanel } from "./RadiusPanel";
import { TacacsPanel } from "./TacacsPanel";
import "./security.css";

type Sub = "RADIUS" | "TACACS+" | "PKI" | "IKE/IPsec";
const subs: Sub[] = ["RADIUS", "TACACS+", "PKI", "IKE/IPsec"];

export function SecurityView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("RADIUS");
  return (
    <Page title={t("security.title")} description={t("security.desc")}
      tabs={<Tabs label={t("security.tool")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, s] as [Sub, string])} />}>
      <TabPanels value={sub} render={(s) => s === "RADIUS" ? <RadiusPanel core={core} /> : s === "TACACS+" ? <TacacsPanel core={core} /> : s === "IKE/IPsec" ? <IkePanel core={core} /> : (
        <>
          <CsrCard core={core} />
          <CaCard core={core} />
          <ExportCard core={core} />
          <DecodeCard core={core} />
        </>
      )} />
    </Page>
  );
}
