import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Page, TabPanels, Tabs } from "../../components/Page";
import { Panels } from "../../components/Panels";
import { Segmented } from "../../components/Segmented";
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
type Pki = "csr" | "ca" | "export" | "decode";

function PkiPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [what, setWhat] = useState<Pki>("csr");
  return (
    <>
      <Segmented legend={t("security.pki.what")} value={what} onChange={setWhat}
        options={[["csr", t("security.pki.csr")], ["ca", t("security.pki.ca")], ["export", t("security.pki.export")], ["decode", t("security.pki.decode")]]} />
      <Panels value={what} panels={{ csr: <CsrCard core={core} />, ca: <CaCard core={core} />, export: <ExportCard core={core} />, decode: <DecodeCard core={core} /> }} />
    </>
  );
}

export function SecurityView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("RADIUS");
  return (
    <Page title={t("security.title")} description={t("security.desc")}
      tabs={<Tabs label={t("security.tool")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, s] as [Sub, string])} />}>
      <TabPanels value={sub} render={(s) => s === "RADIUS" ? <RadiusPanel core={core} /> : s === "TACACS+" ? <TacacsPanel core={core} /> : s === "IKE/IPsec" ? <IkePanel core={core} /> : <PkiPanel core={core} />} />
    </Page>
  );
}
