import { useState, type ReactElement } from "react";
import type { CoreAPI } from "../../lib/core";
import { Page, TabPanels, Tabs } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { BgpPanel } from "./BgpPanel";
import { DscpPanel } from "./DscpPanel";
import { Ipv6Panel } from "./Ipv6Panel";
import { MtuPanel } from "./MtuPanel";
import { OpticsPanel } from "./OpticsPanel";
import { SubnetPanel } from "./SubnetPanel";
import { SummarizePanel } from "./SummarizePanel";
import { TcpPanel } from "./TcpPanel";
import { VlsmPanel } from "./VlsmPanel";
import { WildcardPanel } from "./WildcardPanel";
import "./calc.css";

const subs = ["subnet", "vlsm", "summarize", "wildcard", "ipv6", "mtu", "tcp", "dscp", "optics", "bgp"] as const;
type Sub = (typeof subs)[number];
const panels: Record<Sub, (p: { core: CoreAPI }) => ReactElement> = { subnet: SubnetPanel, vlsm: VlsmPanel, summarize: SummarizePanel, wildcard: WildcardPanel, ipv6: Ipv6Panel, mtu: MtuPanel, tcp: TcpPanel, dscp: DscpPanel, optics: OpticsPanel, bgp: BgpPanel };

export function CalcView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("subnet");
  return (
    <Page title={t("calc.title")} description={t("calc.desc")}
      tabs={<Tabs label={t("calc.nav")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, t(`calc.sub.${s}`)] as [Sub, string])} />}>
      <TabPanels value={sub} render={(s) => {
        const P = panels[s];
        return <P core={core} />;
      }} />
    </Page>
  );
}
