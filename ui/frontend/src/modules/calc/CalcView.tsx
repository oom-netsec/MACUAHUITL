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

const groups = [
  ["addressing", ["subnet", "vlsm", "summarize", "wildcard", "ipv6"]],
  ["transport", ["mtu", "tcp", "dscp"]],
  ["physical", ["optics"]],
  ["routing", ["bgp"]],
] as const;
type Group = (typeof groups)[number][0];
type Sub = (typeof groups)[number][1][number];
const panels: Record<Sub, (p: { core: CoreAPI }) => ReactElement> = { subnet: SubnetPanel, vlsm: VlsmPanel, summarize: SummarizePanel, wildcard: WildcardPanel, ipv6: Ipv6Panel, mtu: MtuPanel, tcp: TcpPanel, dscp: DscpPanel, optics: OpticsPanel, bgp: BgpPanel };

export function CalcView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("subnet");
  const group = groups.find(([, ss]) => (ss as readonly Sub[]).includes(sub))![0];
  const subs: readonly Sub[] = groups.find(([g]) => g === group)![1];
  return (
    <Page title={t("calc.title")} description={t("calc.desc")}
      tabs={<>
        <Tabs label={t("calc.navGroup")} value={group} onChange={(g: Group) => setSub(groups.find(([n]) => n === g)![1][0])} tabs={groups.map(([g]) => [g, t(`calc.group.${g}`)] as [Group, string])} />
        <Tabs label={t("calc.nav")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, t(`calc.sub.${s}`)] as [Sub, string])} />
      </>}>
      <TabPanels value={sub} render={(s) => {
        const P = panels[s];
        return <P core={core} />;
      }} />
    </Page>
  );
}
