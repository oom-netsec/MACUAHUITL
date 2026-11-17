import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Page, Tabs } from "../../components/Page";
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

export function CalcView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("subnet");
  return (
    <Page title={t("calc.title")} description={t("calc.desc")}
      tabs={<Tabs label={t("calc.nav")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, t(`calc.sub.${s}`)] as [Sub, string])} />}>
      {sub === "subnet" && <SubnetPanel core={core} />}
      {sub === "vlsm" && <VlsmPanel core={core} />}
      {sub === "summarize" && <SummarizePanel core={core} />}
      {sub === "wildcard" && <WildcardPanel core={core} />}
      {sub === "ipv6" && <Ipv6Panel core={core} />}
      {sub === "mtu" && <MtuPanel core={core} />}
      {sub === "tcp" && <TcpPanel core={core} />}
      {sub === "dscp" && <DscpPanel core={core} />}
      {sub === "optics" && <OpticsPanel core={core} />}
      {sub === "bgp" && <BgpPanel core={core} />}
    </Page>
  );
}
