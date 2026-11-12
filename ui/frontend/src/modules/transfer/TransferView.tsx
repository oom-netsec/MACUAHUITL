import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { useT } from "../../lib/i18n";
import { Page, Tabs } from "../../components/Page";
import type { Key } from "../../lib/i18n/es";
import { ClientPanel } from "./ClientPanel";
import { ServerPanel } from "./ServerPanel";

type Sub = "server" | "client";
const subs: [Sub, Key][] = [["server", "transfer.sub.server"], ["client", "transfer.sub.client"]];

// Transferencias (fase 22a): servidor temporal de TFTP, FTP, SCP, SFTP y HTTP, y cliente de get y put.
export function TransferView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("server");
  return (
    <Page title={t("nav.transfer")} description={t("transfer.intro")}
      tabs={<Tabs label={t("transfer.tool")} value={sub} onChange={setSub} tabs={subs.map(([s, k]) => [s, t(k)] as [Sub, string])} />}>
      {/* Montados siempre: cambiar de pestaña no corta los servidores ni pierde su registro. */}
      <div hidden={sub !== "server"}><ServerPanel core={core} /></div>
      <div hidden={sub !== "client"}><ClientPanel core={core} /></div>
    </Page>
  );
}
