import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { kbd, useCalc } from "./shared";

export function Ipv6Panel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [address, setAddress] = useState("");
  const [mac, setMac] = useState("");
  const c = useCalc(core);
  return (
    <>
      <div className="field-row end">
        <Field label={t("calc.ipv6.address")} value={address} onChange={setAddress} w="lg" mono />
        <Field label={t("calc.ipv6.mac")} value={mac} onChange={setMac} w="md" mono />
      </div>
      <div className="actions"><button className="primary" disabled={(!address && !mac) || c.busy} aria-busy={c.busy} onClick={() => c.run("ipv6", { address, mac })}>{t("calc.calculate")}{kbd}</button></div>
      {c.view}
    </>
  );
}
