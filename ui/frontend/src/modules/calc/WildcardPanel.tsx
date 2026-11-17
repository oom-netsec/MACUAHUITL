import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { kbd, useCalc } from "./shared";

export function WildcardPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [address, setAddress] = useState("");
  const [value, setValue] = useState("");
  const c = useCalc(core);
  return (
    <>
      <div className="field-row end">
        <Field label={t("calc.wc.address")} value={address} onChange={setAddress} w="lg" mono />
        <Field label={t("calc.wc.value")} value={value} onChange={setValue} w="lg" mono />
      </div>
      <div className="actions"><button className="primary" disabled={!value || c.busy} aria-busy={c.busy} onClick={() => c.run("wildcard", { address, value })}>{t("calc.wc.btn")}{kbd}</button></div>
      {c.view}
    </>
  );
}
