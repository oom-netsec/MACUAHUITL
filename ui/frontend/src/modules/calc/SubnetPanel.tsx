import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { kbd, useCalc } from "./shared";

export function SubnetPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [prefix, setPrefix] = useState("");
  const c = useCalc(core);
  return (
    <>
      <Field label={t("calc.subnet.prefix")} value={prefix} onChange={setPrefix} w="lg" mono />
      <div className="actions"><button className="primary" disabled={!prefix || c.busy} aria-busy={c.busy} onClick={() => c.run("subnet", { prefix })}>{t("calc.calculate")}{kbd}</button></div>
      {c.view}
    </>
  );
}
