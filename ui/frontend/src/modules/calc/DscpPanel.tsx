import { useState } from "react";
import { Advanced } from "../../components/Advanced";
import type { CoreAPI } from "../../lib/core";
import { Field, Select } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { kbd, useCalc } from "./shared";

const dscpFields = (t: ReturnType<typeof useT>): [string, string][] => [
  ["", t("calc.dscp.auto")], ["name", t("calc.dscp.name")], ["dscp", "DSCP"], ["binary", t("calc.dscp.binary")], ["tos", "ToS"],
  ["precedence", t("calc.dscp.precedence")], ["cos", "CoS"], ["exp", "MPLS EXP"],
];

export function DscpPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [field, setField] = useState("");
  const c = useCalc(core);
  return (
    <>
      <div className="field-row end">
        <Field label={t("calc.dscp.query")} value={query} onChange={setQuery} w="lg" mono />
      </div>
      <Advanced changed={field !== "" ? 1 : 0}>
        <Select label={t("calc.dscp.field")} value={field} onChange={setField} options={dscpFields(t)} w="md" />
      </Advanced>
      <div className="actions"><button className="primary" disabled={c.busy} aria-busy={c.busy} onClick={() => c.run("dscp", { query, field })}>{t("calc.dscp.btn")}{kbd}</button></div>
      {c.view}
    </>
  );
}
