import { useState } from "react";
import type { CoreAPI } from "../../lib/core";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { kbd, useCalc, words } from "./shared";

export function SummarizePanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [list, setList] = useState("");
  const c = useCalc(core);
  return (
    <>
      <Field label={t("calc.sum.list")} value={list} onChange={setList} w="full" mono />
      <div className="actions"><button className="primary" disabled={!list.trim() || c.busy} aria-busy={c.busy} onClick={() => c.run("summarize", { prefixes: words(list) })}>{t("calc.sum.btn")}{kbd}</button></div>
      {c.view}
    </>
  );
}
