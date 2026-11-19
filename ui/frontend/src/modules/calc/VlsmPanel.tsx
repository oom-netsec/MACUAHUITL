import { useState } from "react";
import { RunButton } from "../../components/RunButton";
import type { CoreAPI } from "../../lib/core";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { useCalc, words } from "./shared";

export function VlsmPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [network, setNetwork] = useState("");
  const [needs, setNeeds] = useState("");
  const c = useCalc(core);
  const parsed = words(needs).map((w) => {
    const [name, hosts] = w.includes("=") ? w.split("=", 2) : ["", w];
    return { name, hosts: Number(hosts) };
  });
  return (
    <>
      <Field label={t("calc.vlsm.network")} value={network} onChange={setNetwork} w="lg" mono />
      <Field label={t("calc.vlsm.needs")} value={needs} onChange={setNeeds} hint={t("calc.vlsm.note")} w="full" mono />
      <div className="actions"><RunButton primary kbd busy={c.busy} missing={[!network && t("need.network"), parsed.length === 0 && t("need.vlsmNeeds")]} onClick={() => c.run("vlsm", { network, needs: parsed })}>{t("calc.vlsm.btn")}</RunButton></div>
      {c.view}
    </>
  );
}
