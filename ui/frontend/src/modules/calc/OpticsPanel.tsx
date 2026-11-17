import type { CoreAPI } from "../../lib/core";
import { Field, Select } from "../../components/Field";
import { Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";
import { kbd, useCalc } from "./shared";

const fibers = (t: ReturnType<typeof useT>): [string, string][] => [["smf-1310", t("calc.fiber.smf1310")], ["smf-1550", t("calc.fiber.smf1550")], ["mmf-850", t("calc.fiber.mmf850")], ["mmf-1300", t("calc.fiber.mmf1300")]];

interface OpticsForm {
  tx: string; rx: string; ov: string; km: string; fiber: string; lpk: string; conn: string; connLoss: string;
  splices: string; spliceLoss: string; margin: string; power: string;
}
const initial: OpticsForm = {
  tx: "", rx: "", ov: "", km: "", fiber: "smf-1310", lpk: "", conn: "2", connLoss: "0.5",
  splices: "0", spliceLoss: "0.1", margin: "3", power: "",
};

export function OpticsPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, set] = useForm(initial);
  const { tx, rx, ov, km, fiber, lpk, conn, connLoss, splices, spliceLoss, margin, power } = f;
  const c = useCalc(core);
  const budget = () => c.run("optics", {
    txDbm: Number(tx), rxSensitivityDbm: Number(rx), km: Number(km), fiber, lossPerKm: Number(lpk) || 0,
    connectors: Number(conn) || 0, connectorLossDb: Number(connLoss) || 0, splices: Number(splices) || 0, spliceLossDb: Number(spliceLoss) || 0,
    marginDb: Number(margin) || 0, ...(ov.trim() ? { rxOverloadDbm: Number(ov) } : {}),
  });
  return (
    <>
      <Section title={t("calc.optics.secTransceiver")}>
        <div className="field-row end">
          <Field label={t("calc.optics.tx")} type="number" value={tx} onChange={set("tx")} w="md" mono />
          <Field label={t("calc.optics.rx")} type="number" value={rx} onChange={set("rx")} w="md" mono />
          <Field label={t("calc.optics.overload")} type="number" value={ov} onChange={set("ov")} w="md" mono />
        </div>
      </Section>
      <Section title={t("calc.optics.secLink")}>
        <div className="field-row end">
          <Field label={t("calc.optics.km")} type="number" value={km} onChange={set("km")} w="sm" mono />
          <Select label={t("calc.optics.fiber")} value={fiber} onChange={set("fiber")} options={fibers(t)} w="lg" />
          <Field label={t("calc.optics.lossKm")} type="number" value={lpk} onChange={set("lpk")} w="md" mono />
        </div>
        <div className="field-row end">
          <Field label={t("calc.optics.connectors")} type="number" value={conn} onChange={set("conn")} w="sm" mono />
          <Field label={t("calc.optics.connLoss")} type="number" value={connLoss} onChange={set("connLoss")} w="md" mono />
          <Field label={t("calc.optics.splices")} type="number" value={splices} onChange={set("splices")} w="sm" mono />
          <Field label={t("calc.optics.spliceLoss")} type="number" value={spliceLoss} onChange={set("spliceLoss")} w="md" mono />
          <Field label={t("calc.optics.margin")} type="number" value={margin} onChange={set("margin")} w="md" mono />
        </div>
        <div className="actions"><button className="primary" disabled={!tx || !rx || !km || c.busy} aria-busy={c.busy} onClick={budget}>{t("calc.optics.btn")}{kbd}</button></div>
      </Section>
      <Section title={t("calc.optics.convHead")}>
        <Field label={t("calc.optics.power")} value={power} onChange={set("power")} w="md" mono />
        <div className="actions"><button disabled={!power || c.busy} onClick={() => c.run("optics", { convert: power })}>{t("calc.optics.convert")}</button></div>
      </Section>
      {c.view}
    </>
  );
}
