import type { CoreAPI } from "../../lib/core";
import { RunButton } from "../../components/RunButton";
import { Advanced } from "../../components/Advanced";
import { Field } from "../../components/Field";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";
import { useCalc } from "./shared";

interface TcpForm { bw: string; rtt: string; win: string; loss: string; mss: string }
const initial: TcpForm = { bw: "", rtt: "", win: "", loss: "", mss: "" };

export function TcpPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, set] = useForm(initial);
  const { bw, rtt, win, loss, mss } = f;
  const c = useCalc(core);
  return (
    <>
      <div className="field-row end">
        <Field label={t("calc.tcp.bw")} value={bw} onChange={set("bw")} w="md" mono />
        <Field label="RTT (ms)" type="number" value={rtt} onChange={set("rtt")} w="sm" mono />
      </div>
      <Advanced changed={(["win", "loss", "mss"] as const).filter((k) => f[k] !== initial[k]).length}>
      <div className="field-row end">
        <Field label={t("calc.tcp.win")} value={win} onChange={set("win")} w="md" mono />
        <Field label={t("calc.tcp.loss")} type="number" value={loss} onChange={set("loss")} w="sm" mono />
        <Field label={t("calc.tcp.mss")} type="number" value={mss} onChange={set("mss")} w="sm" mono />
      </div>
      </Advanced>
      <div className="actions">
        <RunButton primary kbd busy={c.busy} missing={[!bw && t("need.bandwidth"), !rtt && t("need.rtt")]}
          onClick={() => c.run("tcp", { bandwidth: bw, rttMs: Number(rtt), window: win, lossPercent: Number(loss) || 0, mss: Number(mss) || 0 })}>{t("calc.tcp.btn")}</RunButton>
      </div>
      {c.view}
    </>
  );
}
