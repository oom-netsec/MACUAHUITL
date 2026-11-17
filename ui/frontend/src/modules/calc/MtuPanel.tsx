import type { CoreAPI } from "../../lib/core";
import { Check, Field, Select } from "../../components/Field";
import { Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { useForm } from "./form";
import { kbd, useCalc } from "./shared";

const layerKinds = (t: ReturnType<typeof useT>): [string, string][] => [
  ["gre", "GRE (24)"], ["gre-key", t("calc.layer.greKey")], ["esp-tunnel", t("calc.layer.espTunnel")], ["esp-transport", t("calc.layer.espTransport")],
  ["getvpn", "GETVPN"], ["nat-t", "NAT-T (8)"], ["vxlan", "VXLAN (50)"], ["mpls", "MPLS"], ["dot1q", "802.1Q (4)"], ["qinq", "QinQ (8)"],
  ["pppoe", "PPPoE (8)"], ["lisp", "LISP (36)"],
];
const ciphers: [string, string][] = [["aes-cbc", "AES-CBC"], ["aes-gcm", "AES-GCM"], ["3des", "3DES"], ["des", "DES"]];
const auths: [string, string][] = [["sha1", "HMAC-SHA1-96"], ["sha256", "HMAC-SHA256-128"], ["sha384", "HMAC-SHA384-192"], ["sha512", "HMAC-SHA512-256"], ["md5", "HMAC-MD5-96"]];

interface MtuForm { physical: string; layers: string[]; kind: string; cipher: string; auth: string; tbar: boolean; labels: string; inner6: boolean }
const initial: MtuForm = { physical: "1500", layers: [], kind: "gre", cipher: "aes-cbc", auth: "sha256", tbar: false, labels: "1", inner6: false };

export function MtuPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, set] = useForm(initial);
  const { physical, layers, kind, cipher, auth, tbar, labels, inner6 } = f;
  const c = useCalc(core);
  const esp = kind.startsWith("esp-") || kind === "getvpn";
  const layer = esp ? [kind, cipher, ...(cipher === "aes-gcm" ? [] : [auth]), ...(kind === "getvpn" && tbar ? ["tbar"] : [])].join(":")
    : kind === "mpls" ? `mpls:${labels}` : kind;
  return (
    <>
      <Field label={t("calc.mtu.physical")} type="number" value={physical} onChange={set("physical")} w="sm" mono />
      <Section title={t("calc.mtu.encap")}>
        <div className="field-row end">
          <Select label={t("calc.mtu.layer")} value={kind} onChange={set("kind")} options={layerKinds(t)} w="md" />
          {esp && <Select label={t("calc.mtu.cipher")} value={cipher} onChange={set("cipher")} options={ciphers} w="md" />}
          {esp && cipher !== "aes-gcm" && <Select label={t("calc.mtu.auth")} value={auth} onChange={set("auth")} options={auths} w="md" />}
          {kind === "mpls" && <Field label={t("calc.mtu.labels")} type="number" value={labels} onChange={set("labels")} w="xs" mono />}
        </div>
        {kind === "getvpn" && <Check label={t("calc.mtu.tbar")} checked={tbar} onChange={set("tbar")} />}
        <div className="actions"><button onClick={() => set("layers")([...layers, layer])}>{t("calc.mtu.addLayer")}</button></div>
        {layers.length > 0 && (
          <ol className="layers" aria-label={t("calc.mtu.stack")}>
            {layers.map((l, i) => (
              <li key={i}><code>{l}</code> <button className="quiet sm" aria-label={t("calc.mtu.removeLayer", { l })} onClick={() => set("layers")(layers.filter((_, j) => j !== i))}>{t("calc.mtu.remove")}</button></li>
            ))}
          </ol>
        )}
      </Section>
      <Check label={t("calc.mtu.inner6")} checked={inner6} onChange={set("inner6")} />
      <div className="actions">
        <button className="primary" disabled={layers.length === 0 || c.busy} aria-busy={c.busy} onClick={() => c.run("mtu", { physical: Number(physical) || 0, layers, innerIpv6: inner6 })}>{t("calc.mtu.btn")}{kbd}</button>
      </div>
      {c.view}
    </>
  );
}
