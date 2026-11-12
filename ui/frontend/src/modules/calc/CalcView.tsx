import { useState } from "react";
import { CopyButton } from "../../components/Data";
import { Bars } from "./CalcBars";
import type { CalcResult, CoreAPI } from "../../lib/core";
import { Check, Field, Select } from "../../components/Field";
import { EmptyState, Page, ResultPanel, Section, Tabs, useResult } from "../../components/Page";
import { useT } from "../../lib/i18n";
import "./calc.css";

const subs = ["subnet", "vlsm", "summarize", "wildcard", "ipv6", "mtu", "tcp", "dscp", "optics", "bgp"] as const;
type Sub = (typeof subs)[number];

const words = (s: string) => s.split(/[\s,;]+/).filter(Boolean);
const num = (s: string) => (s.trim() === "" ? undefined : Number(s));
const kbd = <kbd aria-hidden="true">Ctrl ↵</kbd>;

// Dirección, máscara, wildcard o prefijo con dirección: se puede copiar con un clic.
const ADDR = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-f]*:[0-9a-f:]*:[0-9a-f:.]*)(\/\d{1,3})?$/i;

// Tablas y notas del núcleo dentro de un panel de resultado, con las barras de reparto de Subred y VLSM.
function ResultView({ r, kind }: { r: CalcResult; kind: string }) {
  return (
    <>
      <Bars kind={kind} r={r} />
      {r.tables.map((t, i) => (
        <div key={i} className="table-wrap flat" role="region" aria-label={t.title} tabIndex={0}>
          <table>
            <caption>{t.title}</caption>
            <thead><tr>{t.head.map((h) => <th key={h} scope="col">{h}</th>)}</tr></thead>
            <tbody>{t.rows.map((row, j) => (
              <tr key={j}>{row.map((c, k) => (
                <td key={k} className={k > 0 ? "mono" : undefined}>
                  {c}{k > 0 && ADDR.test(c) && <CopyButton value={c} label={t.head[0] === "Campo" ? row[0] : t.head[k]} />}
                </td>
              ))}</tr>
            ))}</tbody>
          </table>
        </div>
      ))}
      {r.notes.length > 0 && <div className="panel-body"><ul className="notes">{r.notes.map((n, i) => <li key={i}>{n}</li>)}</ul></div>}
    </>
  );
}

// Pide un cálculo al núcleo; `view` es el panel de resultado, o qué hacer primero si todavía no hay uno.
function useCalc(core: CoreAPI) {
  const t = useT();
  const r = useResult<CalcResult>();
  const [kind, setKind] = useState("");
  const run = (k: string, req: object) => { setKind(k); return r.run(() => core.calc(k, req)); };
  const view = (
    <div aria-live="polite">
      {!r.data && !r.error && !r.busy && <EmptyState icon="tools" title={t("calc.empty.title")}>{t("calc.empty")}</EmptyState>}
      {(r.data || r.error) && <ResultPanel title={t("calc.result")} error={r.error}>{r.data && <ResultView r={r.data} kind={kind} />}</ResultPanel>}
    </div>
  );
  return { run, busy: r.busy, view };
}

function SubnetPanel({ core }: { core: CoreAPI }) {
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

function VlsmPanel({ core }: { core: CoreAPI }) {
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
      <div className="actions"><button className="primary" disabled={!network || parsed.length === 0 || c.busy} aria-busy={c.busy} onClick={() => c.run("vlsm", { network, needs: parsed })}>{t("calc.vlsm.btn")}{kbd}</button></div>
      {c.view}
    </>
  );
}

function SummarizePanel({ core }: { core: CoreAPI }) {
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

function WildcardPanel({ core }: { core: CoreAPI }) {
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

function Ipv6Panel({ core }: { core: CoreAPI }) {
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

const layerKinds = (t: ReturnType<typeof useT>): [string, string][] => [
  ["gre", "GRE (24)"], ["gre-key", t("calc.layer.greKey")], ["esp-tunnel", t("calc.layer.espTunnel")], ["esp-transport", t("calc.layer.espTransport")],
  ["getvpn", "GETVPN"], ["nat-t", "NAT-T (8)"], ["vxlan", "VXLAN (50)"], ["mpls", "MPLS"], ["dot1q", "802.1Q (4)"], ["qinq", "QinQ (8)"],
  ["pppoe", "PPPoE (8)"], ["lisp", "LISP (36)"],
];
const ciphers: [string, string][] = [["aes-cbc", "AES-CBC"], ["aes-gcm", "AES-GCM"], ["3des", "3DES"], ["des", "DES"]];
const auths: [string, string][] = [["sha1", "HMAC-SHA1-96"], ["sha256", "HMAC-SHA256-128"], ["sha384", "HMAC-SHA384-192"], ["sha512", "HMAC-SHA512-256"], ["md5", "HMAC-MD5-96"]];

function MtuPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [physical, setPhysical] = useState("1500");
  const [layers, setLayers] = useState<string[]>([]);
  const [kind, setKind] = useState("gre");
  const [cipher, setCipher] = useState("aes-cbc");
  const [auth, setAuth] = useState("sha256");
  const [tbar, setTbar] = useState(false);
  const [labels, setLabels] = useState("1");
  const [inner6, setInner6] = useState(false);
  const c = useCalc(core);
  const esp = kind.startsWith("esp-") || kind === "getvpn";
  const layer = esp ? [kind, cipher, ...(cipher === "aes-gcm" ? [] : [auth]), ...(kind === "getvpn" && tbar ? ["tbar"] : [])].join(":")
    : kind === "mpls" ? `mpls:${labels}` : kind;
  return (
    <>
      <Field label={t("calc.mtu.physical")} type="number" value={physical} onChange={setPhysical} w="sm" mono />
      <Section title={t("calc.mtu.encap")}>
        <div className="field-row end">
          <Select label={t("calc.mtu.layer")} value={kind} onChange={setKind} options={layerKinds(t)} w="md" />
          {esp && <Select label={t("calc.mtu.cipher")} value={cipher} onChange={setCipher} options={ciphers} w="md" />}
          {esp && cipher !== "aes-gcm" && <Select label={t("calc.mtu.auth")} value={auth} onChange={setAuth} options={auths} w="md" />}
          {kind === "mpls" && <Field label={t("calc.mtu.labels")} type="number" value={labels} onChange={setLabels} w="xs" mono />}
        </div>
        {kind === "getvpn" && <Check label={t("calc.mtu.tbar")} checked={tbar} onChange={setTbar} />}
        <div className="actions"><button onClick={() => setLayers([...layers, layer])}>{t("calc.mtu.addLayer")}</button></div>
        {layers.length > 0 && (
          <ol className="layers" aria-label={t("calc.mtu.stack")}>
            {layers.map((l, i) => (
              <li key={i}><code>{l}</code> <button className="quiet sm" aria-label={t("calc.mtu.removeLayer", { l })} onClick={() => setLayers(layers.filter((_, j) => j !== i))}>{t("calc.mtu.remove")}</button></li>
            ))}
          </ol>
        )}
      </Section>
      <Check label={t("calc.mtu.inner6")} checked={inner6} onChange={setInner6} />
      <div className="actions">
        <button className="primary" disabled={layers.length === 0 || c.busy} aria-busy={c.busy} onClick={() => c.run("mtu", { physical: Number(physical) || 0, layers, innerIpv6: inner6 })}>{t("calc.mtu.btn")}{kbd}</button>
      </div>
      {c.view}
    </>
  );
}

function TcpPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [bw, setBw] = useState("");
  const [rtt, setRtt] = useState("");
  const [win, setWin] = useState("");
  const [loss, setLoss] = useState("");
  const [mss, setMss] = useState("");
  const c = useCalc(core);
  return (
    <>
      <div className="field-row end">
        <Field label={t("calc.tcp.bw")} value={bw} onChange={setBw} w="md" mono />
        <Field label="RTT (ms)" type="number" value={rtt} onChange={setRtt} w="sm" mono />
        <Field label={t("calc.tcp.win")} value={win} onChange={setWin} w="md" mono />
      </div>
      <div className="field-row end">
        <Field label={t("calc.tcp.loss")} type="number" value={loss} onChange={setLoss} w="sm" mono />
        <Field label={t("calc.tcp.mss")} type="number" value={mss} onChange={setMss} w="sm" mono />
      </div>
      <div className="actions">
        <button className="primary" disabled={!bw || !rtt || c.busy} aria-busy={c.busy}
          onClick={() => c.run("tcp", { bandwidth: bw, rttMs: Number(rtt), window: win, lossPercent: Number(loss) || 0, mss: Number(mss) || 0 })}>{t("calc.tcp.btn")}{kbd}</button>
      </div>
      {c.view}
    </>
  );
}

const dscpFields = (t: ReturnType<typeof useT>): [string, string][] => [
  ["", t("calc.dscp.auto")], ["name", t("calc.dscp.name")], ["dscp", "DSCP"], ["binary", t("calc.dscp.binary")], ["tos", "ToS"],
  ["precedence", t("calc.dscp.precedence")], ["cos", "CoS"], ["exp", "MPLS EXP"],
];

function DscpPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [query, setQuery] = useState("");
  const [field, setField] = useState("");
  const c = useCalc(core);
  return (
    <>
      <div className="field-row end">
        <Field label={t("calc.dscp.query")} value={query} onChange={setQuery} w="lg" mono />
        <Select label={t("calc.dscp.field")} value={field} onChange={setField} options={dscpFields(t)} w="md" />
      </div>
      <div className="actions"><button className="primary" disabled={c.busy} aria-busy={c.busy} onClick={() => c.run("dscp", { query, field })}>{t("calc.dscp.btn")}{kbd}</button></div>
      {c.view}
    </>
  );
}

const fibers = (t: ReturnType<typeof useT>): [string, string][] => [["smf-1310", t("calc.fiber.smf1310")], ["smf-1550", t("calc.fiber.smf1550")], ["mmf-850", t("calc.fiber.mmf850")], ["mmf-1300", t("calc.fiber.mmf1300")]];

function OpticsPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [tx, setTx] = useState("");
  const [rx, setRx] = useState("");
  const [ov, setOv] = useState("");
  const [km, setKm] = useState("");
  const [fiber, setFiber] = useState("smf-1310");
  const [lpk, setLpk] = useState("");
  const [conn, setConn] = useState("2");
  const [connLoss, setConnLoss] = useState("0.5");
  const [splices, setSplices] = useState("0");
  const [spliceLoss, setSpliceLoss] = useState("0.1");
  const [margin, setMargin] = useState("3");
  const [power, setPower] = useState("");
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
          <Field label={t("calc.optics.tx")} type="number" value={tx} onChange={setTx} w="md" mono />
          <Field label={t("calc.optics.rx")} type="number" value={rx} onChange={setRx} w="md" mono />
          <Field label={t("calc.optics.overload")} type="number" value={ov} onChange={setOv} w="md" mono />
        </div>
      </Section>
      <Section title={t("calc.optics.secLink")}>
        <div className="field-row end">
          <Field label={t("calc.optics.km")} type="number" value={km} onChange={setKm} w="sm" mono />
          <Select label={t("calc.optics.fiber")} value={fiber} onChange={setFiber} options={fibers(t)} w="lg" />
          <Field label={t("calc.optics.lossKm")} type="number" value={lpk} onChange={setLpk} w="md" mono />
        </div>
        <div className="field-row end">
          <Field label={t("calc.optics.connectors")} type="number" value={conn} onChange={setConn} w="sm" mono />
          <Field label={t("calc.optics.connLoss")} type="number" value={connLoss} onChange={setConnLoss} w="md" mono />
          <Field label={t("calc.optics.splices")} type="number" value={splices} onChange={setSplices} w="sm" mono />
          <Field label={t("calc.optics.spliceLoss")} type="number" value={spliceLoss} onChange={setSpliceLoss} w="md" mono />
          <Field label={t("calc.optics.margin")} type="number" value={margin} onChange={setMargin} w="md" mono />
        </div>
        <div className="actions"><button className="primary" disabled={!tx || !rx || !km || c.busy} aria-busy={c.busy} onClick={budget}>{t("calc.optics.btn")}{kbd}</button></div>
      </Section>
      <Section title={t("calc.optics.convHead")}>
        <Field label={t("calc.optics.power")} value={power} onChange={setPower} w="md" mono />
        <div className="actions"><button disabled={!power || c.busy} onClick={() => c.run("optics", { convert: power })}>{t("calc.optics.convert")}</button></div>
      </Section>
      {c.view}
    </>
  );
}

interface RouteForm {
  name: string; weight: string; localPref: string; asPath: string; origin: string; med: string; igp: string; rid: string;
  originator: string; cluster: string; nbr: string; age: string; local: boolean; ebgp: boolean; unreachable: boolean;
}
const newRoute = (i: number): RouteForm => ({
  name: String.fromCharCode(65 + (i % 26)), weight: "", localPref: "", asPath: "", origin: "i", med: "", igp: "", rid: "",
  originator: "", cluster: "", nbr: "", age: "", local: false, ebgp: false, unreachable: false,
});
const origins: [string, string][] = [["i", "IGP (i)"], ["e", "EGP (e)"], ["?", "incomplete (?)"]];

// Solo viajan los atributos escritos: los ausentes toman el valor por defecto del núcleo (local-pref 100, MED 0).
const toRoute = (r: RouteForm) => Object.fromEntries(Object.entries({
  name: r.name, weight: num(r.weight), localPref: num(r.localPref), locallyOriginated: r.local, asPath: r.asPath.trim(), origin: r.origin,
  med: num(r.med), ebgp: r.ebgp, igpMetric: num(r.igp), routerId: r.rid.trim(), originatorId: r.originator.trim(),
  clusterListLength: num(r.cluster), neighbor: r.nbr.trim(), ageSeconds: num(r.age), nextHopUnreachable: r.unreachable,
}).filter(([, v]) => v !== undefined && v !== "" && v !== false));

function BgpPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [routes, setRoutes] = useState<RouteForm[]>([newRoute(0), newRoute(1)]);
  const [acm, setAcm] = useState(false);
  const [dmed, setDmed] = useState(false);
  const [relax, setRelax] = useState(false);
  const [maxPaths, setMaxPaths] = useState("");
  const c = useCalc(core);
  const set = (i: number, k: keyof RouteForm) => (v: string | boolean) => setRoutes(routes.map((r, j) => (j === i ? { ...r, [k]: v } : r)));
  return (
    <>
      <Section title={t("calc.bgp.secRoutes")} description={t("calc.bgp.hint")}>
        {routes.map((r, i) => (
          <fieldset key={i} className="box route">
            <legend>{t("calc.bgp.route", { n: i + 1 })}</legend>
            <div className="field-row end">
              <Field label={t("calc.bgp.name")} value={r.name} onChange={set(i, "name")} w="xs" />
              <Field label={t("calc.bgp.weight")} type="number" value={r.weight} onChange={set(i, "weight")} w="md" mono />
              <Field label="Local-pref" type="number" value={r.localPref} onChange={set(i, "localPref")} w="sm" mono />
              <Field label="MED" type="number" value={r.med} onChange={set(i, "med")} w="sm" mono />
              <Select label="Origin" value={r.origin} onChange={set(i, "origin")} options={origins} w="sm" />
            </div>
            <div className="field-row end">
              <Field label="AS_PATH" value={r.asPath} onChange={set(i, "asPath")} w="md" mono />
              <Field label={t("calc.bgp.igp")} type="number" value={r.igp} onChange={set(i, "igp")} w="sm" mono />
              <Field label={t("calc.bgp.cluster")} type="number" value={r.cluster} onChange={set(i, "cluster")} w="sm" mono />
              <Field label={t("calc.bgp.age")} type="number" value={r.age} onChange={set(i, "age")} w="xs" mono />
            </div>
            <div className="field-row end">
              <Field label="Router-ID" value={r.rid} onChange={set(i, "rid")} w="md" mono />
              <Field label="Originator-ID" value={r.originator} onChange={set(i, "originator")} w="md" mono />
              <Field label={t("calc.bgp.neighbor")} value={r.nbr} onChange={set(i, "nbr")} w="md" mono />
            </div>
            <div className="route-flags">
              <Check label={t("calc.bgp.local")} checked={r.local} onChange={set(i, "local")} />
              <Check label="eBGP" checked={r.ebgp} onChange={set(i, "ebgp")} />
              <Check label={t("calc.bgp.unreachable")} checked={r.unreachable} onChange={set(i, "unreachable")} />
              <button className="quiet sm" disabled={routes.length <= 2} aria-label={t("calc.bgp.removeRoute", { n: i + 1 })} onClick={() => setRoutes(routes.filter((_, j) => j !== i))}>{t("calc.mtu.remove")}</button>
            </div>
          </fieldset>
        ))}
        <div className="actions"><button onClick={() => setRoutes([...routes, newRoute(routes.length)])}>{t("calc.bgp.addRoute")}</button></div>
      </Section>
      <Section title={t("calc.bgp.secOptions")}>
        <Check label={t("calc.bgp.acm")} checked={acm} onChange={setAcm} />
        <Check label={t("calc.bgp.dmed")} checked={dmed} onChange={setDmed} />
        <Check label={t("calc.bgp.relax")} checked={relax} onChange={setRelax} />
        <Field label={t("calc.bgp.maxPaths")} type="number" value={maxPaths} onChange={setMaxPaths} w="md" mono />
        <div className="actions">
          <button className="primary" disabled={c.busy} aria-busy={c.busy} onClick={() => c.run("bgp", { routes: routes.map(toRoute), alwaysCompareMed: acm, deterministicMed: dmed, multipathRelax: relax, maximumPaths: Number(maxPaths) || 0 })}>
            {t("calc.bgp.btn")}{kbd}
          </button>
        </div>
      </Section>
      {c.view}
    </>
  );
}

export function CalcView({ core }: { core: CoreAPI }) {
  const t = useT();
  const [sub, setSub] = useState<Sub>("subnet");
  return (
    <Page title={t("calc.title")} description={t("calc.desc")}
      tabs={<Tabs label={t("calc.nav")} value={sub} onChange={setSub} tabs={subs.map((s) => [s, t(`calc.sub.${s}`)] as [Sub, string])} />}>
      {sub === "subnet" && <SubnetPanel core={core} />}
      {sub === "vlsm" && <VlsmPanel core={core} />}
      {sub === "summarize" && <SummarizePanel core={core} />}
      {sub === "wildcard" && <WildcardPanel core={core} />}
      {sub === "ipv6" && <Ipv6Panel core={core} />}
      {sub === "mtu" && <MtuPanel core={core} />}
      {sub === "tcp" && <TcpPanel core={core} />}
      {sub === "dscp" && <DscpPanel core={core} />}
      {sub === "optics" && <OpticsPanel core={core} />}
      {sub === "bgp" && <BgpPanel core={core} />}
    </Page>
  );
}
