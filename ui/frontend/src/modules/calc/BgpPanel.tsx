import type { CoreAPI } from "../../lib/core";
import { Advanced } from "../../components/Advanced";
import { Check, Field, Select } from "../../components/Field";
import { Section } from "../../components/Page";
import { useT } from "../../lib/i18n";
import { useForm } from "../../lib/useForm";
import { kbd, num, useCalc } from "./shared";

interface RouteForm {
  key: number;
  name: string; weight: string; localPref: string; asPath: string; origin: string; med: string; igp: string; rid: string;
  originator: string; cluster: string; nbr: string; age: string; local: boolean; ebgp: boolean; unreachable: boolean;
}
let routeSeq = 0; // clave estable por ruta: al quitar una, el estado de su «Más atributos» no pasa a la siguiente
const newRoute = (i: number): RouteForm => ({
  key: ++routeSeq, name: String.fromCharCode(65 + (i % 26)), weight: "", localPref: "", asPath: "", origin: "i", med: "", igp: "", rid: "",
  originator: "", cluster: "", nbr: "", age: "", local: false, ebgp: false, unreachable: false,
});
const origins: [string, string][] = [["i", "IGP (i)"], ["e", "EGP (e)"], ["?", "incomplete (?)"]];

// Solo viajan los atributos escritos: los ausentes toman el valor por defecto del núcleo (local-pref 100, MED 0).
const toRoute = (r: RouteForm) => Object.fromEntries(Object.entries({
  name: r.name, weight: num(r.weight), localPref: num(r.localPref), locallyOriginated: r.local, asPath: r.asPath.trim(), origin: r.origin,
  med: num(r.med), ebgp: r.ebgp, igpMetric: num(r.igp), routerId: r.rid.trim(), originatorId: r.originator.trim(),
  clusterListLength: num(r.cluster), neighbor: r.nbr.trim(), ageSeconds: num(r.age), nextHopUnreachable: r.unreachable,
}).filter(([, v]) => v !== undefined && v !== "" && v !== false));

const blankRoute = newRoute(0);
const moreKeys: (keyof RouteForm)[] = ["igp", "cluster", "age", "rid", "originator", "nbr", "unreachable"];

interface BgpForm { routes: RouteForm[]; acm: boolean; dmed: boolean; relax: boolean; maxPaths: string }
const initial: BgpForm = { routes: [newRoute(0), newRoute(1)], acm: false, dmed: false, relax: false, maxPaths: "" };

export function BgpPanel({ core }: { core: CoreAPI }) {
  const t = useT();
  const [f, setForm] = useForm(initial);
  const { routes, acm, dmed, relax, maxPaths } = f;
  const setRoutes = setForm("routes");
  const c = useCalc(core);
  const set = (i: number, k: keyof RouteForm) => (v: string | boolean) => setRoutes(routes.map((r, j) => (j === i ? { ...r, [k]: v } : r)));
  return (
    <>
      <Section title={t("calc.bgp.secRoutes")} description={t("calc.bgp.hint")}>
        {routes.map((r, i) => (
          <fieldset key={r.key} className="box route">
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
            </div>
            <div className="route-flags">
              <Check label={t("calc.bgp.local")} checked={r.local} onChange={set(i, "local")} />
              <Check label="eBGP" checked={r.ebgp} onChange={set(i, "ebgp")} />
            </div>
            <Advanced label={t("calc.bgp.more")} changed={moreKeys.filter((k) => r[k] !== blankRoute[k]).length}>
            <div className="field-row end">
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
              <Check label={t("calc.bgp.unreachable")} checked={r.unreachable} onChange={set(i, "unreachable")} />
            </div>
            </Advanced>
            <div className="route-flags">
              <button className="quiet sm" disabled={routes.length <= 2} aria-label={t("calc.bgp.removeRoute", { n: i + 1 })} onClick={() => setRoutes(routes.filter((_, j) => j !== i))}>{t("calc.mtu.remove")}</button>
            </div>
          </fieldset>
        ))}
        <div className="actions"><button onClick={() => setRoutes([...routes, newRoute(routes.length)])}>{t("calc.bgp.addRoute")}</button></div>
      </Section>
      <div className="section">
        <Advanced label={t("calc.bgp.secOptions")} changed={[acm, dmed, relax, maxPaths !== ""].filter(Boolean).length}>
          <Check label={t("calc.bgp.acm")} checked={acm} onChange={setForm("acm")} />
          <Check label={t("calc.bgp.dmed")} checked={dmed} onChange={setForm("dmed")} />
          <Check label={t("calc.bgp.relax")} checked={relax} onChange={setForm("relax")} />
          <Field label={t("calc.bgp.maxPaths")} type="number" value={maxPaths} onChange={setForm("maxPaths")} w="md" mono />
        </Advanced>
        <div className="actions">
          <button className="primary" disabled={c.busy} aria-busy={c.busy} onClick={() => c.run("bgp", { routes: routes.map(toRoute), alwaysCompareMed: acm, deterministicMed: dmed, multipathRelax: relax, maximumPaths: Number(maxPaths) || 0 })}>
            {t("calc.bgp.btn")}{kbd}
          </button>
        </div>
      </div>
      {c.view}
    </>
  );
}
