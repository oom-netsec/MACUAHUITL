// TimeChart bajo demanda: uPlot se descarga la primera vez que una vista muestra una gráfica.
import { Suspense, lazy } from "react";
import type { TimeChartProps } from "./TimeChart";

const Chart = lazy(() => import("./TimeChart"));

export function LazyTimeChart(p: TimeChartProps) {
  return <Suspense fallback={<div className="skeleton chart-skeleton" aria-hidden="true"><i /><i /><i /></div>}><Chart {...p} /></Suspense>;
}
