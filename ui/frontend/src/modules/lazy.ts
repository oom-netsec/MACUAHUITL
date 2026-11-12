import { createElement as h, lazy, type ComponentType, type ReactNode } from "react";
import type { CoreAPI } from "../lib/core";

export type LazyViewFn = ((core: CoreAPI) => ReactNode) & { preload: () => Promise<void> };

// Vista de un módulo cargada bajo demanda (ADR 0009 §6): su código se descarga la primera vez que se abre.
// Una línea del manifiesto: lazyView(() => import("./x/XView"), "XView", { props fijas }).
// eslint no corre aquí; el any es por la forma variable de los módulos importados.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lazyView(load: () => Promise<Record<string, any>>, name: string, props: Record<string, unknown> = {}): LazyViewFn {
  const L = lazy(async () => ({ default: (await load())[name] as ComponentType<Record<string, unknown>> }));
  // Con el código ya descargado se monta el componente directo: sin Suspense no hay fallback, y React frena 300 ms la revelación del contenido que sustituye a un fallback.
  let loaded: ComponentType<Record<string, unknown>> | undefined;
  const preload = () => load().then((m) => { loaded = m[name]; });
  // El mismo elemento mientras el núcleo no cambie: así React no vuelve a renderizar las vistas montadas (ocultas) en cada cambio del shell.
  const els = new WeakMap<CoreAPI, ReactNode>();
  return Object.assign((core: CoreAPI) => {
    let el = els.get(core);
    if (!el) els.set(core, (el = h(loaded ?? L, { core, ...props })));
    return el;
  }, { preload });
}
