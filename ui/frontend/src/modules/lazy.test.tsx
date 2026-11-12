import { Suspense } from "react";
import { render, screen } from "@testing-library/react";
import { lazyView } from "./lazy";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";

test("lazyView no importa el módulo hasta que se muestra, y le pasa el núcleo y sus props", async () => {
  const load = vi.fn(async () => ({ Vista: ({ core, tool }: { core: CoreAPI; tool: string }) => <p>{tool} {typeof core.coreStatus}</p> }));
  const view = lazyView(load, "Vista", { tool: "ping" });
  expect(load).not.toHaveBeenCalled();
  render(<Suspense fallback={<p>cargando</p>}>{view(fakeCore())}</Suspense>);
  expect(await screen.findByText("ping function")).toBeInTheDocument();
  expect(load).toHaveBeenCalledTimes(1);
});

test("lazyView devuelve el mismo elemento por núcleo (el shell no re-renderiza las vistas montadas)", () => {
  const view = lazyView(async () => ({ Vista: () => null }), "Vista");
  const core = fakeCore();
  expect(view(core)).toBe(view(core));
  expect(view(fakeCore())).not.toBe(view(core));
});

test("preload descarga el código y la vista se monta sin pasar por el fallback", async () => {
  const view = lazyView(async () => ({ Vista: () => <p>lista</p> }), "Vista");
  await view.preload();
  render(<Suspense fallback={<p>cargando</p>}>{view(fakeCore())}</Suspense>);
  expect(screen.getByText("lista")).toBeInTheDocument(); // síncrono: ni un tick de fallback
});
