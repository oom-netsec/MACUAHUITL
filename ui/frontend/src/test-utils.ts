import { screen } from "@testing-library/react";
// El resaltado parte las líneas en <span>: getByText(regex) no las ve completas.
// termText compara el texto completo del <pre> o <li> de una terminal.
export const termText = (re: RegExp) => (_: string, el: Element | null) =>
  !!el && (el.tagName === "PRE" || el.tagName === "LI") && re.test(el.textContent ?? "");

// Las subvistas visitadas siguen montadas (hidden): el único campo con esa etiqueta que está a la vista (dos visibles es un error, como en getByLabelText).
export const shown = (label: string) => {
  const v = screen.getAllByLabelText(label).filter((e) => !e.closest("[hidden]"));
  if (v.length !== 1) throw new Error(`shown(${label}): ${v.length} campos visibles`);
  return v[0];
};

// Recorre la fibra de React desde un contenedor y dice si algún hook (estado, ref, memo) o prop guarda el marcador.
export function findFiberState(container: Element, marker: string): boolean {
  const key = Object.keys(container).find((k) => k.startsWith("__reactFiber$") || k.startsWith("__reactContainer$"));
  let root: any = key ? (container as any)[key] : null; // eslint-disable-line @typescript-eslint/no-explicit-any
  while (root?.return) root = root.return; // sube hasta la raíz
  if (root?.stateNode?.current) root = root.stateNode.current;
  const seen = new Map<unknown, number>(); // objeto -> profundidad mínima con que se exploró
  const has = (v: unknown, depth = 0): boolean => {
    if (typeof v === "string") return v.includes(marker);
    if (!v || typeof v !== "object" || typeof v === "function" || depth > 6 || (seen.get(v) ?? Infinity) <= depth || v instanceof Node || v instanceof Window) return false;
    seen.set(v, depth);
    return Object.values(v as object).some((x) => has(x, depth + 1));
  };
  const walk = (f: any): boolean => { // eslint-disable-line @typescript-eslint/no-explicit-any
    for (let n = f; n; n = n.sibling) {
      for (let h = n.memoizedState; h && typeof h === "object" && "next" in h; h = h.next) if (has(h.memoizedState) || has(h.queue?.lastRenderedState)) return true;
      if (n.memoizedState && !("next" in (n.memoizedState as object)) && has(n.memoizedState)) return true;
      if (n.tag !== 5 && has(n.memoizedProps)) return true;
      if (walk(n.child)) return true;
    }
    return false;
  };
  return walk(root);
}
