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
