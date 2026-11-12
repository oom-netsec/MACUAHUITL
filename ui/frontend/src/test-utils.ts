// El resaltado parte las líneas en <span>: getByText(regex) no las ve completas.
// termText compara el texto completo del <pre> o <li> de una terminal.
export const termText = (re: RegExp) => (_: string, el: Element | null) =>
  !!el && (el.tagName === "PRE" || el.tagName === "LI") && re.test(el.textContent ?? "");
