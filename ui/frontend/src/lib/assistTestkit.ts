// Ayudas de pruebas del modo asistido (ADR 0009 §5): los botones dicen qué hacen y "Aplicar" se habilita tras un momento.
import { waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

export const START = /^Iniciar el cambio en/;
export const confirmStep = (id: string) => new RegExp(`\\(${id}\\)$`);

export async function clickWhenReady(btn: HTMLElement) {
  await waitFor(() => expect(btn).toBeEnabled(), { timeout: 3000 });
  await userEvent.click(btn);
}

// Una línea de configuración del plan o del paso: va resaltada y con su marca (+ o ↺), así que se compara el texto completo.
export const lineText = (text: string) => (_: string, el: Element | null) =>
  el?.tagName === "DIV" && (el.textContent ?? "").replace(/^[+↺] /, "") === text;
