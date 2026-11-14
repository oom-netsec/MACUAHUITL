import { render, screen } from "@testing-library/react";
import { PlanView } from "./AssistRun";
import { I18nProvider } from "../lib/i18n";

test("el plan marca los caracteres invisibles de una línea (p. ej. de un respaldo restaurado)", () => {
  render(
    <I18nProvider>
      <PlanView r={{ planId: "p1", plan: { function: "restore", devices: [{ device: "sw1", pre: [], apply: ["description a‮b"], rollback: [], post: [] }] } }} />
    </I18nProvider>,
  );
  expect(screen.getByText(/U\+202E/)).toBeInTheDocument();
});
