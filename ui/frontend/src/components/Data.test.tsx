import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CoreContext } from "../app/activity";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";
import { CopyButton, Duration, RelativeTime, SeverityBadge, StatusPill, formatDateTime, formatDuration } from "./Data";
import { Meter, Sparkline } from "./charts/Mini";

const withCore = (core: CoreAPI, ui: React.ReactNode) => render(<CoreContext.Provider value={core}>{ui}</CoreContext.Provider>);

test("CopyButton copia el valor, confirma sin moverse y su nombre dice qué copia", async () => {
  const core = fakeCore();
  withCore(core as unknown as CoreAPI, <CopyButton value="10.0.0.1" label="IP" />);
  const b = screen.getByRole("button", { name: "Copiar IP" });
  await userEvent.click(b);
  expect(core.copyText).toHaveBeenCalledWith("10.0.0.1");
  expect(screen.getByRole("status")).toHaveTextContent("Copiado");
  expect(screen.getByRole("button", { name: "Copiar IP" })).toBe(b);
});

test("RelativeTime dice hace cuánto y deja la hora exacta en el título", () => {
  const at = new Date(Date.now() - 3 * 60_000).toISOString();
  render(<RelativeTime iso={at} />);
  const el = screen.getByText(/hace 3 minutos/);
  expect(el.tagName).toBe("TIME");
  expect(el).toHaveAttribute("dateTime", at);
  expect(el).toHaveAttribute("title");
});

test("Duration y formatDuration resumen de forma legible", () => {
  expect(formatDuration(850)).toBe("850 ms");
  expect(formatDuration(42_000)).toBe("42 s");
  expect(formatDuration(5 * 60_000 + 3_000)).toBe("5 min 3 s");
  expect(formatDuration(2 * 3_600_000 + 15 * 60_000)).toBe("2 h 15 min");
  render(<Duration ms={42_000} />);
  expect(screen.getByText("42 s")).toBeInTheDocument();
});

test("StatusPill y SeverityBadge llevan texto, no solo color", () => {
  render(<><StatusPill tone="bad" label="Caído" /><SeverityBadge sev={2} /><SeverityBadge sev={6} /></>);
  expect(screen.getByText("Caído")).toBeInTheDocument();
  expect(screen.getByText("2 · Crítico")).toBeInTheDocument();
  expect(screen.getByText("6 · Informativo")).toBeInTheDocument();
});

test("Sparkline y Meter tienen una descripción en texto", () => {
  render(<><Sparkline values={[1, 5, 3, 9]} label="CPU" unit="%" /><Meter value={82} max={100} warn={70} crit={90} label="Memoria" unit="%" /></>);
  expect(screen.getByRole("img", { name: "CPU: mín 1 %, máx 9 %, último 9 %" })).toBeInTheDocument();
  const m = screen.getByRole("meter", { name: "Memoria" });
  expect(m).toHaveAttribute("aria-valuenow", "82");
  expect(m).toHaveAttribute("data-level", "warn");
});

test("formatDateTime muestra fecha y hora locales con segundos y deja pasar lo que no es fecha", () => {
  const iso = "2026-11-08T16:31:28.990Z";
  const out = formatDateTime(iso, "es");
  expect(out).not.toContain("T16");
  expect(out).not.toContain(".990");
  expect(out).toMatch(/\d{2}:\d{2}:\d{2}/);
  expect(formatDateTime("no es fecha", "es")).toBe("no es fecha");
});
