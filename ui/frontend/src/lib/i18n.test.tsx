import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider, LanguageSwitch, useT } from "./i18n";

function Probe() {
  const t = useT();
  return <p>{t("shell.coreStatus.connected")} · {t("patrol.deviceCount", { n: 3 })}</p>;
}

beforeEach(() => localStorage.clear());

test("arranca en el idioma del sistema (español en las pruebas) y sustituye variables", () => {
  render(<I18nProvider><Probe /></I18nProvider>);
  expect(screen.getByText("Núcleo conectado · 3 equipos")).toBeInTheDocument();
  expect(document.documentElement.lang).toBe("es");
});

test("cambiar a inglés traduce, actualiza lang y se recuerda", async () => {
  const { unmount } = render(<I18nProvider><LanguageSwitch /><Probe /></I18nProvider>);
  await userEvent.click(screen.getByRole("radio", { name: "English" }));
  expect(screen.getByText("Core connected · 3 devices")).toBeInTheDocument();
  expect(document.documentElement.lang).toBe("en");
  unmount();
  render(<I18nProvider><Probe /></I18nProvider>);
  expect(screen.getByText("Core connected · 3 devices")).toBeInTheDocument();
});

test("onLang recibe el idioma vigente al arrancar y cada vez que cambia", async () => {
  const onLang = vi.fn();
  render(<I18nProvider onLang={onLang}><LanguageSwitch /></I18nProvider>);
  expect(onLang).toHaveBeenLastCalledWith("es");
  await userEvent.click(screen.getByRole("radio", { name: "English" }));
  expect(onLang).toHaveBeenLastCalledWith("en");
  expect(onLang).toHaveBeenCalledTimes(2);
});

test("sin proveedor usa español", () => {
  render(<Probe />);
  expect(screen.getByText(/Núcleo conectado/)).toBeInTheDocument();
});

test("usa el singular cuando n es 1", () => {
  function One() {
    const t = useT();
    return <p>{t("patrol.deviceCount", { n: 1 })} · {t("syslog.count", { n: 1 })} · {t("syslog.count", { n: 0 })}</p>;
  }
  render(<One />);
  expect(screen.getByText("1 equipo · 1 mensaje · 0 mensajes")).toBeInTheDocument();
});

// Una severidad nueva del núcleo arma una clave que no existe: se muestra la clave, la app no queda en blanco.
function Missing() {
  const t = useT();
  return <p>{t("fleet.sev.desconocida" as Parameters<typeof t>[0])}</p>;
}

test("una clave inexistente se muestra tal cual en lugar de romper la vista", () => {
  render(<I18nProvider><Missing /></I18nProvider>);
  expect(screen.getByText("fleet.sev.desconocida")).toBeInTheDocument();
});
