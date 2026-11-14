import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { I18nProvider, LanguageSwitch, langStorageKey, setFallbackLangForTests, tr, useCoreLang, useT } from "./i18n";

function Probe() {
  const t = useT();
  return <p>{t("shell.coreStatus.connected")} · {t("patrol.deviceCount", { n: 3 })}</p>;
}

// El setup de las pruebas deja el español elegido; aquí se quita la clave para ver el valor por omisión.
beforeEach(() => localStorage.removeItem(langStorageKey));

test("sin nada guardado arranca en inglés (el canónico), aunque el sistema esté en español, y sustituye variables", () => {
  vi.spyOn(navigator, "language", "get").mockReturnValue("es-MX");
  render(<I18nProvider><Probe /></I18nProvider>);
  expect(screen.getByText("Core connected · 3 devices")).toBeInTheDocument();
  expect(document.documentElement.lang).toBe("en");
  expect(localStorage.getItem(langStorageKey)).toBeNull(); // lo autodetectado no se guarda
  expect(tr("shell.coreStatus.connected")).toBe("Core connected");
});

test("la elección explícita de español se guarda en la clave nueva y se recuerda", async () => {
  const { unmount } = render(<I18nProvider><LanguageSwitch /><Probe /></I18nProvider>);
  await userEvent.click(screen.getByRole("radio", { name: "Español" }));
  expect(screen.getByText("Núcleo conectado · 3 equipos")).toBeInTheDocument();
  expect(document.documentElement.lang).toBe("es");
  expect(localStorage.getItem(langStorageKey)).toBe("es");
  unmount();
  render(<I18nProvider><Probe /></I18nProvider>);
  expect(screen.getByText("Núcleo conectado · 3 equipos")).toBeInTheDocument();
});

test("la clave vieja (macuahuitl.idioma) se ignora", () => {
  localStorage.setItem("macuahuitl.idioma", "es");
  render(<I18nProvider><Probe /></I18nProvider>);
  expect(screen.getByText("Core connected · 3 devices")).toBeInTheDocument();
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
  expect(onLang).toHaveBeenLastCalledWith("en");
  await userEvent.click(screen.getByRole("radio", { name: "Español" }));
  expect(onLang).toHaveBeenLastCalledWith("es");
  expect(onLang).toHaveBeenCalledTimes(2);
});

// Lo que pide el idioma al núcleo (nombres de playbooks) espera a que el núcleo lo tenga: dos llamadas de Wails no llegan en orden.
test("useCoreLang cambia cuando el núcleo confirmó el idioma, no antes", async () => {
  let done = () => {};
  const onLang = vi.fn(() => new Promise<void>((r) => { done = r; }));
  function Core() { return <output>{useCoreLang() ?? "-"}</output>; }
  render(<I18nProvider onLang={onLang}><LanguageSwitch /><Core /></I18nProvider>);
  await act(async () => done());
  expect(screen.getByRole("status")).toHaveTextContent("en");
  await userEvent.click(screen.getByRole("radio", { name: "Español" }));
  expect(screen.getByRole("status")).toHaveTextContent("en");
  await act(async () => done());
  expect(screen.getByRole("status")).toHaveTextContent("es");
});

test("sin proveedor usa inglés", () => {
  setFallbackLangForTests("en"); // el setup de las pruebas lo deja en español
  render(<Probe />);
  expect(screen.getByText(/Core connected/)).toBeInTheDocument();
});

test("usa el singular cuando n es 1", () => {
  function One() {
    const t = useT();
    return <p>{t("patrol.deviceCount", { n: 1 })} · {t("syslog.count", { n: 1 })} · {t("syslog.count", { n: 0 })}</p>;
  }
  render(<I18nProvider><One /></I18nProvider>);
  expect(screen.getByText("1 device · 1 message · 0 messages")).toBeInTheDocument();
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
