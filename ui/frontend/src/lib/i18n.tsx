import { createContext, useContext, useLayoutEffect, useState, type ReactNode } from "react";
import { Segmented } from "../components/Segmented";
import { es, type Key } from "./i18n/es";
import { en } from "./i18n/en";

// Textos de la interfaz en español e inglés. Los mensajes que vienen del núcleo no se traducen.
export type Lang = "es" | "en";
const dicts: Record<Lang, Record<Key, string>> = { es, en };
// Clave nueva: la anterior (macuahuitl.lang) guardaba también el idioma autodetectado y no se puede distinguir de una
// elección explícita, así que se ignora; solo se guarda lo que el usuario elige en Ajustes. Inglés es el canónico.
export const langStorageKey = "macuahuitl.lang";

type T = (key: Key, vars?: Record<string, string | number>) => string;
// Con n = 1 se usa la variante "<clave>.one" si existe ("1 equipo", no "1 equipos").
const make = (lang: Lang): T => (key, vars) => {
  const d = dicts[lang] as Record<string, string>;
  const text = (vars?.n === 1 && d[`${key}.one`]) || d[key] || key; // una clave que falta se ve, no deja la vista en blanco
  return text.replace(/\{(\w+)\}/g, (_, v: string) => String(vars?.[v] ?? `{${v}}`));
};

type CtxValue = { lang: Lang; setLang: (l: Lang) => void; t: T; coreLang?: Lang };
// Sin proveedor: inglés. Solo las pruebas lo cambian (test-setup.ts fija es, que es en lo que están escritas la mayoría).
const fallback: CtxValue = { lang: "en", setLang: () => {}, t: make("en"), coreLang: "en" };
export function setFallbackLangForTests(l: Lang) {
  Object.assign(fallback, { lang: l, t: make(l), coreLang: l });
  document.documentElement.lang = l;
}
const Ctx = createContext<CtxValue>(fallback);

function initial(): Lang {
  try {
    const v = localStorage.getItem(langStorageKey);
    if (v === "es" || v === "en") return v;
  } catch { /* sin almacenamiento: inglés */ }
  return "en";
}

// `onLang` se llama con el idioma vigente al montar y en cada cambio (el shell lo pasa al núcleo); `coreLang` es el
// idioma que el núcleo ya tiene: cambia cuando la promesa de onLang termina, con éxito o no.
export function I18nProvider({ children, onLang }: { children: ReactNode; onLang?: (l: Lang) => unknown }) {
  const [lang, setLangState] = useState<Lang>(initial);
  const setLang = (l: Lang) => {
    try { localStorage.setItem(langStorageKey, l); } catch { /* sin persistencia */ }
    setLangState(l);
  };
  const [coreLang, setCoreLang] = useState<Lang>();
  useLayoutEffect(() => {
    document.documentElement.lang = lang;
    let off = false;
    void Promise.resolve(onLang?.(lang)).catch(() => {}).finally(() => { if (!off) setCoreLang(lang); });
    return () => { off = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- solo cuando cambia el idioma
  }, [lang]);
  return <Ctx.Provider value={{ lang, setLang, t: make(lang), coreLang }}>{children}</Ctx.Provider>;
}

export const useT = () => useContext(Ctx).t;
// Fuera de React (p. ej. lib/core.ts): el idioma activo es el de <html lang>, que fija I18nProvider.
export const tr: T = (key, vars) => make(document.documentElement.lang === "es" ? "es" : "en")(key, vars);
export const useLang = () => useContext(Ctx).lang;
export const useSetLang = () => useContext(Ctx).setLang;
// Idioma que el núcleo ya confirmó (undefined hasta la primera confirmación): dependencia de lo que el núcleo traduce.
export const useCoreLang = () => useContext(Ctx).coreLang;

export function LanguageSwitch() {
  const { lang, setLang, t } = useContext(Ctx);
  return <Segmented legend={t("shell.language")} value={lang} onChange={setLang} options={[["es", "Español"], ["en", "English"]]} />;
}
