import { en } from "./i18n/en";

// El inglés es el idioma canónico: ningún texto de en.ts lleva letras o signos propios del español (se cuela al copiar
// de es.ts o al citar un nombre de playbook en español en vez de su name_en).
test("en.ts no trae texto en español", () => {
  const bad = Object.entries(en).filter(([, v]) => /[áéíóúñÁÉÍÓÚÑ¿¡]/.test(v)).map(([k, v]) => `${k}: ${v}`);
  expect(bad).toEqual([]);
});
