import { es } from "./i18n/es";
import { en } from "./i18n/en";
import { JOB_STATES, VOCAB, jobState, vocab, vocabKey, type VocabGroup } from "./vocab";

// Guardia de los vocabularios del núcleo: cada valor conocido tiene su texto en es y en en.
// Fuentes del catálogo en Go, leídas como texto (las pruebas _test.go quedan fuera).
const goSources = import.meta.glob<string>(["../../../../internal/assist/*.go", "!**/*_test.go"], { query: "?raw", import: "default", eager: true });
const E = es as Record<string, string>;
const N = en as Record<string, string>;
const both = (k: string) => (E[k] && N[k] ? null : k);

test("cada valor conocido del núcleo tiene clave en español e inglés", () => {
  const missing = (Object.keys(VOCAB) as VocabGroup[]).flatMap((g) => VOCAB[g].map((v) => both(vocabKey(g, v))).filter(Boolean));
  expect(missing).toEqual([]);
  expect(JOB_STATES.map((s) => both(`patrol.state.${s}`)).filter(Boolean)).toEqual([]);
});

test("en inglés ningún valor del núcleo se queda en español", () => {
  const spanishWord = /^(ausente|válido|inválido|hallazgo|equipo|módulo|aviso)$/i;
  const bad = (Object.keys(VOCAB) as VocabGroup[]).flatMap((g) => VOCAB[g].map((v) => N[vocabKey(g, v)]).filter((x) => spanishWord.test(x)));
  expect(bad).toEqual([]);
});

test("vocab: un valor sin clave se muestra tal cual", () => {
  const t = ((k: string) => (E[k] ?? k)) as Parameters<typeof vocab>[0];
  expect(vocab(t, "ma", "válido")).toBe("válido");
  expect(vocab(t, "problem", "algo-nuevo")).toBe("algo-nuevo");
  expect(jobState(t, "closed")).toBe("Cerrado");
  expect(jobState(t, "otro")).toBe("otro");
});

// Plantillas de snippets: el catálogo vive en internal/assist/*.go (nombre, campos, ayudas) y la interfaz las muestra
// con claves snippet.<id>.name y snippet.<id>.field.<campo>[.help]. Si el núcleo agrega una plantilla o un campo, esta
// prueba obliga a traducirlos (si no, en inglés se verían en español).
test("las plantillas de snippets del núcleo están traducidas (nombre, campos y ayudas)", () => {
  const src = Object.values(goSources).join("\n");
  const missing: string[] = [];
  let seen = 0;
  for (const part of src.split(/\{ID: "/).slice(1)) {
    const id = /^([a-z0-9-]+)", Tech: "/.exec(part)?.[1];
    if (!id) continue;
    seen++;
    const block = part.split(/\n\t\t\tPre:|\n\t\t\tPlan:/)[0];
    [both(`snippet.${id}.name`)].forEach((m) => m && missing.push(m));
    for (const line of block.split("\n")) {
      const f = /\{Name: "(\w+)", Label: "/.exec(line)?.[1];
      if (!f) continue;
      const m1 = both(`snippet.${id}.field.${f}`);
      if (m1) missing.push(m1);
      if (/Help: "/.test(line)) { const m2 = both(`snippet.${id}.field.${f}.help`); if (m2) missing.push(m2); }
    }
  }
  expect(seen).toBeGreaterThanOrEqual(15);
  expect(missing).toEqual([]);
});
