import "@testing-library/jest-dom/vitest";

// El idioma canónico de la app es el inglés; la mayoría de las pruebas comprueban textos en español, así que cada una
// arranca con el español elegido (la clave de i18n.tsx). Las que prueban el valor por omisión limpian el almacenamiento.
import { beforeEach } from "vitest";
import { setFallbackLangForTests } from "./lib/i18n";
const fijaEs = () => { setFallbackLangForTests("es"); try { localStorage.setItem("macuahuitl.lang", "es"); } catch { /* sin almacenamiento */ } };
beforeEach(fijaEs);
// Muchas pruebas limpian el almacenamiento con localStorage.clear(): el español elegido se vuelve a fijar. Para probar el
// valor por omisión (nada guardado) se quita la clave con removeItem.
const limpiar = Storage.prototype.clear;
Storage.prototype.clear = function (this: Storage) { limpiar.call(this); if (this === localStorage) fijaEs(); };

// Las vistas se cargan bajo demanda (React.lazy): con la máquina ocupada, 1 s no alcanza para que aparezcan.
import { configure } from "@testing-library/react";
configure({ asyncUtilTimeout: 3000 });

// El runtime real de Wails, al importarse, arranca un temporizador que toca `window` (drag.js); si un archivo de pruebas
// termina antes, jsdom ya se cerró y vitest reporta un error suelto (con la máquina cargada no basta con esperar).
// Las pruebas usan los dobles de lib/fake.ts: aquí el runtime es un doble y nada lo carga. Un archivo puede poner el suyo.
import { vi } from "vitest";
vi.mock("@wailsio/runtime", () => {
  const sinPuente = async () => { throw new Error("sin puente de Wails en las pruebas"); };
  return {
    Call: { ByName: vi.fn(sinPuente) },
    Clipboard: { SetText: vi.fn(sinPuente), Text: vi.fn(sinPuente) },
    Dialogs: { Error: vi.fn(sinPuente), OpenFile: vi.fn(sinPuente), Question: vi.fn(sinPuente), SaveFile: vi.fn(sinPuente) },
    Events: { On: vi.fn(() => () => {}) },
    Window: { Close: vi.fn(sinPuente), Minimise: vi.fn(sinPuente), ToggleMaximise: vi.fn(sinPuente) },
  };
});
