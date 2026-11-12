import "@testing-library/jest-dom/vitest";

// Las pruebas simulan un sistema en español (idioma inicial de la app).
Object.defineProperty(navigator, "language", { value: "es-MX", configurable: true });

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
