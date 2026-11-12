import "@testing-library/jest-dom/vitest";

// Las pruebas simulan un sistema en español (idioma inicial de la app).
Object.defineProperty(navigator, "language", { value: "es-MX", configurable: true });

// Las vistas se cargan bajo demanda (React.lazy): con la máquina ocupada, 1 s no alcanza para que aparezcan.
import { configure } from "@testing-library/react";
configure({ asyncUtilTimeout: 3000 });

// El runtime de Wails, al importarse, arranca un temporizador de 50 ms que toca `window` (drag.js). Si un archivo de
// pruebas termina antes, jsdom ya se cerró y vitest reporta un error suelto: se espera ese tic antes de cerrar.
import { afterAll } from "vitest";
afterAll(() => new Promise((r) => setTimeout(r, 60)));
