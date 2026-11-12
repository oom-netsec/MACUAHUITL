/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // vocab.test.ts lee el catálogo de plantillas de internal/assist (Go) como texto.
  // vocab.test.ts lee el catálogo de plantillas del núcleo: solo esa carpeta además del proyecto (allow reemplaza la raíz por omisión).
  server: { fs: { allow: [".", "../../internal/assist"] } },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    // Las vistas cargan bajo demanda y la paleta escribe y navega: 5 s se queda corto con la máquina ocupada.
    testTimeout: 10_000,
  },
});
