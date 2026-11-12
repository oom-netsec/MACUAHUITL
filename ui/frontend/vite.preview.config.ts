import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";

// Vista previa con los dobles de pruebas, sin vitest: `vitest` apunta a un shim.
export default defineConfig({
  plugins: [react()],
  resolve: { alias: { vitest: fileURLToPath(new URL("./src/preview/vitest-shim.ts", import.meta.url)) } },
  server: { port: 5199, strictPort: true },
  build: { outDir: "dist-preview", rollupOptions: { input: "preview.html" } },
});
