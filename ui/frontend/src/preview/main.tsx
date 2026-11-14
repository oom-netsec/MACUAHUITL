// Vista previa en navegador con datos de ejemplo (npm run preview:ui). No entra al build de la app.
// Parámetros: ?m=<id del manifiesto>&theme=light|dark&lang=es|en
import { createRoot } from "react-dom/client";
import { App } from "../app/App";
import { fakeCore } from "../lib/fake";
import type { CoreAPI } from "../lib/core";
import { sample } from "./data";
import { Gallery } from "./Gallery";
import { resetTheme } from "../lib/theme";
import "../styles.css";

const q = new URLSearchParams(location.search);
try {
  if (q.get("theme")) localStorage.setItem("macuahuitl.tema", q.get("theme")!);
  if (q.get("lang")) localStorage.setItem("macuahuitl.lang", q.get("lang")!);
} catch { /* sin almacenamiento */ }
// lib/theme.ts leyó el almacenamiento al importarse, antes de la línea de arriba: vuelve a leerlo para aplicar ?theme= en esta carga.
resetTheme();

const core = fakeCore(sample()) as unknown as CoreAPI;
// Para las capturas: permite emitir eventos de ejemplo (core.emitDiag, core.emitAssist…) desde Playwright.
(window as unknown as { core: CoreAPI }).core = core;
createRoot(document.getElementById("root")!).render(q.get("gallery") ? <Gallery core={core} /> : <App core={core} initial={q.get("m") ?? undefined} />);
