// Browser preview with sample data (npm run preview:ui). Not part of the app build.
// Parameters: ?m=<manifest id>&theme=light|dark&lang=es|en
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
} catch { /* no storage */ }
// lib/theme.ts read storage at import time, before the lines above: read it again to apply ?theme= on this load.
resetTheme();

const core = fakeCore(sample()) as unknown as CoreAPI;
// For screenshots: lets Playwright emit sample events (core.emitDiag, core.emitAssist…).
(window as unknown as { core: CoreAPI }).core = core;
createRoot(document.getElementById("root")!).render(q.get("gallery") ? <Gallery core={core} /> : <App core={core} initial={q.get("m") ?? undefined} />);
