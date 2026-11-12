import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app/App";
import { WindowControls } from "./app/WindowControls";
import { wailsCore } from "./lib/core";
import { setTermBackend } from "./lib/termPrefs";
import "./styles.css";

void setTermBackend(wailsCore);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App core={wailsCore} chrome={<WindowControls />} />
  </StrictMode>,
);
