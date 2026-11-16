// Capturas del cambio asistido para el README, tomadas de la vista previa de la UI (datos de ejemplo, IP de documentación):
// ../../screens/assist-plan-dark.png (plan con las líneas y su reversa) y ../../screens/assist-confirm-dark.png (el paso espera
// confirmación). Hace falta la vista previa corriendo en el puerto 5199 y playwright-core (ver README.md aquí):
//   (cd ui/frontend && npx vite --config vite.preview.config.ts --port 5199 --strictPort --host 127.0.0.1) &
//   PLAYWRIGHT_CORE=/tmp/pw/node_modules/playwright-core node docs/assets/pro/src/capture-assist.cjs
const path = require("path");
const { chromium } = require(process.env.PLAYWRIGHT_CORE || "playwright-core");

const base = process.env.PREVIEW_URL || "http://127.0.0.1:5199/preview.html";
const out = (name) => path.join(__dirname, "..", "..", "screens", name);

// Recorta de la página la franja entre el borde de arriba de `from` y el de abajo de `to`.
async function band(page, from, to, file) {
  // El botón «Plan (read-only)» marca el borde izquierdo de la columna de contenido; el derecho es el de la ventana.
  const a = await from.boundingBox(), b = await to.boundingBox(), col = await page.getByRole("button", { name: "Plan (read-only)" }).boundingBox();
  if (!a || !b || !col) throw new Error("no encontré la franja para " + file);
  const pad = 16, x = col.x - pad;
  await page.screenshot({ path: out(file), clip: { x, y: a.y - pad, width: page.viewportSize().width - pad - x, height: b.y + b.height - a.y + 2 * pad + 10 } });
}

(async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1900 }, deviceScaleFactor: 2 });
    await page.clock.setFixedTime(new Date("2026-11-14T22:40:00"));
    await page.goto(`${base}?m=ports&theme=dark&lang=en`);
    await page.getByLabel("Device (IP or hostname[:port])").fill("192.0.2.21");
    await page.getByLabel("Interfaces").fill("Gi1/0/1");
    await page.getByLabel("Access VLAN").fill("20");
    await page.getByRole("button", { name: "Plan (read-only)" }).click();
    await page.getByText("Plan for SW1").waitFor();
    await page.evaluate(() => document.fonts.ready);
    if (!(await page.evaluate(() => document.fonts.check('16px "JetBrains Mono"')))) throw new Error("no cargó la fuente monoespaciada");
    await band(page, page.getByText("Plan for SW1"), page.getByRole("button", { name: /Start change on/ }), "assist-plan-dark.png");

    await page.getByLabel("Enable assisted mode for this run").check();
    await page.getByRole("button", { name: /Start change on/ }).click();
    // Los eventos que mandaría el núcleo: la corrida arranca y el primer paso espera confirmación.
    await page.evaluate(() => {
      const c = window.core;
      c.emitAssist({ runId: "r1", seq: 1, kind: "state", state: "running" });
      c.emitAssist({ runId: "r1", seq: 2, kind: "pending", step: { id: "apply-1", kind: "apply", device: "SW1", lines: ["interface GigabitEthernet1/0/1", "switchport access vlan 20"] } });
    });
    await page.getByText("Ready to apply.").waitFor();
    await band(page, page.getByText("Run r1: Running"), page.getByRole("button", { name: /^Apply 2 lines to SW1/ }), "assist-confirm-dark.png");
    console.log("screens/assist-plan-dark.png, screens/assist-confirm-dark.png");
  } finally {
    await browser.close();
  }
})().catch((e) => { console.error(e); process.exit(1); });
