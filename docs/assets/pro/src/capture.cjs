// Toma de la vista previa de la UI (datos de ejemplo en inglés, IPs de documentación) las capturas que usa social.html:
// shots/patrol-dark.png y shots/patrol-light.png (1280×800 a 2x). Hace falta la vista previa corriendo (ver README.md aquí).
const path = require("path");
const { chromium } = require(process.env.PLAYWRIGHT_CORE || "playwright-core");

const base = process.env.PREVIEW_URL || "http://127.0.0.1:5199/preview.html";
// Hora fija: las fases de Patrol muestran la hora, y la imagen tiene que salir igual en cada corrida.
const now = new Date("2026-11-14T22:40:00");

(async () => {
  const browser = await chromium.launch();
  try {
    for (const theme of ["dark", "light"]) {
      const page = await browser.newPage({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2 });
      await page.clock.setFixedTime(now);
      await page.goto(`${base}?m=patrol&theme=${theme}&lang=en`);
      await page.getByText("Summary of SW1").waitFor();
      await page.evaluate(() => document.fonts.ready);
      await page.screenshot({ path: path.join(__dirname, "shots", `patrol-${theme}.png`) });
      await page.close();
    }
    console.log("shots/patrol-dark.png, shots/patrol-light.png");
  } finally {
    await browser.close();
  }
})().catch((e) => { console.error(e); process.exit(1); });
