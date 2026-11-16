// Renderiza bento.html a ../bento.jpg (2560×2084, con el número de reglas que hay en internal/analyze/rules) y social.html a
// ../../portada.png (2560×1280: portada del README y vista social de GitHub, que pide menos de 1 MB).
// Uso (ver README.md aquí): PLAYWRIGHT_CORE=/ruta/a/node_modules/playwright-core node docs/assets/pro/src/render.cjs
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const { chromium } = require(process.env.PLAYWRIGHT_CORE || "playwright-core");

const root = path.resolve(__dirname, "../../../..");
const dir = path.join(root, "internal/analyze/rules");
// Cada regla abre con «- id:» al inicio de la línea; TestReadmeCuentaReglas compara el README con analyze.DefaultRules.
const rules = fs.readdirSync(dir).filter((f) => f.endsWith(".yaml"))
  .reduce((n, f) => n + (fs.readFileSync(path.join(dir, f), "utf8").match(/^- id:/gm) || []).length, 0);
if (!rules) throw new Error("no se encontraron reglas en " + dir);

(async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 1280, height: 1042 }, deviceScaleFactor: 2 });
    await page.goto(pathToFileURL(path.join(__dirname, "bento.html")).href + "?rules=" + rules);
    await page.evaluate(() => document.fonts.ready);
    if (!(await page.evaluate(() => document.fonts.check('750 56px "Inter"')))) throw new Error("no cargó la fuente Inter");
    if ((await page.textContent("#rules")) !== String(rules)) throw new Error("la página no recibió el número de reglas");
    await page.screenshot({ path: path.join(__dirname, "..", "bento.jpg"), type: "jpeg", quality: 90 });
    console.log(`bento.jpg: ${rules} reglas`);

    await page.setViewportSize({ width: 1280, height: 640 });
    await page.goto(pathToFileURL(path.join(__dirname, "social.html")).href);
    await page.evaluate(() => document.fonts.ready);
    if (!(await page.evaluate(() => document.fonts.check('750 64px "Inter"')))) throw new Error("no cargó la fuente Inter");
    if (await page.evaluate(() => [...document.images].some((i) => !i.complete || !i.naturalWidth))) throw new Error("falta una imagen (¿corriste capture.cjs?)");
    const out = path.join(__dirname, "..", "..", "portada.png");
    await page.screenshot({ path: out });
    const bytes = fs.statSync(out).size;
    if (bytes >= 1_000_000) throw new Error(`portada.png pesa ${bytes} bytes; GitHub pide menos de 1 MB`);
    console.log(`portada.png: ${bytes} bytes`);
  } finally {
    await browser.close();
  }
})().catch((e) => { console.error(e); process.exit(1); });
