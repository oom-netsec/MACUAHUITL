# Fuentes de las imágenes de la portada

No se retocan los PNG ni los JPG: se cambia el HTML y se vuelve a renderizar.

| Imagen | Fuente | Qué es |
|---|---|---|
| `../bento.jpg` (2560×2084) | `bento.html` | El bloque «One app. The whole job.» del README. |
| `../../portada.png` (2560×1280) | `social.html` + `shots/` | La portada del README y la vista social de GitHub (Settings → Social preview, menos de 1 MB). |

El número de reglas de análisis no está escrito en el HTML: `render.cjs` lo cuenta en `internal/analyze/rules` y lo pasa a
la página. `tools/packaging` falla si el README o el roadmap dicen otro número que el de `analyze.DefaultRules`.

Las capturas de `shots/` salen de la vista previa de la UI (`ui/frontend/src/preview`, datos de ejemplo en inglés e IPs de
documentación, RFC 5737) con la hora fija, así que se repiten igual.

```sh
npm install --prefix /tmp/pw playwright-core@1.56.1        # una vez, fuera del repo (Apache-2.0)
/tmp/pw/node_modules/.bin/playwright-core install chromium-headless-shell
export PLAYWRIGHT_CORE=/tmp/pw/node_modules/playwright-core

# Solo si cambió la UI: capturas nuevas desde la vista previa.
(cd ui/frontend && npx vite --config vite.preview.config.ts --port 5199 --strictPort --host 127.0.0.1) &
until curl -sf http://127.0.0.1:5199/preview.html >/dev/null; do sleep 0.2; done
node docs/assets/pro/src/capture.cjs                         # shots/patrol-dark.png y shots/patrol-light.png
kill %1

node docs/assets/pro/src/render.cjs                          # bento.jpg y portada.png
```

La fuente tipográfica y el logo son los de la app (`ui/frontend/src/assets/fonts`, OFL; `ui/frontend/public/favicon.svg`);
el render falla si no cargan, si falta una captura o si `portada.png` pasa de 1 MB.

## Subir la vista social a GitHub

GitHub no la toma del repo: se sube a mano.

1. En el repositorio: **Settings → General → Social preview → Edit → Upload an image…**
2. Elige `docs/assets/portada.png`.
3. Revisa la vista previa y guarda. La miniatura que muestran LinkedIn o Slack puede tardar en refrescarse por su caché.
