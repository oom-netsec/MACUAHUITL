# Fuentes de las imágenes de la portada

`bento.html` es la fuente de `../bento.jpg` (2560×2084). No se retoca el JPG: se cambia el HTML y se vuelve a renderizar.
El número de reglas de análisis no está escrito en el HTML: `render.cjs` lo cuenta en `internal/analyze/rules` y lo pasa
a la página. `tools/packaging` falla si el README dice otro número que el de `analyze.DefaultRules`.

```sh
npm install --prefix /tmp/pw playwright-core@1.56.1        # una vez, fuera del repo (Apache-2.0)
/tmp/pw/node_modules/.bin/playwright-core install chromium-headless-shell
PLAYWRIGHT_CORE=/tmp/pw/node_modules/playwright-core node docs/assets/pro/src/render.cjs
```

La fuente tipográfica es la de la app (`ui/frontend/src/assets/fonts`, OFL); el render falla si no carga.
