# deploy/packaging

Paquetes `.deb` y `.rpm` con nfpm (`nfpm.yaml`), construidos por `.github/workflows/release.yml` al etiquetar `vX.Y.Z`, o a mano:

```sh
VERSION=v1.0.0 task release-build   # núcleo y CLI reproducibles en bin/
task ui-build                       # UI en bin/
VERSION=v1.0.0 task package         # dist/*.deb y dist/*.rpm
```

Instalación: `sudo dpkg -i dist/macuahuitl_*.deb` y después, como el usuario que lo usará, `systemctl --user enable --now macuahuitld`.

## Dependencias de la UI de escritorio

El binario `macuahuitl` (Wails v3) usa el motor web del sistema. Para compilarlo:

| Distribución | Paquetes |
|---|---|
| Ubuntu / Debian | `libgtk-3-dev libwebkit2gtk-4.1-dev build-essential pkg-config` |
| Fedora / RHEL | `gtk3-devel webkit2gtk4.1-devel gcc pkgconf-pkg-config` |

Se compila con `task ui-build`, que usa las etiquetas `wails gtk3`: Wails 3.1 usa GTK4 y WebKitGTK 6.0 por defecto, y estas distribuciones traen GTK3 con WebKitGTK 4.1.

Para ejecutarlo basta con las versiones de runtime (`libwebkit2gtk-4.1-0`, `webkit2gtk4.1`).

Si se lanza desde la terminal de un VS Code instalado como snap, GTK hereda variables del snap y falla con `symbol lookup error … libpthread`. Lánzalo desde una terminal normal o quita esas variables (`GTK_PATH`, `GTK_EXE_PREFIX`, `GIO_MODULE_DIR`, `GDK_PIXBUF_MODULE_FILE`, `GSETTINGS_SCHEMA_DIR`, `LOCPATH`).

El núcleo `macuahuitld` y `mctl` no necesitan nada de esto: se compilan sin cgo.
