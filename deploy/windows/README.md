# deploy/windows

El instalador de Windows (ADR 0012, «Instalador»): NSIS, por usuario y sin administrador.

| Archivo | Qué hace |
|---|---|
| `macuahuitl.nsi` | La plantilla del instalador y del desinstalador. |
| `build-installer.sh` | La arma: genera el `.ico` con `tools/icowin` y llama a `makensis`. Corre en Linux (paquete `nsis`) o en Git Bash en Windows. |
| `build-release.sh` | Lo que corre `release.yml` en cada tag: compila los tres `.exe` dos veces y exige los mismos bytes, arma `macuahuitl_X.Y.Z_windows_amd64.zip` y el instalador. Las sumas y la atestación las agrega `release.yml` como con el resto. |
| `test-installer.ps1` | Instala y desinstala en un Windows desechable (el runner de CI) y revisa el resultado. **No lo corras en tu equipo:** desinstala MACUAHUITL del usuario actual. |

```sh
VERSION=1.2.3 BIN=<carpeta> deploy/windows/build-installer.sh dist/MACUAHUITL-1.2.3-setup.exe
```

`BIN` trae `macuahuitl.exe`, `macuahuitld.exe` y `mctl.exe`.

## Qué instala

- **Carpeta:** los tres ejecutables, el ícono, `LICENSE.txt`, `NOTICE.txt`, `THIRD_PARTY_LICENSES.txt` y `TRADEMARK.md`, en `%LOCALAPPDATA%\Programs\MACUAHUITL`.
  - La carpeta es fija: no hay página para elegirla y `/D=` se ignora. Una carpeta fuera del perfil, como `C:\Tools\…`, heredaría «Modificar» para Usuarios autenticados, y otro usuario local podría reemplazar el núcleo que arranca la entrada `Run`.
  - Si la clave de desinstalación apunta a otra carpeta que existe (una instalación de cuando se podía elegir), el instalador sale con código 3 sin cambiar nada y pide desinstalarla primero. Si esa carpeta ya no existe, instala normalmente.
  - Riesgo residual aceptado: la carpeta hereda la ACL del perfil. Si un administrador reubica `Local AppData` en un volumen con permisos abiertos, o en FAT/exFAT, esa protección no existe, igual que para los datos que están al lado.
- **Accesos directos:** uno en el menú Inicio del usuario. El del escritorio es opcional y viene apagado.
- **Entrada `Run` en HKCU:** arranca el núcleo al iniciar sesión, con la ruta absoluta de `macuahuitld.exe`.
- **Clave de desinstalación en HKCU.** Nada en HKLM y nada que pida UAC.
- **WebView2:** nada de Microsoft va dentro ni se descarga. Su licencia exige indemnizar a Microsoft a quien redistribuye el runtime o su bootstrapper (ADR 0012). Si falta, el instalador avisa al final con el enlace oficial, y la app avisa lo mismo al abrirse. Windows 11 ya lo trae.

## Actualizar y desinstalar

- **Detener el núcleo:** antes de reemplazar o borrar los ejecutables, el instalador pide al núcleo que se detenga con `mctl core stop`.
  - Si se niega porque hay trabajo en curso (código 3), avisa y no cambia nada.
  - Si algún ejecutable sigue en uso, también se detiene sin cambiar nada.
- **Qué se borra:** la desinstalación borra solo lo que puso el instalador.
  - Los datos en `%LOCALAPPDATA%\MACUAHUITL` (bóveda, auditoría y configuración) se borran solo si el usuario dice que sí. La respuesta por omisión es «No».
  - Con `/S` nunca se borran.
  - La carpeta de salidas nunca se toca.

## Firma

La beta sale sin firmar, por decisión del dueño. Con `SIGN_CMD` el armado firma el instalador y el desinstalador. Por ejemplo: `SIGN_CMD='signtool sign /fd sha256 /tr <url> /td sha256 "%1"'`. Sin `SIGN_CMD`, el paso se salta.
