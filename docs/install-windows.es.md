# Instalar en Windows (beta)

La versión para Windows es una **beta**. No promete paridad con Linux y sale **sin firma** (ver [Beta sin firma](#beta-sin-firma-qué-dirá-windows)). Lee esta página antes de ejecutar el instalador.

## Requisitos

- Windows 10 u 11 de 64 bits (amd64). ARM64 todavía no.
- El runtime WebView2 de Microsoft. Windows 11 lo trae. Si falta, el instalador y la app te lo avisan y dan el enlace oficial: <https://developer.microsoft.com/microsoft-edge/webview2/consumer/>. MACUAHUITL no incluye ni descarga nada de Microsoft.
- Sin permisos de administrador. Se instala solo para tu usuario.

## Descargar y verificar antes de ejecutar

En el [último release](../../../releases/latest) descarga el instalador y `SHA256SUMS`. El instalador se llama `MACUAHUITL-<versión>-setup.exe`; el nombre exacto está en la página del release.

Calcula el hash en PowerShell, en la carpeta de la descarga, y compáralo con la línea de tu archivo en `SHA256SUMS`:

```powershell
Get-FileHash -Algorithm SHA256 .\MACUAHUITL-<versión>-setup.exe
```

Con Git Bash puedes usar `sha256sum -c --ignore-missing SHA256SUMS`.

El hash detecta una descarga rota. Para comprobar que el archivo lo construyó el flujo de release de este repositorio, verifica su procedencia firmada con la [GitHub CLI](https://cli.github.com/):

```powershell
gh attestation verify .\MACUAHUITL-<versión>-setup.exe --repo oom-netsec/MACUAHUITL `
  --signer-workflow oom-netsec/MACUAHUITL/.github/workflows/release.yml
```

No ejecutes un instalador que falle cualquiera de las dos comprobaciones.

## Beta sin firma: qué dirá Windows

La beta no lleva firma de código. La verificación se apoya en `SHA256SUMS`, la atestación de arriba y el código abierto. Eso trae consecuencias:

- **SmartScreen** muestra «Windows protegió su PC». Elige **Más información** y luego **Ejecutar de todas formas**. Vuelve a aparecer con cada versión nueva.
- **Smart App Control** (Windows 11), si está activo, bloquea por completo un ejecutable sin firma, sin opción de ejecutarlo. Desactivarlo no tiene vuelta atrás sin reinstalar Windows. Esa decisión es tuya; el proyecto no la recomienda.
- **Microsoft Defender** puede marcar un binario Go sin firma como falso positivo. Si pasa, repórtalo a Microsoft como falso positivo.

## Qué instala y dónde

- **Programa:** `%LOCALAPPDATA%\Programs\MACUAHUITL` (la app, el núcleo `macuahuitld.exe`, `mctl.exe` y los archivos de licencia).
- **Accesos directos:** uno en el menú Inicio. El del escritorio es opcional y viene apagado.
- **Arranque:** el núcleo se inicia al iniciar sesión, con una entrada `Run` en `HKCU`. No se escribe nada en `HKLM` ni hay servicio de Windows.
- **Datos** (bóveda, auditoría, configuración): `%LOCALAPPDATA%\MACUAHUITL`.
- **Salidas** (evidencia, capturas): `%USERPROFILE%\MACUAHUITL\outputs`.

Si el instalador se abre como administrador, te avisa: ábrelo de nuevo sin «Ejecutar como administrador».

## Firewall y puertos

Windows no tiene puertos privilegiados, así que los servidores TFTP, FTP, SCP/SFTP, syslog y traps escuchan en su puerto estándar. Lo que estorba es el Firewall de Windows.

La app muestra la orden `New-NetFirewallRule` exacta del servidor que inicias, limitada al programa del núcleo, la IP, el protocolo y el puerto. Córrela una vez en un PowerShell de administrador. La app nunca la aplica por ti. Por ejemplo:

```powershell
New-NetFirewallRule -DisplayName MACUAHUITL-TFTP -Direction Inbound `
  -Program "<carpeta>\macuahuitld.exe" -LocalAddress <IP> -Protocol UDP -LocalPort 69 -Action Allow
```

Si cancelas el diálogo del Firewall la primera vez que un servidor escucha, Windows crea reglas de **bloqueo** para el programa, y el bloqueo gana a las reglas de permiso. Quítalas en *Firewall de Windows Defender con seguridad avanzada → Reglas de entrada* (busca `macuahuitld.exe`) y luego agrega la regla de permiso.

## Herramientas opcionales que instalas tú

Nunca van en el instalador:

- **nmap**, **Wireshark con Npcap** (captura de paquetes) e **iperf3**. Sin ellas, cada herramienta muestra un aviso de instalación con el enlace de descarga.
- La opción de escaneo SYN de nmap está oculta en Windows; el escaneo usa conexión normal.
- Para la consola serie necesitas el driver USB de tu adaptador.

## Lo que puede faltar en la beta

- Captura de paquetes, hasta que instales Wireshark con Npcap (nmap e iperf3, igual).
- El bloqueo de toda la memoria del proceso: solo se bloquean los rangos del material de llaves.
- Protección contra procesos del mismo usuario, que no existe en Windows sin administrador.
- La consola serie, si su validación en hardware real no está lista: se marca «sin validar».
- ARM64: solo amd64 al principio.
- El escaneo SYN de nmap.

Todo lo demás debe funcionar igual que en Linux, incluidos la bóveda, Patrol, el cambio asistido, los paquetes `.mpack`, el enmascarado, la auditoría y el terminal SSH. Esa es la vara de las pruebas de Windows, no una garantía.

## Actualizar

Ejecuta el instalador nuevo encima del anterior. Primero pide al núcleo que se detenga. Si hay trabajo en curso (un trabajo de Patrol, una transferencia o una captura), te avisa y no cambia nada: termina o cancela el trabajo y vuelve a intentar. Si la app está abierta, ciérrala antes.

## Desinstalar

Usa *Configuración → Aplicaciones* y quita MACUAHUITL. El desinstalador borra solo lo que puso el instalador.

- Tus datos en `%LOCALAPPDATA%\MACUAHUITL` se borran solo si contestas **Sí** a una pregunta aparte. La respuesta por omisión es **No**, y una desinstalación silenciosa (`/S`) nunca los borra.
- La carpeta de salidas nunca se borra.
