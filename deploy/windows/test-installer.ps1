# Prueba del instalador en un Windows desechable (el runner de CI): instala en silencio, revisa lo que deja, comprueba que
# la desinstalación se detiene si un ejecutable está en uso y que /S nunca borra los datos. No usar en un equipo propio:
# instala y desinstala MACUAHUITL del usuario actual. Uso:
#   test-installer.ps1 -Installer <instalador.exe> -DeleteDataInstaller <armado con TEST_DELETE_DATA=1> -Version X.Y.Z
param([Parameter(Mandatory = $true)][string]$Installer, [Parameter(Mandatory = $true)][string]$DeleteDataInstaller,
  [Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
$inst = Join-Path $env:LOCALAPPDATA 'Programs\MACUAHUITL'
$data = Join-Path $env:LOCALAPPDATA 'MACUAHUITL'
$runKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$unKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MACUAHUITL'
$startLnk = Join-Path ([Environment]::GetFolderPath('Programs')) 'MACUAHUITL.lnk'
$deskLnk = Join-Path ([Environment]::GetFolderPath('Desktop')) 'MACUAHUITL.lnk'
$files = 'macuahuitl.exe', 'macuahuitld.exe', 'mctl.exe', 'macuahuitl.ico', 'LICENSE.txt', 'NOTICE.txt', 'THIRD_PARTY_LICENSES.txt', 'TRADEMARK.md'
function Must($cond, $msg) { if (-not $cond) { throw "FALLA: $msg" }; Write-Host "ok: $msg" }
function RunWait($exe, $argList) { (Start-Process -FilePath $exe -ArgumentList $argList -Wait -PassThru).ExitCode }

Must ((RunWait $Installer '/S') -eq 0) 'el instalador termina sin error'
foreach ($f in $files + 'uninstall.exe') { Must (Test-Path (Join-Path $inst $f)) "instalado $f" }
Must ((Get-ItemProperty $runKey).'MACUAHUITL core' -eq "`"$inst\macuahuitld.exe`"") 'entrada Run con la ruta absoluta del núcleo'
$un = Get-ItemProperty $unKey
Must ($un.DisplayVersion -eq $Version -and $un.QuietUninstallString -eq "`"$inst\uninstall.exe`" /S") 'clave de desinstalación en HKCU'
Must (-not (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\MACUAHUITL')) 'nada en HKLM'
Must (Test-Path $startLnk) 'acceso directo en el menú Inicio'
Must (-not (Test-Path $deskLnk)) 'sin acceso directo en el escritorio por omisión'

# Actualizar encima: sin nada abierto termina bien; con la app abierta se detiene antes de tocar nada (ni el núcleo).
Must ((RunWait $Installer '/S') -eq 0) 'actualizar encima de una instalación termina sin error'
Set-Content (Join-Path $inst 'macuahuitld.exe') 'núcleo de la versión anterior' # marca: el instalador trae otro contenido
$core = Get-Content -Raw (Join-Path $inst 'macuahuitld.exe')
Copy-Item -Force "$env:SystemRoot\System32\ping.exe" (Join-Path $inst 'macuahuitl.exe')
$app = Start-Process -FilePath (Join-Path $inst 'macuahuitl.exe') -ArgumentList '-n', '60', '127.0.0.1' -PassThru -WindowStyle Hidden
try {
  Must ((RunWait $Installer '/S') -eq 2) 'con la app abierta, actualizar se detiene'
  Must ((Get-Content -Raw (Join-Path $inst 'macuahuitld.exe')) -eq $core) 'y no reemplazó el núcleo'
} finally { Stop-Process -Id $app.Id -Force; $app.WaitForExit() }

# Datos de una instalación en uso: /S nunca los borra.
New-Item -ItemType Directory -Force (Join-Path $data 'data') | Out-Null
Set-Content (Join-Path $data 'data\vault.db') 'bóveda de prueba'

# Un ejecutable en uso detiene la desinstalación sin tocar nada (NSIS sale con 2 al abortar).
Copy-Item -Force "$env:SystemRoot\System32\ping.exe" (Join-Path $inst 'macuahuitld.exe')
$busy = Start-Process -FilePath (Join-Path $inst 'macuahuitld.exe') -ArgumentList '-n', '60', '127.0.0.1' -PassThru -WindowStyle Hidden
try {
  Must ((RunWait (Join-Path $inst 'uninstall.exe') @('/S', "_?=$inst")) -eq 2) 'con el núcleo en uso, la desinstalación se detiene'
  foreach ($f in $files) { Must (Test-Path (Join-Path $inst $f)) "sigue $f" }
  Must ($null -ne (Get-ItemProperty $runKey).'MACUAHUITL core') 'sigue la entrada Run'
} finally { Stop-Process -Id $busy.Id -Force; $busy.WaitForExit() }

# _?= corre el desinstalador en su lugar y espera; por eso uninstall.exe y la carpeta quedan y se quitan aquí.
Must ((RunWait (Join-Path $inst 'uninstall.exe') @('/S', "_?=$inst")) -eq 0) 'la desinstalación termina sin error'
foreach ($f in $files) { Must (-not (Test-Path (Join-Path $inst $f))) "quitado $f" }
Must ($null -eq (Get-ItemProperty $runKey).'MACUAHUITL core') 'quitada la entrada Run'
Must (-not (Test-Path $unKey)) 'quitada la clave de desinstalación'
Must (-not (Test-Path $startLnk)) 'quitado el acceso directo'
Must ((Get-Content (Join-Path $data 'data\vault.db')) -eq 'bóveda de prueba') 'con /S los datos quedan intactos'
Remove-Item -Recurse -Force $inst, $data

# Contestar Sí a borrar los datos (compilación de prueba, que contesta Sí en silencioso): se borran los enlaces que haya
# dentro, nunca lo que está del otro lado. RMDir /r de NSIS sí los seguía (esta prueba lo mostró): el .nsi usa SafeRemove.
$outside = Join-Path $env:TEMP 'macuahuitl-fuera'
New-Item -ItemType Directory -Force $outside | Out-Null
Set-Content (Join-Path $outside 'no-borrar.txt') 'ajeno'
Must ((RunWait $DeleteDataInstaller '/S') -eq 0) 'instala la compilación de prueba del borrado'
New-Item -ItemType Directory -Force (Join-Path $data 'data') | Out-Null
Set-Content (Join-Path $data 'data\vault.db') 'bóveda de prueba'
New-Item -ItemType Junction -Path (Join-Path $data 'data\enlace-junction') -Target $outside | Out-Null
New-Item -ItemType SymbolicLink -Path (Join-Path $data 'enlace-symlink') -Target $outside | Out-Null
Must ((RunWait (Join-Path $inst 'uninstall.exe') @('/S', "_?=$inst")) -eq 0) 'desinstala contestando Sí a borrar los datos'
Must (-not (Test-Path $data)) 'contestando Sí, se borran los datos'
Must ((Get-Content (Join-Path $outside 'no-borrar.txt')) -eq 'ajeno') 'lo que está del otro lado de un junction o symlink queda intacto'
Remove-Item -Recurse -Force $inst, $outside
