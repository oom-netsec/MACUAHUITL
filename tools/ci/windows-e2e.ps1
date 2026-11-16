# Prueba de punta a punta de MACUAHUITL en un Windows desechable (el runner de CI; ADR 0012). Crea usuarios locales
# ESTÁNDAR y corre el núcleo y mctl como ellos: el runner es administrador con token elevado y el núcleo se niega a correr
# así, además de que el pipe lleva el SID de quien lo abre. NO usar en un equipo propio: crea y borra usuarios.
# Uso: windows-e2e.ps1 -BinDir <carpeta con macuahuitl.exe macuahuitld.exe mctl.exe simserver.exe> -Installer <setup.exe> `
#        -Transcripts <test/transcripts/ios-xe> -Version X.Y.Z
# Contraseñas: se generan aquí (nunca en el log: ::add-mask::). Las que mctl lee por stdin pasan por un archivo en una
# carpeta con ACL solo del usuario (y Administradores, para poder borrarla al final); se borra en cada uso y al terminar.
param([Parameter(Mandatory = $true)][string]$BinDir, [Parameter(Mandatory = $true)][string]$Installer,
  [Parameter(Mandatory = $true)][string]$Transcripts, [Parameter(Mandatory = $true)][string]$Version)
$ErrorActionPreference = 'Stop'
$root = 'C:\e2e'
$work = "$root\work"
$bin = "$root\bin"
$script:procs = @()
$script:users = @()

function Must($cond, $msg) { if (-not $cond) { throw "FALLA: $msg" }; Write-Host "ok: $msg" }
function NewSecret {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  $s = 'Aa1-' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')
  Write-Host "::add-mask::$s"
  $s
}
function Grant($path, $sid) { icacls $path /grant "*${sid}:(OI)(CI)F" | Out-Null; if ($LASTEXITCODE) { throw "icacls $path" } }

# La carpeta solo tiene el SID del usuario y Administradores (S-1-5-32-544), con DACL protegida (por SID, no por nombres).
function AssertPrivateAcl($path, $sid) {
  $acl = Get-Acl $path
  $sids = @($acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique)
  $extra = @($sids | Where-Object { $_ -notin @($sid, 'S-1-5-32-544') })
  if ($extra.Count -or -not $acl.AreAccessRulesProtected -or $sid -notin $sids) { throw "FALLA: ACL de $path no es privada ($($sids -join ', '))" }
}
# Carpeta solo del usuario (y Administradores, para poder borrarla al final).
function New-PrivateDir($path, $sid) {
  New-Item -ItemType Directory $path | Out-Null
  icacls $path /inheritance:r | Out-Null; if ($LASTEXITCODE) { throw "icacls /inheritance:r $path" }
  Grant $path $sid; Grant $path 'S-1-5-32-544'
  AssertPrivateAcl $path $sid
}

# Usuario estándar (grupo Usuarios, S-1-5-32-545) con contraseña aleatoria y carpeta de secretos solo suya.
function New-E2EUser($name) {
  $pw = NewSecret
  New-LocalUser -Name $name -Password (ConvertTo-SecureString $pw -AsPlainText -Force) -AccountNeverExpires -PasswordNeverExpires | Out-Null
  # Se registra ya: el finally lo borra aunque falle lo que sigue (el SID se completa después).
  $u = @{ Name = $name; Sid = $null }
  $script:users += $u
  Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $name
  $u.Sid = (Get-LocalUser $name).SID.Value
  $u.Secret = "$root\secret-$name"; $u.Work = "$root\work-$name"
  New-PrivateDir $u.Secret $u.Sid # contraseñas de bóveda por stdin
  New-PrivateDir $u.Work $u.Sid   # salidas de sus procesos: un usuario no lee las del otro
  $u.Vault = NewSecret
  $u.Cred = New-Object Management.Automation.PSCredential(".\$name", (ConvertTo-SecureString $pw -AsPlainText -Force))
  $u
}
function ProfileOf($u) { (Get-CimInstance Win32_UserProfile -Filter "SID='$($u.Sid)'").LocalPath }

# Corre un programa como el usuario y espera. stdin va por archivo (nunca por argumento); la salida, a archivos de work.
function Invoke-As($u, $exe, [string[]]$argv = @(), $stdin = $null, [switch]$NoWait) {
  $id = [guid]::NewGuid().ToString('N').Substring(0, 8)
  $o = "$($u.Work)\$id.out"; $e = "$($u.Work)\$id.err"
  $sp = @{ FilePath = $exe; Credential = $u.Cred; LoadUserProfile = $true; UseNewEnvironment = $true; WorkingDirectory = $u.Work; RedirectStandardOutput = $o
    RedirectStandardError = $e; PassThru = $true; WindowStyle = 'Hidden' }
  if ($argv.Count) { $sp.ArgumentList = $argv }
  $in = $null
  if ($null -ne $stdin) {
    $in = "$($u.Secret)\$id.in"
    [IO.File]::WriteAllText($in, $stdin, (New-Object Text.UTF8Encoding($false)))
    $sp.RedirectStandardInput = $in
  }
  try {
    $p = Start-Process @sp
    $null = $p.Handle # que ExitCode quede disponible
    if ($NoWait) { $script:procs += $p; return @{ Proc = $p; OutFile = $o; ErrFile = $e } }
    if (-not $p.WaitForExit(120000)) { $p.Kill(); throw "se colgó: $exe $argv" }
    $p.WaitForExit()
    $r = @{ Code = $p.ExitCode; Out = ''; Err = '' }
    if (Test-Path $o) { $r.Out = Get-Content -Raw $o }; if (Test-Path $e) { $r.Err = Get-Content -Raw $e }
    $r.Out = "$($r.Out)"; $r.Err = "$($r.Err)"
    $r
  } finally { if ($in) { Remove-Item -Force $in -ErrorAction SilentlyContinue } }
}
function Mctl($u, [string[]]$argv, $stdin = $null) { Invoke-As $u "$bin\mctl.exe" $argv $stdin }
function MctlOk($u, [string[]]$argv, $stdin = $null) {
  $r = Mctl $u $argv $stdin
  if ($r.Code -ne 0) { throw "FALLA: mctl $argv salió $($r.Code)`n$($r.Out)`n$($r.Err)" }
  $r.Out
}
function PipeNames { [IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { $_.ToLowerInvariant() } }
function WaitPipe($sid, $want) {
  $name = "\\.\pipe\macuahuitl-$sid".ToLowerInvariant()
  for ($i = 0; $i -lt 60; $i++) { if ((PipeNames) -contains $name -eq $want) { return $true }; Start-Sleep -Milliseconds 500 }
  $false
}

$u1 = $null; $u2 = $null; $core = $null; $sim = $null
try {
  New-Item -ItemType Directory -Force $work, $bin | Out-Null
  icacls $work /inheritance:r /grant '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE) { throw 'icacls work' }
  Copy-Item "$BinDir\*.exe" $bin
  $adm = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  Must $adm 'el runner es administrador (token elevado)'

  # 0) elevado, el núcleo se niega y no crea el pipe.
  $runnerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $p = Start-Process "$bin\macuahuitld.exe" -PassThru -WindowStyle Hidden -RedirectStandardError "$work\elev.err"
  $null = $p.Handle
  if (-not $p.WaitForExit(30000)) { $p.Kill(); throw 'FALLA: macuahuitld elevado no terminó (¿arrancó?)' }
  $elevErr = Get-Content -Raw "$work\elev.err"
  Must ($null -ne $p.ExitCode -and $p.ExitCode -ne 0 -and $elevErr -match 'does not run elevated') "macuahuitld elevado se niega (salida $($p.ExitCode): $($elevErr.Trim()))"
  Must (-not ((PipeNames) -contains "\\.\pipe\macuahuitl-$runnerSid".ToLowerInvariant())) 'y no creó el pipe del runner'

  # 1) usuario estándar: su núcleo crea el pipe con su SID.
  $u1 = New-E2EUser 'mctlE2Ea'
  $u2 = New-E2EUser 'mctlE2Eb'
  Write-Host "usuarios estándar creados: $($u1.Name) ($($u1.Sid)), $($u2.Name) ($($u2.Sid))"
  $core = Invoke-As $u1 "$bin\macuahuitld.exe" -NoWait
  Must (WaitPipe $u1.Sid $true) "existe el pipe \\.\pipe\macuahuitl-$($u1.Sid) del usuario 1"
  Must (-not ((PipeNames) -contains "\\.\pipe\macuahuitl-$($u2.Sid)".ToLowerInvariant())) 'y no hay pipe del usuario 2'
  $local = Join-Path (ProfileOf $u1) 'AppData\Local\MACUAHUITL'

  # 2) bóveda por stdin (contraseña y confirmación) y estado.
  MctlOk $u1 @('vault', 'create') "$($u1.Vault)`n$($u1.Vault)`n" | Out-Null
  $st = MctlOk $u1 @('vault', 'status')
  Must ($st -match 'unlocked') "vault status del usuario 1: $($st.Trim())"

  # 3) un segundo núcleo del mismo usuario se niega y el primero sigue vivo.
  $r = Invoke-As $u1 "$bin\macuahuitld.exe"
  # Todos envuelven ipc.ErrAlreadyRunning (ipc.err.already_running, o ipc.err.pipe_other_user si Listen no puede abrir el
  # pipe); se aceptan en inglés y en español para no depender del idioma del núcleo.
  Must ($r.Code -ne 0 -and $r.Err -match 'already listening|ya hay un núcleo escuchando|held by another user|lo tiene otro usuario') "un segundo macuahuitld del mismo usuario se niega con ErrAlreadyRunning (salida $($r.Code): $($r.Err.Trim()))"
  Must ((MctlOk $u1 @('vault', 'status')) -match 'unlocked') 'el primer núcleo sigue respondiendo'

  # 4) otro usuario no conecta al pipe ajeno.
  $r = Mctl $u2 @('vault', 'status')
  Must ($r.Code -ne 0 -and $r.Out -notmatch 'unlocked|locked' -and $r.Err -match 'cannot find the file specified') "sin núcleo propio, mctl del usuario 2 falla (su pipe no existe; salida $($r.Code): $($r.Err.Trim()))"
  Must ((MctlOk $u1 @('vault', 'status')) -match 'unlocked') 'y el núcleo del usuario 1 sigue bien'

  # 4b) el usuario 2 abre DIRECTAMENTE el pipe del usuario 1: la DACL lo niega (no un timeout ni «no existe»).
  $probe = "`$c = New-Object System.IO.Pipes.NamedPipeClientStream('.', 'macuahuitl-$($u1.Sid)', 'InOut'); " +
    "try { `$c.Connect(2000); Write-Output 'EXC:ninguna (conectó)' } catch { `$e = `$_.Exception; if (`$e.InnerException) { `$e = `$e.InnerException }; Write-Output ('EXC:' + `$e.GetType().FullName + ': ' + `$e.Message) }"
  $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($probe))
  $r = Invoke-As $u2 "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @('-NoProfile', '-EncodedCommand', $enc)
  Write-Host "excepción del usuario 2 al abrir el pipe del usuario 1: $(($r.Out -split "`n" | Where-Object { $_ -like 'EXC:*' }) -join ' ')"
  Must ($r.Out -match 'EXC:System\.UnauthorizedAccessException') 'el usuario 2 recibe acceso denegado (UnauthorizedAccessException) al abrir el pipe del usuario 1'
  # 4c) PENDIENTE (Backend): mctl no tiene variable de entorno ni bandera para apuntar a otro pipe (ipc.SocketPath solo usa el SID
  # del proceso), así que no se puede hacer que mctl del usuario 2 marque al pipe del usuario 1. 4b cubre lo mismo sin mctl.
  Write-Host 'pendiente: 4c, mctl no ofrece forzar el pipe a dial (Backend); cubierto por 4b'
  # 4d) la auditoría del núcleo del usuario 1 no menciona al usuario 2 (ni su SID): sus intentos nunca llegaron al núcleo.
  $aud = MctlOk $u1 @('audit', 'export')
  Must ($aud.Length -gt 0 -and $aud -notmatch [regex]::Escape($u2.Sid) -and $aud -notmatch [regex]::Escape($u2.Name)) 'la auditoría del usuario 1 no registra nada del usuario 2'
  Must ((MctlOk $u1 @('audit', 'verify')) -match '.') 'y la cadena de auditoría está íntegra'

  # 5) ACL de la carpeta de datos: solo el usuario, SYSTEM y Administradores, por SID.
  $data = Join-Path $local 'data'
  $acl = Get-Acl $data
  $sids = $acl.Access | ForEach-Object { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } | Sort-Object -Unique
  $allowed = @($u1.Sid, 'S-1-5-18', 'S-1-5-32-544')
  $extra = @($sids | Where-Object { $_ -notin $allowed })
  Must ($extra.Count -eq 0 -and $acl.AreAccessRulesProtected -and $u1.Sid -in $sids) "ACL de ${data}: solo el usuario, SYSTEM y Administradores, protegida ($($sids -join ', '))"

  # 6) Patrol contra el simulador SSH (127.0.0.1, puerto alto que elige el sistema).
  $addrFile = "$work\sim.addr"
  $sim = Start-Process "$bin\simserver.exe" -ArgumentList '-transcripts', $Transcripts, '-addrfile', $addrFile -PassThru -WindowStyle Hidden
  $script:procs += $sim
  $hostPort = ''
  for ($i = 0; $i -lt 40 -and $hostPort -notmatch ':\d+$'; $i++) { Start-Sleep -Milliseconds 250; if (Test-Path $addrFile) { $hostPort = (Get-Content -Raw $addrFile).Trim() } }
  Must ($hostPort -match ':\d+$') "el simulador escucha en $hostPort"
  $simHost, $simPort = $hostPort -split ':'
  $cred = (MctlOk $u1 @('cred', 'add', '--label', 'lab', '--user', 'admin') "pw-lab`nen-lab`n").Trim()
  $outs = Join-Path (ProfileOf $u1) 'MACUAHUITL\outputs'
  $null = Invoke-As $u1 "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @('-NoProfile', '-Command', "New-Item -ItemType Directory -Force '$outs'")
  $spec = "$($u1.Work)\job.yaml"
  Set-Content $spec "name: lab`ntargets:`n  - address: $simHost`n    port: $simPort`n    device_id: sw1`ndefault_credential_id: $cred`ncustom_commands: |`n  show version`noutput_dir: '$outs'`nwindow_hours: 1`nschedule:`n  interval_seconds: 1`n  rounds: 2`n"
  $job = (MctlOk $u1 @('job', 'create', '-f', $spec)).Trim()
  $lt = (Mctl $u1 @('job', 'logintest', $job)).Out # sale 1 a propósito: la llave del equipo aún no está aceptada
  $fp = [regex]::Match($lt, 'SHA256:\S+').Value
  Must ($fp -ne '') "logintest da la huella $fp"
  MctlOk $u1 @('job', 'arm', '--accept', $fp, $job) | Out-Null
  $w = MctlOk $u1 @('job', 'watch', $job)
  Must ($w -match 'closed' -and $w -match 'COMPLETED') 'el trabajo de Patrol termina COMPLETED'
  $man = @(Get-ChildItem $outs -Recurse -Filter manifest.json)
  $zip = @(Get-ChildItem $outs -Recurse -Filter *.zip)
  Must ($man.Count -ge 1 -and $zip.Count -ge 1) "hay manifest.json ($($man.Count)) y zip de salida ($($zip.Count)) en $outs"
  Stop-Process -Id $sim.Id -Force

  # 7) core stop: sale 0 y el proceso desaparece.
  $stopOut = MctlOk $u1 @('core', 'stop')
  Must ($core.Proc.WaitForExit(10000)) 'el proceso macuahuitld del usuario 1 ya no existe'
  Must (WaitPipe $u1.Sid $false) 'y el pipe desapareció'

  # 8) instalador real, por usuario: instala y desinstala con /S como el usuario 1; los datos quedan.
  $setup = "$root\setup.exe"; Copy-Item $Installer $setup
  $before = Get-ChildItem $local -Recurse -File | ForEach-Object { "$($_.FullName)|$($_.Length)" } | Sort-Object
  $r = Invoke-As $u1 $setup @('/S')
  Must ($r.Code -eq 0) "el instalador /S como el usuario 1 termina sin error"
  $inst = Join-Path (ProfileOf $u1) 'AppData\Local\Programs\MACUAHUITL'
  foreach ($f in 'macuahuitl.exe', 'macuahuitld.exe', 'mctl.exe', 'uninstall.exe') { Must (Test-Path "$inst\$f") "instalado $f" }
  $r = Invoke-As $u1 "$inst\uninstall.exe" @('/S', "_?=$inst")
  Must ($r.Code -eq 0) 'la desinstalación /S termina sin error'
  Must (-not (Test-Path "$inst\mctl.exe")) 'desinstalado mctl.exe'
  $after = Get-ChildItem $local -Recurse -File | ForEach-Object { "$($_.FullName)|$($_.Length)" } | Sort-Object
  Must ((Test-Path $data) -and -not (Compare-Object $before $after)) 'la desinstalación /S deja %LOCALAPPDATA%\MACUAHUITL intacto'
  Write-Host 'windows-e2e: todo ok'
} catch {
  Write-Host "::error::$($_.Exception.Message)"
  foreach ($f in Get-ChildItem $root -Recurse -Filter *.err -ErrorAction SilentlyContinue) { Write-Host "--- $($f.Name)"; Get-Content $f.FullName }
  if ($u1) { $log = Join-Path (ProfileOf $u1) 'AppData\Local\MACUAHUITL\state\macuahuitld.log'; if (Test-Path $log) { Write-Host '--- macuahuitld.log'; Get-Content $log } }
  throw
} finally {
  foreach ($p in $script:procs) { try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {} }
  Start-Sleep -Seconds 1
  foreach ($u in $script:users) {
    if (-not $u.Sid) { try { $u.Sid = (Get-LocalUser $u.Name).SID.Value } catch {} }
    try { if ($u.Sid) { Get-CimInstance Win32_UserProfile -Filter "SID='$($u.Sid)'" | Remove-CimInstance } } catch { Write-Host "perfil $($u.Name): $_" }
    try { Remove-LocalUser $u.Name } catch { Write-Host "usuario $($u.Name): $_" }
  }
  try { icacls $root /setowner '*S-1-5-32-544' /t /c | Out-Null; icacls $root /grant '*S-1-5-32-544:(OI)(CI)F' /t /c | Out-Null; Remove-Item -Recurse -Force $root } catch { Write-Host "limpieza: $_" }
}
