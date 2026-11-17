# 43d: pruebas defensivas de entradas hostiles (plan)

Pedido del dueño, prioridad alta. Pruebas en tabla, dentro del repo, que comprueban que el núcleo RECHAZA o neutraliza
cada caso hostil y que nunca lee ni escribe fuera de lo permitido. Corren en el job `windows` (obligatorio) y en Linux.
Si una prueba falla, se arregla en el mismo PR; si el arreglo es grande, en otro. Este documento es solo el plan: la
verdad la dan las pruebas; todo «POSIBLE BUG» está por confirmar leyendo el código, no ejecutándolo.

## Áreas

1. Nombres de archivo que llegan de la red (fileserve: tftp, ftp, scp, sftp, http, lectura y escritura; Field).
2. Carpetas: TOCTOU por junction o symlink, raíces del perfil (HOME distinto del perfil), ACE de Users/Everyone, `\\?\` y UNC.
3. Entorno: LOCALAPPDATA, USERPROFILE, TEMP y HOME vacíos, relativos, UNC o en otra unidad (núcleo y mctl).
4. Texto que se arma en órdenes que el usuario copia: New-NetFirewallRule, icacls, sysctl, nft.
5. Herramientas externas: ping, tracert, nmap, dumpcap solo por ruta absoluta; DLL plantada; opciones de texto sin inyección.
6. Respaldo de bóveda (.mcvault) manipulado.
7. Auditoría: `audit verify` detecta truncado y edición; lo que no, va a THREAT_MODEL.md.
8. (Añadida por Release) Hallazgos de la auditoría de Windows: M1, B1, B2, B3 y la deriva entre el ADR 0012 y el código.

Aclaraciones del código: «Field» es `internal/service/field` (`outFile`, field.go:40-50); el .mcvault es binario
(vault/format.go `parseFile`), no JSON: «JSON truncado» se prueba como archivo truncado en cada offset.
Seams que ya existen: `goos` y `exigeUnidad` (dirs.go:30-33), `finalPath`, `accountHome`, `evalSymlinks`, `homeDir`
(dirs.go), `hintOS`/`fijaWindows(t,"windows")` (firewall.go:25, firewall_test.go), `paths.Resolve(env)` y `winLook(env, exeDir, isFile, bin)`
con `env` inyectable.

## Inventario de lo cubierto

| Área | Caso | Prueba existente (archivo: nombre) | Producción |
|---|---|---|---|
| 1 | `../`, `..\`, ruta con barras, `a/..` | fileserve/recv_test.go: TestSafeName; fuzz_test.go: FuzzSafeName | recv.go:37 SafeName toma el último componente tras `/` o `\` |
| 1 | vacío, espacios en extremos, NUL, controles, Cf/bidi (U+202E, ancho cero, BOM, U+00AD), UTF-8 inválido, >200 bytes, dotfiles | TestSafeName | SafeName |
| 1 | no sobrescribir, enlaces | recv_test.go: TestReceiverNeverOverwrites | sys.OpenNewPrivateIn (O_EXCL) |
| 1 | WRQ TFTP con nombre hostil, rechazos | recv_test.go: TestTFTPWriteRefusals, TestTFTPWrite | tftp.go:109 |
| 1 | `\\?\`, `\\.\`, UNC como valor de ruta (no nombre) | sys/openregular_windows_test.go: TestRutasUNCYDispositivoRechazadas | sys/openregular_windows.go:41 checkPath |
| 1 | lectura: `/`, `\`, `.`, `..`, controles | fuzz_test.go: FuzzParseRequest; dirs_test.go: TestSourceFolder (parcial) | source.go:39 plainName |
| 1 | texto hostil del par en razones/auditoría | textos_del_par_test.go (TFTP RRQ/WRQ, SSH canal) | fileserve live/reason |
| 1 | Field: no abre archivo existente ni enlace | service/field/outfile_test.go: TestOutFileNoSigueEnlacesNiReusaNombres | field.go:40-50 |
| 2 | symlink/junction intercambiado tras validar (recepción y publicación) | dirs_test.go: TestReceiverPinnedAgainstSymlinkSwap, TestSourcePinnedAgainstSymlinkSwap, TestSourceOpenSameFile; sys/private_windows_test.go: TestOpenNewPrivateInRechazaCarpetaCambiadaPorJunction, TestOpenNewNoSigueJunction | dirs.go:135 OpenDir (os.Root + SameFile + checkFinal); source.go:74 |
| 2 | junction intermedia a carpeta negada | dirs_windows_test.go: TestWindowsJunctionIntermediaHaciaCarpetaNegada; dirs_hallazgos_test.go: TestRutaFinalDelHandleEntraEnLaListaNegada, TestSourceOpenAplicaRutaFinal, TestValidateDirAplicaRutaFinal | dirs.go:270 checkFinal |
| 2 | HOME falso/vacío/enlace, perfil real, ocultos | dirs_hallazgos_test.go: TestWindowsHomeFalsoNoAbreElPerfilReal; dirs_winsim_test.go: TestWindowsPerfilRealEsHomeExactoYOcultos; dirs_test.go: TestHomeVacioUsaLaCuentaYSinHomeRechaza, TestHomeSinResolverSigueRechazando; dirs_homelink_test.go | dirs.go:238 homesOf |
| 2 | prefijos `\\?\ \\.\ \??\`, UNC, sin letra de unidad | dirs_windows_test.go: TestWindowsRechazaPrefijosDeDispositivo; dirs_winsim_test.go: TestSinLetraDeUnidad; dirs_hallazgos_test.go: TestPublishUNCNoTocaLaRuta | dirs.go:36 sinLetraDeUnidad |
| 2 | mayúsculas, Temp, AppData, XDG | dirs_winsim_test.go: TestWindowsListaSinDistinguirMayusculas, TestWindowsTempNoDependeDeTMP; dirs_hallazgos_test.go: TestWindowsAppDataDelEntornoEsSensible; dirs_test.go: TestXDG* | dirs.go:67-120 |
| 2 | outputs: relativa, `..`, dueño, permisos, ancestro, HOME, symlink | service/prefs/prefs_test.go: TestOutputsReglasDeValidacion, TestOutputsOtroDuenoSeRechaza, TestOutputsAncestroEscribiblePorOtrosSeRechaza, TestOutputsQueContieneElHomeSeRechaza, TestCargarRevalidaLaCarpetaGuardada…; service/outputs_contrato_test.go | service/outputs.go:59 CheckOutputs |
| 2 | outputs con ACE de otro SID, ancestro, junction | service/prefs/prefs_windows_test.go: TestOutputsConAclLaxaSeRechaza; sys/private_windows_test.go: TestPrivateDirRechazaUsuarios, TestPrivateDirRechazaAncestorEscribibleParaTodos, TestPrivateDirYMkdirPrivateRechazanJunction; service/outputs_windows_msg_test.go; TestRaizDeUnidadEsReservada | sys/private_windows.go:289 PrivateDir |
| 3 | LOCALAPPDATA inválida (vacía, relativa, UNC, `\\?\`, `..`, `C:`) | internal/paths/paths_test.go: TestResolvePathsWindowsSinLocalAppData | paths.go:45, 58 |
| 3 | XDG relativo ignorado | paths_linux_test.go: TestResolvePathsIgnoresRelativeXDG | paths.go:23 |
| 3 | TEMP/TMP de las herramientas | diag/windows_test.go: TestWinChildEnv | diag/winlook.go:86 |
| 4 | regla de firewall: comillas simples, `$()`, acento grave, comillas tipográficas, IP con zona, FTP pasivo, sin ruta | fileserve/firewall_test.go: TestReglaFirewallCitaSimple, TestReglaFirewallWindows, TestNombreReglaUnicoPorServidor, TestIPConZonaNoLlegaAlComando, TestIPv6ConZonaFamiliaIP6, TestReglaFirewallSinRutaNoEmiteRegla, TestReglaFirewallFTPPasivo | firewall.go:29 psq, :38 fwName, :60 |
| 4 | icacls: solo con SID válido y ruta segura | service/outputs_windows_msg_test.go: TestWindowsOutputsErrSinOrdenSiLaRutaNoEsSegura, TestWindowsOutputsErrOrdenConSIDDelUsuario; outputs_test.go: TestSugerenciaChmodSoloConRutaSegura | outputs.go:154 windowsOutputsErr; regex :19-:27 |
| 5 | argv: opciones tipo bandera, `/x` en Windows, filtro tras -f solo en dumpcap | diag/windows_test.go: TestCheckFlagLikeFiltroSoloDumpcap, TestBuildWindowsRechaza, TestBuildWindowsArgv; diag_linux_test.go: TestBuildRejects; review_fixes_linux_test.go: TestStrictNumbersAndInterface; args_ping_test.go | args.go:303 checkFlagLike; :44 target |
| 5 | rutas fijas en Windows, sin PATH, SystemRoot inválida | diag/windows_test.go: TestWinLook | winlook.go:42 winLook; winAbs :14 |
| 5 | interfaz Windows: solo GUID real | windows_test.go: TestWinIfaceName, TestBuildWindowsRechaza | winlook.go:95 |
| 6 | no es respaldo, texto, vacío, truncado, encabezado corto, carpeta, frase mala, tope de entradas, parámetros Argon2 altos, fuzz mutado | vault/backup_test.go: TestOpenBackupArchivoAjeno, TestOpenBackupTopeDeEntradas, TestWriteBackupParametrosTopeAbrir; vault/fuzz_test.go: FuzzOpenBackup; core/respaldo_test.go: TestRespaldoPreviewErrores, TestRespaldoBorraDescifradoAlAplicarYAlCerrar | vault/backup.go:175 OpenBackup; format.go:62 parseFile; PutBatch todo o nada |
| 7 | fila editada, fila borrada, secuencia no contigua | audit/audit_test.go: TestDetectsEditedRow, TestDetectsDeletedRow, TestVerifyRequiresContiguousSeq | audit.go:179 Verify |

## Huecos (sin prueba) y lo que espera el código

Leyenda de ubicación: **[W]** solo Windows (`_windows_test.go`, job windows); **[T]** todos los sistemas; **[S]** simulación de
Windows con `goos`/`fijaWindows`/`exigeUnidad` en Linux; **[L]** solo Linux.

### Área 1: nombres
| # | Caso | Espera por lectura | Ubicación |
|---|---|---|---|
| 1.1 | `C:\x`, `C:x`, `\\?\C:\x`, `\\.\pipe\x`, `\\host\share\x` como nombre de red (escritura) | Neutraliza: SafeName toma lo posterior al último `\` y deja `x`. `C:x` pasa íntegro como nombre válido en SafeName (recv.go:37-45) y solo lo para Windows en `OpenNewPrivateIn` (IsLocal falla por volumen). **POSIBLE BUG**: SafeName no lo rechaza; depende de la API | [T] fileserve/nombres_hostiles_test.go (tabla de SafeName) + [W] la misma tabla contra `create()` real |
| 1.2 | `archivo:flujo` (ADS) | **POSIBLE BUG**: SafeName (recv.go:37-66) acepta `:`; `filepath.IsLocal` de Windows no rechaza `:` en medio de un nombre, así que `OpenNewPrivateIn` (sys/private_windows.go:196-200) crea `archivo` vacío y un flujo oculto. Lectura: `plainName` (source.go:39-50) también lo deja pasar y se podría leer `x:flujo` de un archivo publicado. Esperado: rechazo | [W] + tabla [S] |
| 1.3 | CON/NUL/AUX/COM1/LPT1/PRN/CONIN$, con y sin extensión (`con.txt`, `NUL.`), `COM¹` | Rechazo por `IsLocal` en sys (private_windows.go:197 y openregular_windows.go:43) pero SafeName no lo dice; en Linux se crean sin problema (correcto en Linux). Lectura: `root.OpenFile` depende de la validación de os.Root. Probar rechazo en Windows y que en Linux no haya falso positivo | [W] + [S] |
| 1.4 | Punto final (`a.`, `a..`) | **POSIBLE BUG**: Win32 recorta el punto: `a.` se crea como `a`; SafeName rechaza espacio final pero no punto (recv.go:42-44). Choca con el control de `inFlight` y con `exists` por nombre exacto | [W]+[S] |
| 1.5 | Nombres cortos 8.3 (`PROGRA~1`, `FW~1.BIN`) | Se crean/abren como cualquier otro; el riesgo es B2: el `inFlight` no los reconoce. Ver B2 | [W] |
| 1.6 | Mayúsculas que chocan (`FW.BIN` / `fw.bin`) | CREATE_NEW falla por el segundo (errExists) bien, pero `inFlight` (recv.go:108-111) y `source.hidden` (source.go:52) comparan exacto: se lee el archivo a medias con otra capitalización. **POSIBLE BUG** (ver B2) | [W]+[S] |
| 1.7 | Caracteres reservados de Windows `<>:"|?*` | Win32 los rechaza en CreateFile; probar que falla limpio sin pánico y sin dejar archivo | [W] |
| 1.8 | >255 caracteres | SafeName rechaza >200 BYTES (recv.go:46); falta prueba de límite exacto (200/201, 255 runas multibyte) y de ruta total >MAX_PATH | [T] |
| 1.9 | Unicode de formato/bidi, controles | TestSafeName cubre parte; faltan U+2066-2069, U+200E/F, U+061C, tags U+E0000, C1 (U+0085), U+2028/2029, NUL en mitad. `unicode.Is(Cf)` y `IsControl` los cubren por lectura | [T] |
| 1.10 | Lectura: todos los anteriores por `plainName` (TFTP RRQ, FTP RETR, SCP -f, SFTP open, HTTP GET) | plainName rechaza `/`, `\`, controles (source.go:39); no rechaza `:`, `C:x`, reservados. Por protocolo no hay prueba tabular; hay solo `FuzzParseRequest` | [T] por protocolo, +[W] |
| 1.11 | Field.outFile: `prefix` viene de `filepath.Base(cfg.Path)` (field.go:85); path serie hostil con `:` o `\` | serialcon.validPath (serialcon_windows.go:44) solo acepta COMn; en Linux `validPath` bajo /dev. Probar tabla: nada raro llega a `outFile`; y que `outFile` use `os.OpenFile` (no Root) con carpeta de salidas validada: junction cambiada tras el `MkdirAll` → no hay Root | [T]+[W] service/field |
| 1.12 | Percent-encoding y variantes en HTTP (`%2e%2e%2f`, `%5c`, `..%2f`) | Go decodifica la ruta antes de `plainName`; probar con request real | [T] |

### Área 2: carpetas
| # | Caso | Espera | Ubicación |
|---|---|---|---|
| 2.1 | outputs / salidas de Field y diag: carpeta cambiada por junction o symlink ENTRE `CheckOutputs` y el uso | `CheckOutputs` resuelve y valida, pero `field.outFile` (field.go:40-50) y `diag.Run` (diag.go:112-117, `MkdirAll` + `CreateTemp`) usan rutas, no un Root: **POSIBLE BUG TOCTOU**. Sin prueba | [T] symlink (Linux) + [W] junction |
| 2.2 | HOME ≠ perfil real | Cubierto en fileserve, no en `CheckOutputs` (outputs.go:98-108: `st.Home` viene de USERPROFILE) ni en paths. Prueba: `HOME=D:\x`, perfil real como outputs | [S]+[W] |
| 2.3 | ACE de Users / Everyone en recepción y publicación (no solo outputs) | El destino de fileserve no pasa por `PrivateDir`; el archivo nace privado pero la carpeta puede ser compartida: esperar rechazo o aviso. **POSIBLE BUG** si se espera rechazo (dirs.go no mira ACL) | [W] |
| 2.4 | `\\?\` y UNC en `prefs.outputs` | `CheckOutputs` (outputs.go:59) no tiene `sinLetraDeUnidad`: `\\srv\share\x` pasa `IsAbs`, `EvalSymlinks` y llega a `PrivateDir`/`CreateTemp` (SMB sale de la red y filtra NTLM). **POSIBLE BUG**. `\\?\C:\x` tampoco se compara con la lista reservada (outputs.go:90-107) tal cual | [W]+[S] (sin `exigeUnidad` hay que inyectar seam) |
| 2.5 | `--dir`, `--from`, `--out` de mctl con `\\?\`/UNC | Servidor: `ValidateDir` rechaza (dirs.go:168-170). mctl: ver quién valida `--out` (cmd/mctl/field, transfer, diag); sin prueba | [W] cmd/mctl |
| 2.6 | `ValidateDir` con nombre 8.3 (`PROGRA~1`) de carpeta negada | `evalSymlinks` no expande 8.3 en todos los casos; la ruta final del handle (`checkFinal`) sí. Probar | [W] |
| 2.7 | Carpeta en raíz de unidad, `\\.\`, volumen `\\?\Volume{…}` | dirs.go:197 rechaza raíz; falta volumen GUID | [W] |

### Área 3: entorno
| # | Caso | Espera | Ubicación |
|---|---|---|---|
| 3.1 | Linux: HOME vacío o relativo | **POSIBLE BUG**: paths.go:21-37 hace `filepath.Join(home, ".config", …)`: con HOME vacío salen rutas RELATIVAS (`.config/macuahuitl`, `MACUAHUITL/outputs`) y `macuahuitld` (main.go:103) solo comprueba que no estén vacías. Esperado: rechazo al arrancar | [L]/[T] paths_test.go |
| 3.2 | Windows: USERPROFILE inválida (vacía, relativa, UNC, otra unidad) | paths.go:50 deja Home y Outputs vacíos y NO se rechaza el arranque (main.go:103 solo mira Config/Data/State). Ver qué pasa con `Outputs()==""` en core.go:191 y services.go:276 | [T] |
| 3.3 | LOCALAPPDATA en otra unidad o con 8.3 | winAbs la acepta (es válida); probar que se usa tal cual | [T] |
| 3.4 | TEMP/TMP vacíos, relativos, UNC | winChildEnv (winlook.go:86-103) los reemplaza por LOCALAPPDATA\Temp; sin pruebas de UNC/relativos | [T] |
| 3.5 | `os.TempDir()` / TMPDIR / TEMP relativos en el núcleo (CreateTemp, ProtectNew, tests de CheckOutputs `/tmp`) | no hay prueba; `os.CreateTemp("")` usa TEMP | [W] |
| 3.6 | mctl: XDG_RUNTIME_DIR vacío/relativo | ipc_unix.go:26 rechaza relativa: cubierto en ipc/addr_unix_test.go (verificar) ; en Windows el pipe no usa entorno | [L] |
| 3.7 | `macuahuitld` en Windows con todas las variables vacías | arranca con error claro `harden.err.localappdata` (main.go:103); prueba de proceso | [W] cmd/macuahuitld |

### Área 4: texto copiable
| # | Caso | Espera | Ubicación |
|---|---|---|---|
| 4.1 | Regla: salto de línea (`\n`, `\r`, U+2028, U+0085) en la ruta del ejecutable (psq, firewall.go:29-35) | **POSIBLE BUG**: psq no escapa saltos de línea; en una cadena entre comillas simples, pegada en PowerShell, un `\n` rompe la línea de comando visible (ISE/consola); ruta con `\n` más `;` y otra orden se ve como dos líneas. Esperado: rechazar la ruta (sin regla) o neutralizar | [S] firewall_test.go + [W] |
| 4.2 | Regla: `;`, `&`, `|`, `#`, `%`, `"`, backtick, `$()` dentro de comillas simples | psq neutraliza (TestReglaFirewallCitaSimple cubre `$()`, backtick, `'`). Falta tabla con `;`, `"`, `%`, `\u0000` y bidi | [S] |
| 4.3 | Regla: nombre con IP no IP / hostil | fwName (firewall.go:38) usa `netip.ParseAddr`, si falla `any`: seguro. Probar `ip` con comillas, `$`, saltos | [S] |
| 4.4 | Regla: `exe` con caracteres de formato/bidi | no se rechaza (**POSIBLE BUG** de presentación: la orden mostrada engaña) | [S] |
| 4.5 | `-Program` de rutas UNC o `\\?\` | `exePath()` viene del sistema; probar que no se emite si no es `X:\` (firewall.go:24 comentario dice «relativo» solo) | [S] |
| 4.6 | `fileserve.RedirectCommandIn` nft: IP hostil | redirTarget parsea la IP; `port` int; `nftTable` con `proto` de lista cerrada. Falta tabla | [T] |
| 4.7 | icacls: ruta con `"`, `%`, `^`, `!`, `$`, backtick, saltos, bidi; SID falso | safeCmdPath/regex (outputs.go:19-27) y SID `S-1-` (outputs.go:172). Cubierto en parte; falta tabla completa (saltos de línea, `%`, `^`, bidi) y que la ruta con espacios vaya entre comillas | [T] |
| 4.8 | sysctl: puerto, `low` entero (bind.go:46) | solo enteros; sin entrada de texto. Prueba de que `cmd` solo tiene dígitos | [T] |
| 4.9 | chmod de outputs: `safeShellPath` (outputs.go:22) | cubierto por TestSugerenciaChmodSoloConRutaSegura; falta bidi, saltos, `~`, `\u00a0` | [T] |

### Área 5: herramientas externas
| # | Caso | Espera | Ubicación |
|---|---|---|---|
| 5.1 | cwd: `exec.CommandContext(path, …)` sin `cmd.Dir` (diag.go:260) | **POSIBLE BUG** (endurecimiento): el hijo hereda el cwd del núcleo y busca DLL ahí. Esperado: `cmd.Dir` fijo (SystemRoot\System32 o la carpeta de la herramienta) | [W] |
| 5.2 | DLL plantada en cwd o junto al núcleo (`version.dll`/`wpcap.dll` falsos) | Prueba con un hijo de prueba que intente cargarla; el cwd no debe estar en la ruta de búsqueda; con `SetDllDirectory("")`/`SetDefaultDllDirectories` en el núcleo | [W] |
| 5.3 | DLL en la carpeta de la herramienta (`Nmap\`) | No es nuestro control (quien escribe en ProgramFiles ya es admin); aun así winChildEnv pone esa carpeta en PATH (winlook.go:103); probar que el PATH del hijo no incluye cwd ni `.` | [T] |
| 5.4 | `ping.exe`, `tracert.exe`, `nmap.exe`, `dumpcap.exe` plantados en cwd y en PATH | winLook (winlook.go:42-70) solo mira rutas fijas: probar en Windows REAL con un `ping.exe` en cwd y PATH que `lookPath` no lo devuelva; hoy solo la versión inyectada (TestWinLook) | [W] |
| 5.5 | SystemRoot/ProgramFiles falsos (`C:\evil`) | winAbs solo comprueba forma: `SystemRoot=C:\evil` se acepta (winlook.go:15-31, 42). Decidir: validar contra `GetSystemWindowsDirectory` (API) y no contra el entorno. **POSIBLE BUG** | [W] |
| 5.6 | Linux: `exec.LookPath` con PATH que incluye `.` o relativo | diag/proc_linux.go: ErrDot de Go cubre `.`; probar ruta relativa en PATH | [L] |
| 5.7 | Opciones con texto: interfaz, filtro BPF, hostname, `-` inicial, espacios, saltos, NUL, `--script`, `-oN`, `@`, `=`, `/` inicial, `-f` doble | `checkFlagLike` exime todo lo que sigue a `-f` solo en dumpcap (args.go:303-310): el filtro `-f -w /ruta` pasa como UN argumento, no inyecta. Faltan: hostname `-oN`, `--iflist`, hostname con espacios/saltos/NUL, interfaz con `;`, filtros con comillas | [T] diag/args |
| 5.8 | Que `argv` nunca pase por shell | `exec.Command` directo (no cmd.exe): probar que `ping` con `a&b` no ejecuta; en Windows `cmd`/`.bat` desde `exec` (CVE-2024-24576, nombres `.bat`) no aplica a .exe | [W] |

### Área 6: respaldo
| # | Caso | Espera | Ubicación |
|---|---|---|---|
| 6.1 | Versión de formato desconocida | parseFile (format.go:70) la rechaza como `corrupt` → ErrNotBackup. Sin prueba específica; tabla de versión 0, 2, 65535 | [T] vault/backup_hostil_test.go |
| 6.2 | Longitudes enormes: `n` de entradas, `l` de cada una (format.go:86-101) | `uint64(n)*minEntryLen > len(rest)` y `l > len(rest)` las rechazan; probar `n=0xFFFFFFFF`, `l=0xFFFFFFFF`, y que no se reserve memoria | [T] |
| 6.3 | Campos enormes dentro del cifrado (label/usuario/clave de 10 MB; 10000 entradas) | Tope de archivo 64 MiB (backup.go:46) y de entradas 10000; falta tope por campo al importar: **POSIBLE BUG** si `Put` valida largo y `OpenBackup` no (importar rompe a medias) | [T] core/respaldo + vault |
| 6.4 | Clave privada SSH inválida / truncada / de otro tipo / con comentario enorme | `ApplyBackupImport` (core/respaldo.go:337…) usa `PutBatch` todo o nada; falta prueba de que una privada inválida falla limpio y deja la bóveda intacta (hash del archivo igual antes/después) | [T] core |
| 6.5 | Pánico: truncado en CADA offset; magic ok con cola basura; AAD alterado (id de bóveda cambiado) | FuzzOpenBackup lo cubre aleatoriamente; falta tabla determinista exhaustiva en CI (el fuzz no corre en CI normal) | [T] |
| 6.6 | Bóveda a medias | tras fallo en `ApplyBackupImport`: `vault.mcv` byte a byte igual y sin `.tmp` sobrante | [T]+[W] (rename y bloqueo de archivo) |
| 6.7 | Ruta del respaldo: FIFO, enlace, UNC, `\\.\pipe\x`, `CON` | `sys.OpenRegular` + `AbsPathReason`; faltan UNC y dispositivos en Windows (checkPath cubre en parte) | [W] |

### Área 7: auditoría
| # | Caso | Espera | Ubicación |
|---|---|---|---|
| 7.1 | Truncar las últimas N filas | **POSIBLE BUG / límite**: `Verify` (audit.go:179-193) valida la cadena contigua desde 1; un truncado de COLA deja una cadena válida y `Intact=true`. Solo se detecta si se compara `Head` con un ancla externa (manifest). Prueba: debe detectarse al comparar con el último `Head` anclado; documentar en THREAT_MODEL | [T] audit_test.go |
| 7.2 | Truncar el principio (borrar las primeras) | `r.Seq != next` (audit.go:182): detecta | [T] |
| 7.3 | Editar prev/hash a la vez y recalcular toda la cadena | no se detecta: sin clave. Documentar | doc |
| 7.4 | Duplicar una fila, reordenar, insertar con seq duplicada, seq/at NULL o tipo equivocado | debe fallar limpio; probar | [T] |
| 7.5 | Fila cuyo `at` tiene otro formato, texto no UTF-8, entrada enorme | sin pánico | [T] |
| 7.6 | Borrar la DB entera o restaurar una anterior | no se detecta; THREAT_MODEL.md (punto 4 ya lo insinúa, línea 49): ampliar con borrado total, rollback de DB, truncado de cola y reinicio de `seq` | doc |
| 7.7 | Los triggers `audit_log_no_update/no_delete` | los hay; con acceso al archivo SQLite se saltan (`DROP TRIGGER` en la prueba). Documentar | doc |

### Área 8: hallazgos de la auditoría de Windows (Release)
| # | Hallazgo | Dónde (archivo:línea) | Esperado / arreglo | Prueba |
|---|---|---|---|---|
| M1 (medio) | El cliente no verifica el NIVEL DE INTEGRIDAD del servidor del pipe: un proceso Low IL del mismo usuario puede crear `macuahuitl-<SID>` antes que el núcleo y recibir la contraseña maestra | internal/ipc/ipc_windows.go:154-180 `dialPipe` (usa `pipeOwner` + `pidSID`); internal/ipc/sidcheck.go:18-23 `checkServer` | Exigir TokenIntegrityLevel del servidor ≥ el del cliente; rechazar AppContainer (`TokenIsAppContainer`) y tokens restringidos (`TokenIsRestricted`); o leer la etiqueta obligatoria del pipe (LABEL_SECURITY_INFORMATION). Función de decisión pura (`checkServer` amplía con nivel/flags) | Unitaria en `sidcheck_test.go` (todas las plataformas) con tabla de decisión; `_windows_test.go` con hijo de token rebajado (`CreateRestrictedToken` + `SetTokenInformation(TokenIntegrityLevel)`) si la API lo permite en CI. La confirmación en VM es manual y se anota en el PR |
| B1 (bajo) | Los archivos recibidos no llevan Mark of the Web | internal/diag/fileserve/recv.go:149 (`OpenNewPrivateIn`) y :218 `commit`; internal/diag/transfer/transfer.go:212 | En Windows, al confirmar, escribir `<archivo>:Zone.Identifier` con `[ZoneTransfer]\r\nZoneId=3`. Nota: choca con el rechazo de `:` en nombres (1.2); es un nombre interno, no del par; escribirlo con `CreateFile` directo, sin pasar por SafeName. En FAT/exFAT falla sin error fatal | [W] en fileserve y transfer; [T] que un nombre de par con `:` sigue rechazado |
| B2 (bajo) | `inFlight` compara el nombre exacto: mientras se sube `FW.BIN`, `fw.bin` o `FW~1.BIN` sirven un archivo truncado | recv.go:108-111 `writing`, recv.go:147-148 (marca), source.go:52-54 `hidden` | `os.SameFile` contra los archivos en recepción, o recibir con nombre temporal y renombrar al final (sys.RenameNoReplaceIn ya existe: openregular_windows.go:61) | [W]: subir `FW.BIN` a medias y leer `fw.bin` y `FW~1.BIN` (debe dar «no publicado»); [S] solo cubre mayúsculas |
| B3 (bajo) | Faltan como carpetas prohibidas los perfiles de PowerShell | dirs.go:65-92 (`windowsSensitiveDirs`, `denyList`; solo `<home>\AppData` en :88-90) | Añadir `<home>\Documents\WindowsPowerShell`, `<home>\Documents\PowerShell`, y revisar OneDrive (`<home>\OneDrive\Documents\…`, `Documents` redirigida por KFM). Startup ya queda cubierto por AppData (`…\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`) y por ProgramData (:70, entorno `ProgramData`), pero hay que probarlo; falta también `<home>\Documents\Windows PowerShell`-equivalentes y `%ALLUSERSPROFILE%` = ProgramData ya incluido | [S] tabla en dirs_winsim_test.go + [W] |
| ADR-1 | `SetErrorMode(SEM_NOGPFAULTERRORBOX)` no se llama | ADR 0012 línea 67; internal/sys/harden_windows.go:55-64 (`NoDump`, `werExclude`) no lo llama | Código: llamar `windows.SetErrorMode(SEM_NOGPFAULTERRORBOX\|SEM_FAILCRITICALERRORS)` al principio de `Harden` | [W] `GetErrorMode`/`SetErrorMode` devuelve el valor previo con el bit puesto |
| ADR-2 | `pagefileWarnings` avisa sin mirar el cifrado (`EncryptPagingFile`, BitLocker) | ADR 0012 línea 69; internal/sys/harden.go:44-58; harden_windows.go:98-109 (`readPagingFiles`) | Corregir el código si es barato (`EncryptPagingFile` en `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`, DWORD; si 1 no avisa); BitLocker sin admin no se puede leer fiablemente: corregir el ADR a «avisa si EncryptPagingFile=0; BitLocker no se comprueba» | Tabla en `harden_test.go` ([T]) |
| ADR-3 | ADR (g) dice que «la app y mctl lo lanzan bajo demanda»; mctl no lo hace | ADR 0012 línea 121; `sys.StartDetached` solo lo usan ui/corestart_windows.go:33 y ui/bridge/corelaunch.go:16; cmd/mctl no lo llama | Corregir el ADR: solo la app lanza el núcleo; mctl avisa que el núcleo no corre y cómo iniciarlo. (Cambiar el código sería añadir superficie: mctl es de scripts.) | Prueba de mctl [W]: sin núcleo, el error dice cómo iniciarlo y NO lanza proceso |
| ADR-4 | Texto sobre `FILE_FLAG_FIRST_PIPE_INSTANCE` | ADR 0012 líneas 45 y 55 y 58; el código (ipc_windows.go:18-19 y :55) usa `FILE_CREATE` con NtCreateNamedPipeFile (go-winio), equivalente | Corregir el ADR: nombrar el mecanismo real y que la prueba lo confirma | Ya cubierto en ipc_windows_test.go (verificar que el segundo núcleo falla); solo documentación |

## POSIBLE BUG para arreglar (ordenados)

1. 1.2 ADS en nombres de red (escritura y lectura): recv.go:37-66 SafeName y source.go:39-50 plainName. Arreglo: una función común `winName` que rechaza `:` (y `<>"|?*`) en todos los sistemas, o solo en Windows con el seam `goos`. Mejor en todos: ningún equipo legítimo manda `:` en un nombre.
2. 1.4 punto final y 1.6/B2 mayúsculas y 8.3 (recv.go:108-111, source.go:52-54).
3. 2.4 UNC y `\\?\` en `prefs.outputs` y rutas de salidas (service/outputs.go:59-76, sin `sinLetraDeUnidad`).
4. 3.1 HOME vacío o relativo en Linux (paths/paths.go:21-37) y 3.2 USERPROFILE inválida en Windows sin rechazar el arranque (main.go:103).
5. 4.1 saltos de línea en la ruta de la regla de firewall (fileserve/firewall.go:29-35).
6. 5.1/5.2 cwd del hijo sin fijar (diag/diag.go:260) y SystemRoot de entorno sin validar (diag/winlook.go:42-70).
7. 2.1 TOCTOU en salidas de Field y diag (field.go:40-50, diag.go:112-117).
8. 7.1 truncado de cola no se detecta sin ancla (audit/audit.go:179-193): documentar; el arreglo (ancla en la UI/mctl) es mayor.
9. M1, B1, B3 y ADR-1..4 de la sección 8.
10. 2.3 ACE de Users en la carpeta de recepción/publicación (a confirmar si se rechaza o solo se avisa; decisión del dueño).

## Bloques

Cada bloque es un PR chico, con `./dev.sh test` verde y el job windows. Las pruebas de la lista de huecos se escriben PRIMERO (rojas) y se corrige.

- **43d-1 Nombres de red** (área 1; 1.1-1.12, B1, B2). Archivos: fileserve/nombres_hostiles_test.go [T], nombres_hostiles_windows_test.go [W], tabla por protocolo (tftp, ftp, scp, sftp, http; lectura y escritura) reutilizando los helpers de recv_test/ssh_test; service/field/outfile_hostil_test.go; arreglo común en un solo `winName`. Incluye B1 (Zone.Identifier) y B2.
- **43d-2 Carpetas y entorno** (áreas 2 y 3; 2.1-2.7, 3.1-3.7, B3). Archivos: fileserve/dirs_hostiles_winsim_test.go [S], dirs_hostiles_windows_test.go [W]; service/outputs_hostiles_test.go, service/prefs/prefs_windows_test.go (UNC, `\\?\`, ACE de Everyone); paths/paths_test.go y paths_linux_test.go; cmd/macuahuitld/main_windows_test.go (entorno vacío); cmd/mctl (`--dir`, `--from`, `--out`).
- **43d-3 Órdenes copiables y herramientas** (áreas 4 y 5; 4.1-4.9, 5.1-5.8). Archivos: fileserve/firewall_hostil_test.go [S]; service/outputs_windows_msg_test.go (tabla icacls); diag/args_hostil_test.go [T]; diag/herramientas_windows_test.go [W] (ping.exe/DLL plantados en cwd y PATH); diag/listen/bind_test.go (sysctl).
- **43d-4 .mcvault y auditoría** (áreas 6 y 7). Archivos: vault/backup_hostil_test.go [T] (offsets, versión, longitudes, campos enormes), core/respaldo_hostil_test.go (privada inválida y bóveda intacta), audit/audit_hostil_test.go [T] (cola, cabeza, duplicados, tipos), docs/security/THREAT_MODEL.md (límites: DB borrada, rollback, truncado de cola, reescritura completa de la cadena, triggers salteables).
- **43d-5 Auditoría Windows** (área 8). M1 (ipc: nivel de integridad; arreglo PROPIO, no solo prueba), ADR-1 (SetErrorMode), ADR-2 (EncryptPagingFile), ADR-3 y ADR-4 (texto del ADR 0012). Archivos: ipc/sidcheck_test.go, ipc/ipc_windows_test.go, sys/harden_test.go, sys/harden_windows_test.go, docs/adr/0012-multiplataforma.md. M1 sin confirmación en VM: anotarlo en el PR como manual.

Orden sugerido: 43d-1 → 43d-2 → 43d-3 → 43d-4 → 43d-5 (M1 puede ir antes si el dueño lo prefiere: es el único medio).

## Review Focus

- Que cada prueba de la tabla falle ANTES del arreglo (rojo primero) y que «rechaza» sea el error esperado, no cualquier error.
- Que las pruebas [S] no den falsa seguridad: la simulación usa rutas del anfitrión; lo que dependa de la API real (IsLocal, ADS, 8.3, junction, DLL, ACL) debe tener su gemela [W] corriendo en el job windows.
- ADS y reservados: confirmar con la API real de Windows lo que SafeName/IsLocal dejan pasar; no suponer.
- Que `winName` no rompa nombres legítimos en Linux ni rechace Unicode normal (ñ, acentos, CJK).
- B1: que escribir Zone.Identifier no reabra el hueco de ADS (nombre interno, nunca del par) y no falle en FAT.
- B2: la solución elegida (SameFile vs nombre temporal) no debe cambiar el comportamiento visible de «no publicado» ni la cuenta de topes (`files`, `total`).
- M1: la decisión de integridad falla cerrado (no se puede leer → rechaza) y no rompe un núcleo lanzado con otro token legítimo (elevado vs no elevado: solo se exige ≥ al del cliente; un núcleo normal con cliente elevado puede quedar rechazado: decidirlo).
- Que ningún arreglo toque el comportamiento de Linux sin prueba.
- Que lo que no se detecta en auditoría quede escrito en THREAT_MODEL.md, en inglés (el idioma del documento).
- Pruebas con tiempos o carga: una suite a la vez, `-p 2`, `GOMAXPROCS=4`.
