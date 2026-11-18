; Instalador de MACUAHUITL para Windows (ADR 0012, «Instalador»): NSIS, por usuario y sin administrador (ADR 0004).
; Parte de la plantilla NSIS de Wails v3 (MIT, Lea Anthony; en THIRD_PARTY_LICENSES), reducida a lo que se usa.
; Lo arma deploy/windows/build-installer.sh, que pasa:
;   VERSION  X.Y.Z
;   BIN      carpeta con macuahuitl.exe, macuahuitld.exe, mctl.exe y macuahuitl.ico
;   SRC      raíz del repo (LICENSE, NOTICE, THIRD_PARTY_LICENSES, TRADEMARK.md)
;   OUT      ruta del instalador
;   SIGN     opcional: orden de firma con %1 en lugar del archivo; sin ella no se firma (la beta sale sin firmar)
;   TEST_DELETE_DATA  solo para test-installer.ps1 (nunca en un release): en silencioso la pregunta de datos contesta Sí

Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma

!ifndef VERSION
  !error "falta VERSION (ver deploy/windows/build-installer.sh)"
!endif
!ifndef BIN
  !error "falta BIN (ver deploy/windows/build-installer.sh)"
!endif
!ifndef SRC
  !error "falta SRC (ver deploy/windows/build-installer.sh)"
!endif
!ifndef OUT
  !error "falta OUT (ver deploy/windows/build-installer.sh)"
!endif

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\MACUAHUITL"
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"
!define RUN_VALUE "MACUAHUITL core"
!define DATA_DIR "$LOCALAPPDATA\MACUAHUITL"
!define WV2_CLIENT "Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
!define WV2_URL "https://developer.microsoft.com/microsoft-edge/webview2/consumer/"

!ifdef SIGN
  !finalize `${SIGN}`
  !uninstfinalize `${SIGN}`
!endif

Name "MACUAHUITL"
OutFile "${OUT}"
; Carpeta fija, sin página para elegirla ni /D=: una carpeta fuera del perfil (C:\Tools\…) hereda «Modificar» para Usuarios
; autenticados, y otro usuario local podría reemplazar macuahuitld.exe, que la entrada Run ejecuta como la víctima.
!define FIXED_DIR "$LOCALAPPDATA\Programs\MACUAHUITL"
InstallDir "${FIXED_DIR}"
ShowInstDetails show

VIProductVersion "${VERSION}.0"
VIFileVersion "${VERSION}.0"
VIAddVersionKey /LANG=0 "ProductName" "MACUAHUITL"
VIAddVersionKey /LANG=0 "FileDescription" "MACUAHUITL installer"
VIAddVersionKey /LANG=0 "ProductVersion" "${VERSION}"
VIAddVersionKey /LANG=0 "FileVersion" "${VERSION}"
VIAddVersionKey /LANG=0 "CompanyName" "Os Ordonez"
VIAddVersionKey /LANG=0 "LegalCopyright" "Os Ordonez. Apache-2.0"

!include "MUI2.nsh"
!include "LogicLib.nsh"

!define MUI_ICON "${BIN}\macuahuitl.ico"
!define MUI_UNICON "${BIN}\macuahuitl.ico"
!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_FUNCTION LaunchApp

Var PrevInstall ; carpeta de una instalación anterior (HKCU), vacía si es la primera

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Sin diálogo de idioma: NSIS elige el del sistema si está aquí; si no, el primero (inglés, el canónico).
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Spanish"

LangString SecDesktop ${LANG_ENGLISH} "Desktop shortcut"
LangString SecDesktop ${LANG_SPANISH} "Acceso directo en el escritorio"
; El mismo texto que ui.webview2_missing (internal/i18n/catalog_webview2.go), que la app muestra al abrirse.
LangString WV2Missing ${LANG_ENGLISH} "The Microsoft WebView2 Runtime is not installed on this computer, and MACUAHUITL needs it for its window. Download and install it from ${WV2_URL}, then open MACUAHUITL again."
LangString WV2Missing ${LANG_SPANISH} "En este equipo no está instalado el runtime WebView2 de Microsoft, que MACUAHUITL necesita para su ventana. Descárgalo e instálalo desde ${WV2_URL} y vuelve a abrir MACUAHUITL."
LangString CoreBusy ${LANG_ENGLISH} "MACUAHUITL has work in progress (a Patrol job, a transfer or a capture). Close or cancel what is running in MACUAHUITL and try again. Nothing was changed."
LangString CoreBusy ${LANG_SPANISH} "MACUAHUITL tiene trabajo en curso (un trabajo de Patrol, una transferencia o una captura). Cierra o cancela lo que está corriendo en MACUAHUITL y vuelve a intentarlo. No se cambió nada."
LangString OtherDir ${LANG_ENGLISH} "MACUAHUITL is installed in $PrevInstall. Uninstall it from Settings → Apps and run this installer again; it now always installs in ${FIXED_DIR}. Nothing was changed."
LangString OtherDir ${LANG_SPANISH} "MACUAHUITL está instalado en $PrevInstall. Desinstálalo desde Configuración → Aplicaciones y vuelve a ejecutar este instalador; ahora siempre instala en ${FIXED_DIR}. No se cambió nada."
LangString AppOpen ${LANG_ENGLISH} "MACUAHUITL is open. Close it and try again. Nothing was changed."
LangString AppOpen ${LANG_SPANISH} "MACUAHUITL está abierto. Ciérralo y vuelve a intentarlo. No se cambió nada."
LangString CoreInUse ${LANG_ENGLISH} "$R9 is still running and did not stop. Open Task Manager → Details, end $R9 and choose Retry."
LangString CoreInUse ${LANG_SPANISH} "$R9 sigue corriendo y no se detuvo. Abre el Administrador de tareas → Detalles, finaliza $R9 y elige Reintentar."
LangString Elevated ${LANG_ENGLISH} "The installer is running as administrator. MACUAHUITL installs for your user only and its core refuses to run elevated: close this and open the installer again without «Run as administrator». Continue anyway?"
LangString Elevated ${LANG_SPANISH} "El instalador corre como administrador. MACUAHUITL se instala solo para tu usuario y su núcleo no corre elevado: cierra esto y vuelve a abrir el instalador sin «Ejecutar como administrador». ¿Continuar de todos modos?"
LangString AskData ${LANG_ENGLISH} "Also delete the MACUAHUITL data in $\r$\n${DATA_DIR}?$\r$\n$\r$\nThis includes the vault (saved credentials), the audit log and the settings, and cannot be undone. The outputs folder is never deleted.$\r$\n$\r$\nIf you choose No, everything stays and a new installation will find it."
LangString AskData ${LANG_SPANISH} "¿Borrar también los datos de MACUAHUITL en$\r$\n${DATA_DIR}?$\r$\n$\r$\nIncluye la bóveda (credenciales guardadas), la auditoría y la configuración, y no se puede deshacer. La carpeta de salidas nunca se borra.$\r$\n$\r$\nSi eliges No, todo queda y una instalación nueva lo encuentra."

; IfInUse: si $R9 está vacío y el ejecutable está en uso (abrirlo para escritura falla), deja su nombre en $R9.
!macro IfInUse name
  ${If} $R9 == ""
  ${AndIf} ${FileExists} "$INSTDIR\${name}"
    ClearErrors
    FileOpen $1 "$INSTDIR\${name}" a
    ${If} ${Errors}
      StrCpy $R9 "${name}"
    ${Else}
      FileClose $1
    ${EndIf}
  ${EndIf}
!macroend

LangString DataLeft ${LANG_ENGLISH} "Some MACUAHUITL data could not be deleted (a file in use or without permission). Delete this folder by hand:$\r$\n${DATA_DIR}"
LangString DataLeft ${LANG_SPANISH} "No se pudieron borrar todos los datos de MACUAHUITL (un archivo en uso o sin permiso). Borra a mano esta carpeta:$\r$\n${DATA_DIR}"

; StopCoreAll: antes de reemplazar o borrar los ejecutables (Windows no deja tocar un .exe en uso).
; 1. La app abierta la cierra el usuario: se revisa antes de tocar el núcleo, para que «no se cambió nada» sea cierto.
; 2. `mctl core stop` (contrato con Backend: 0 = el núcleo ya terminó o no corría, 3 = se negó por trabajo vivo), con plazo.
; 3. Hasta 10 s a que el núcleo y mctl dejen de estar en uso; si no, Reintentar o Cancelar (en silencioso, Cancelar).
!macro StopCoreAll un
Function ${un}StopCoreAll
  StrCpy $R9 ""
  !insertmacro IfInUse "macuahuitl.exe"
  ${If} $R9 != ""
    MessageBox MB_ICONSTOP "$(AppOpen)" /SD IDOK
    Abort
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\mctl.exe"
    nsExec::Exec /TIMEOUT=30000 '"$INSTDIR\mctl.exe" core stop'
    Pop $0
    ${If} $0 == 3
      MessageBox MB_ICONSTOP "$(CoreBusy)" /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}
  retry:
  StrCpy $2 0
  ${Do}
    StrCpy $R9 ""
    !insertmacro IfInUse "macuahuitld.exe"
    !insertmacro IfInUse "mctl.exe"
    ${If} $R9 == ""
      Return
    ${EndIf}
    IntOp $2 $2 + 1
    ${IfThen} $2 > 20 ${|} ${ExitDo} ${|}
    Sleep 500
  ${Loop}
  MessageBox MB_RETRYCANCEL|MB_ICONSTOP "$(CoreInUse)" /SD IDCANCEL IDRETRY retry
  Abort
FunctionEnd
!macroend
!insertmacro StopCoreAll ""
!insertmacro StopCoreAll "un."

Function .onInit
  StrCpy $INSTDIR "${FIXED_DIR}" ; pisa un /D= de la línea de comandos
  ReadRegStr $PrevInstall HKCU "${UNINST_KEY}" "InstallLocation"
  ; Una instalación anterior en otra carpeta (cuando se podía elegir): su núcleo seguiría corriendo allá y su entrada Run
  ; quedaría pisada. Se pide desinstalarla antes; no se cambió nada. Si esa carpeta ya no existe (borrada a mano, perfil
  ; movido) no hay núcleo viejo: se sigue, y esta instalación reescribe Run y la clave de desinstalación.
  ${If} $PrevInstall != ""
  ${AndIf} $PrevInstall != "${FIXED_DIR}"
  ${AndIf} ${FileExists} "$PrevInstall\*.*"
    MessageBox MB_OK|MB_ICONEXCLAMATION "$(OtherDir)" /SD IDOK
    SetErrorLevel 3
    Quit
  ${EndIf}
  ; Elevado (clic derecho → Ejecutar como administrador): todo iría al perfil y al HKCU de esa cuenta y lo que la app cree
  ; quedaría con dueño Administradores. En silencioso se sigue (despliegue deliberado; el runner de CI siempre es admin).
  System::Call 'shell32::IsUserAnAdmin() i .r0'
  ${If} $0 = 1
    MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION|MB_DEFBUTTON2 "$(Elevated)" /SD IDOK IDOK elevatedOk
    Abort
    elevatedOk:
  ${EndIf}
FunctionEnd

; La app se abre con el token de la sesión (explorer), no con el del instalador aunque este haya corrido elevado.
Function LaunchApp
  Exec '"$WINDIR\explorer.exe" "$INSTDIR\macuahuitl.exe"'
FunctionEnd

; WebView2: no se empaqueta ni se descarga (ADR 0012, «Instalación del runtime»: su licencia exige indemnizar a Microsoft
; a quien lo redistribuye). Si falta (valor «pv» vacío o 0.0.0.0 en HKLM y en HKCU, método 1 de Microsoft), se avisa al
; final con el enlace oficial, la vía que documenta Microsoft; la app avisa lo mismo al abrirse (ui/webview2_windows.go).
Var WV2Missing
Function WebView2
  StrCpy $WV2Missing 0
  ReadRegStr $0 HKLM "SOFTWARE\WOW6432Node\${WV2_CLIENT}" "pv"
  ${If} $0 != ""
  ${AndIf} $0 != "0.0.0.0"
    Return
  ${EndIf}
  ReadRegStr $0 HKCU "Software\${WV2_CLIENT}" "pv"
  ${If} $0 != ""
  ${AndIf} $0 != "0.0.0.0"
    Return
  ${EndIf}
  StrCpy $WV2Missing 1
FunctionEnd

Section "MACUAHUITL" SecMain
  SectionIn RO
  Call StopCoreAll ; al actualizar, el núcleo de la versión anterior está corriendo
  Call WebView2
  SetOutPath "$INSTDIR"
  File "${BIN}\macuahuitl.exe"
  File "${BIN}\macuahuitld.exe"
  File "${BIN}\mctl.exe"
  File "${BIN}\macuahuitl.ico"
  File "/oname=LICENSE.txt" "${SRC}\LICENSE"
  File "/oname=NOTICE.txt" "${SRC}\NOTICE"
  File "/oname=THIRD_PARTY_LICENSES.txt" "${SRC}\THIRD_PARTY_LICENSES"
  File "${SRC}\TRADEMARK.md"
  CreateShortcut "$SMPROGRAMS\MACUAHUITL.lnk" "$INSTDIR\macuahuitl.exe" "" "$INSTDIR\macuahuitl.ico"
  ; El núcleo arranca al iniciar sesión (ADR 0012 (g)): ruta absoluta, nunca por el PATH.
  WriteRegStr HKCU "${RUN_KEY}" "${RUN_VALUE}" '"$INSTDIR\macuahuitld.exe"'
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "MACUAHUITL"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "Os Ordonez"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\macuahuitl.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  ${If} $WV2Missing = 1
    MessageBox MB_ICONINFORMATION "$(WV2Missing)" /SD IDOK
  ${EndIf}
SectionEnd

Section /o "$(SecDesktop)" SecDesktop
  CreateShortcut "$DESKTOP\MACUAHUITL.lnk" "$INSTDIR\macuahuitl.exe" "" "$INSTDIR\macuahuitl.ico"
SectionEnd

; SafeRemove: borra la ruta que está en la pila sin seguir reparse points. Un junction o symlink se borra como enlace
; (RMDir o Delete sobre el enlace mismo) y nunca se entra en él; una carpeta normal se recorre y se borra. RMDir /r de
; NSIS sí los sigue y borra lo que está del otro lado (lo mostró test-installer.ps1), por eso no se usa con los datos.
; Recursiva: guarda y restaura $R0-$R3 en la pila.
!define FILE_ATTRIBUTE_DIRECTORY 0x10
!define FILE_ATTRIBUTE_REPARSE_POINT 0x400
Function un.SafeRemove
  Exch $R0
  Push $R1
  Push $R2
  Push $R3
  System::Call 'kernel32::GetFileAttributesW(w R0) i .R3'
  ${If} $R3 <> -1 ; -1: no existe o no se puede leer, no se toca
    IntOp $R1 $R3 & ${FILE_ATTRIBUTE_REPARSE_POINT}
    IntOp $R2 $R3 & ${FILE_ATTRIBUTE_DIRECTORY}
    ${If} $R1 <> 0
      ${If} $R2 <> 0
        RMDir "$R0" ; sin /r: quita el junction o el symlink de carpeta, no su destino
      ${Else}
        Delete "$R0"
      ${EndIf}
    ${ElseIf} $R2 <> 0
      FindFirst $R1 $R2 "$R0\*"
      ${DoWhile} $R2 != ""
        ${If} $R2 != "."
        ${AndIf} $R2 != ".."
          Push "$R0\$R2"
          Call un.SafeRemove
        ${EndIf}
        FindNext $R1 $R2
      ${Loop}
      FindClose $R1
      RMDir "$R0"
    ${Else}
      Delete "$R0"
    ${EndIf}
  ${EndIf}
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
FunctionEnd

; Desinstalar quita solo lo que puso el instalador. Los datos (bóveda, auditoría, configuración) se borran solo si el
; usuario dice que sí, con No por omisión, y nunca en modo silencioso (/S). La carpeta de salidas nunca se toca.
Section "Uninstall"
  Call un.StopCoreAll
  DeleteRegValue HKCU "${RUN_KEY}" "${RUN_VALUE}"
  Delete "$SMPROGRAMS\MACUAHUITL.lnk"
  Delete "$DESKTOP\MACUAHUITL.lnk"
  Delete "$INSTDIR\macuahuitl.exe"
  Delete "$INSTDIR\macuahuitld.exe"
  Delete "$INSTDIR\mctl.exe"
  Delete "$INSTDIR\macuahuitl.ico"
  Delete "$INSTDIR\LICENSE.txt"
  Delete "$INSTDIR\NOTICE.txt"
  Delete "$INSTDIR\THIRD_PARTY_LICENSES.txt"
  Delete "$INSTDIR\TRADEMARK.md"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR" ; solo si quedó vacía: nada ajeno que el usuario haya puesto ahí se borra
  DeleteRegKey HKCU "${UNINST_KEY}"
  StrCpy $3 1 ; preguntar por los datos: nunca en silencioso
  ${If} ${Silent}
    StrCpy $3 0
  ${EndIf}
!ifdef TEST_DELETE_DATA ; solo la compilación de test-installer.ps1: en silencioso contesta Sí, para probar el borrado
  StrCpy $3 1
  !define DATA_DEFAULT IDYES
!else
  !define DATA_DEFAULT IDNO
!endif
  ${If} $3 = 1
  ${AndIf} ${FileExists} "${DATA_DIR}\*.*"
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "$(AskData)" /SD ${DATA_DEFAULT} IDNO keepData
    Push "${DATA_DIR}"
    Call un.SafeRemove
    ${If} ${FileExists} "${DATA_DIR}\*.*" ; algo bloqueado o sin permiso: que el usuario lo sepa y lo borre a mano
      MessageBox MB_ICONEXCLAMATION "$(DataLeft)" /SD IDOK
    ${EndIf}
    keepData:
  ${EndIf}
SectionEnd
