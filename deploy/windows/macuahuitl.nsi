; Instalador de MACUAHUITL para Windows (ADR 0012, «Instalador»): NSIS, por usuario y sin administrador (ADR 0004).
; Parte de la plantilla NSIS de Wails v3 (MIT, Lea Anthony; en THIRD_PARTY_LICENSES), reducida a lo que se usa.
; Lo arma deploy/windows/build-installer.sh, que pasa:
;   VERSION  X.Y.Z
;   BIN      carpeta con macuahuitl.exe, macuahuitld.exe, mctl.exe, macuahuitl.ico y MicrosoftEdgeWebview2Setup.exe
;   SRC      raíz del repo (LICENSE, NOTICE, THIRD_PARTY_LICENSES, TRADEMARK.md)
;   OUT      ruta del instalador
;   SIGN     opcional: orden de firma con %1 en lugar del archivo; sin ella no se firma (la beta sale sin firmar)

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

!ifdef SIGN
  !finalize `${SIGN}`
  !uninstfinalize `${SIGN}`
!endif

Name "MACUAHUITL"
OutFile "${OUT}"
InstallDir "$LOCALAPPDATA\Programs\MACUAHUITL"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
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
!define MUI_FINISHPAGE_RUN "$INSTDIR\macuahuitl.exe"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Sin diálogo de idioma: NSIS elige el del sistema si está aquí; si no, el primero (inglés, el canónico).
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "Spanish"

LangString SecDesktop ${LANG_ENGLISH} "Desktop shortcut"
LangString SecDesktop ${LANG_SPANISH} "Acceso directo en el escritorio"
LangString WV2Installing ${LANG_ENGLISH} "Installing the Microsoft WebView2 Runtime…"
LangString WV2Installing ${LANG_SPANISH} "Instalando el runtime WebView2 de Microsoft…"
LangString WV2Failed ${LANG_ENGLISH} "The Microsoft WebView2 Runtime could not be installed (it needs an internet connection). MACUAHUITL will be installed anyway; when it opens, it shows the official download link."
LangString WV2Failed ${LANG_SPANISH} "No se pudo instalar el runtime WebView2 de Microsoft (necesita conexión a internet). MACUAHUITL se instala de todos modos; al abrirlo muestra el enlace oficial de descarga."
LangString CoreBusy ${LANG_ENGLISH} "MACUAHUITL has work in progress (a Patrol job, a transfer or a capture). Close or cancel what is running in MACUAHUITL and try again. Nothing was changed."
LangString CoreBusy ${LANG_SPANISH} "MACUAHUITL tiene trabajo en curso (un trabajo de Patrol, una transferencia o una captura). Cierra o cancela lo que está corriendo en MACUAHUITL y vuelve a intentarlo. No se cambió nada."
LangString InUse ${LANG_ENGLISH} "$R9 is still running. Close MACUAHUITL (or sign out of Windows) and try again. Nothing was changed."
LangString InUse ${LANG_SPANISH} "$R9 sigue abierto. Cierra MACUAHUITL (o cierra la sesión de Windows) y vuelve a intentarlo. No se cambió nada."
LangString AskData ${LANG_ENGLISH} "Also delete the MACUAHUITL data in $\r$\n${DATA_DIR}?$\r$\n$\r$\nThis includes the vault (saved credentials), the audit log and the settings, and cannot be undone. The outputs folder is never deleted.$\r$\n$\r$\nIf you choose No, everything stays and a new installation will find it."
LangString AskData ${LANG_SPANISH} "¿Borrar también los datos de MACUAHUITL en$\r$\n${DATA_DIR}?$\r$\n$\r$\nIncluye la bóveda (credenciales guardadas), la auditoría y la configuración, y no se puede deshacer. La carpeta de salidas nunca se borra.$\r$\n$\r$\nSi eliges No, todo queda y una instalación nueva lo encuentra."

; InUse: $R9 = nombre del ejecutable. Abrir para escritura falla si el archivo está en uso.
!macro InUseCheck name
  StrCpy $R9 "${name}"
  ${If} ${FileExists} "$INSTDIR\${name}"
    ClearErrors
    FileOpen $1 "$INSTDIR\${name}" a
    ${If} ${Errors}
      MessageBox MB_ICONSTOP "$(InUse)" /SD IDOK
      Abort
    ${EndIf}
    FileClose $1
  ${EndIf}
!macroend

; StopCoreAll: antes de reemplazar o borrar los ejecutables (Windows no deja tocar un .exe en uso). Pide al núcleo que
; se detenga con `mctl core stop` (0 = detenido o no corría, 3 = se negó por trabajo vivo) y luego comprueba que ningún
; ejecutable siga en uso. Si algo sigue en uso, se detiene sin cambiar nada.
!macro StopCoreAll un
Function ${un}StopCoreAll
  ${If} ${FileExists} "$INSTDIR\mctl.exe"
    nsExec::Exec '"$INSTDIR\mctl.exe" core stop'
    Pop $0
    ${If} $0 == 3
      MessageBox MB_ICONSTOP "$(CoreBusy)" /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}
  !insertmacro InUseCheck "macuahuitl.exe"
  !insertmacro InUseCheck "macuahuitld.exe"
  !insertmacro InUseCheck "mctl.exe"
FunctionEnd
!macroend
!insertmacro StopCoreAll ""
!insertmacro StopCoreAll "un."

; WebView2: solo si falta (valor «pv» vacío o 0.0.0.0 en HKLM y en HKCU, método 1 de Microsoft). Sin elevar, el
; bootstrapper instala por usuario. Si falla (sin internet), se sigue: la app avisa con el enlace (ui/webview2_windows.go).
Function WebView2
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
  DetailPrint "$(WV2Installing)"
  InitPluginsDir
  File "/oname=$PLUGINSDIR\MicrosoftEdgeWebview2Setup.exe" "${BIN}\MicrosoftEdgeWebview2Setup.exe"
  ExecWait '"$PLUGINSDIR\MicrosoftEdgeWebview2Setup.exe" /silent /install' $0
  ${If} $0 != 0
    MessageBox MB_ICONEXCLAMATION "$(WV2Failed)" /SD IDOK
  ${EndIf}
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
SectionEnd

Section /o "$(SecDesktop)" SecDesktop
  CreateShortcut "$DESKTOP\MACUAHUITL.lnk" "$INSTDIR\macuahuitl.exe" "" "$INSTDIR\macuahuitl.ico"
SectionEnd

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
  ${IfNot} ${Silent}
  ${AndIf} ${FileExists} "${DATA_DIR}\*.*"
    MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "$(AskData)" /SD IDNO IDNO keepData
    RMDir /r "${DATA_DIR}"
    keepData:
  ${EndIf}
SectionEnd
