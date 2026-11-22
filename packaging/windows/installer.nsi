; Homograph Guard installer (NSIS 3).  Built by packaging/windows/build.ps1:
;   makensis /DVERSION=1.3.0 /DSRCDIR=<PyInstaller output> /DOUTFILE=<setup.exe> installer.nsi
;
; Per-user by default: no administrator rights needed, everything goes to
;   %LOCALAPPDATA%\Programs\HomographGuard  (programs)   and  %LOCALAPPDATA%\HomographGuard  (your data)
; Only the optional firewall rules ask for administrator rights (one UAC prompt).
;
; Silent install:   HomographGuard-Setup.exe /S [/FIREWALL] [/NOSHORTCUTS] [/NOEXTENSION] [/NOUPDATES] [/D=C:\path]
; Silent uninstall: Uninstall.exe /S [/PURGE]   (/PURGE also deletes your lists and the threat database)
;
; Interruptions (power cut, shutdown, a restart forced by Windows Update or a firmware update):
; * The new version is unpacked next to the installed one and swapped in with two folder renames,
;   each atomic, so the program folder always holds a complete version, old or new.
; * Every step can be repeated, so running Setup again finishes an interrupted installation;
;   "InstallState" in HKCU\Software\HomographGuard says whether the last one completed (the app
;   shows a reminder). Nothing is registered to start Setup by itself: antivirus engines rightly
;   treat self-restarting installers as persistence (Defender: Behavior:Win32/Persistence.A!ml).
; * The threat database download is resumable: feeds are saved one transaction at a time and the
;   daily task, created before the first download, finishes whatever is missing (after sign-in,
;   then hourly).

Unicode true
ManifestDPIAware true
!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"
!include "Sections.nsh"
!include "WinMessages.nsh"

!ifndef VERSION
  !error "pass /DVERSION=x.y.z"
!endif
!ifndef SRCDIR
  !error "pass /DSRCDIR=<folder with HomographGuard.exe>"
!endif
!ifndef OUTFILE
  !define OUTFILE "HomographGuard-Setup-${VERSION}.exe"
!endif
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\HomographGuard"
!define APP_KEY "Software\HomographGuard"

Name "Homograph Guard"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\HomographGuard"
InstallDirRegKey HKCU "${APP_KEY}" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "Homograph Guard ${VERSION}"
ShowInstDetails show
ShowUninstDetails show
VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "Homograph Guard"
VIAddVersionKey "CompanyName" "Homograph Guard"
VIAddVersionKey "FileDescription" "Homograph Guard setup"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "MIT License"

!define MUI_ICON "app.ico"
!define MUI_UNICON "app.ico"
!define MUI_ABORTWARNING
!define MUI_COMPONENTSPAGE_SMALLDESC
!define MUI_WELCOMEPAGE_TEXT "Homograph Guard checks the links in your emails, chats and web pages for phishing.$\r$\n$\r$\nIt keeps a threat database and your own allow and block lists on this computer. Checking a link never sends it anywhere.$\r$\n$\r$\nNo administrator rights are needed unless you choose the firewall rules."
!define MUI_DIRECTORYPAGE_TEXT_TOP "Choose a new or empty folder, or the one Homograph Guard is already in. Updates replace this whole folder in one step, so an interrupted update never leaves a half-installed copy."
!define MUI_FINISHPAGE_RUN "$INSTDIR\HomographGuard.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Open Homograph Guard"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\extension-setup.html"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "Show how to add the browser extension"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "${SRCDIR}\LICENSE.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Homograph Guard" SecApp
  SectionIn RO
  Call CheckFolder
  WriteRegStr HKCU "${APP_KEY}" "InstallState" "incomplete"
  Call StopRunningCopies
  Call RestoreInterruptedSwap
  ; Unpack next to the installed version, then swap the folders (see SwapInNewVersion).
  DetailPrint "Unpacking Homograph Guard ${VERSION}..."
  RMDir /r "$INSTDIR.new"
  SetOutPath "$INSTDIR.new"
  File /r "${SRCDIR}\*.*"
  WriteUninstaller "$INSTDIR.new\Uninstall.exe"
  SetOutPath "$TEMP"  ; the installer must not hold either folder open while they are renamed
  Call SwapInNewVersion
  SetOutPath "$INSTDIR"
  WriteRegStr HKCU "${APP_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${APP_KEY}" "Version" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "Homograph Guard"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "Homograph Guard"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\HomographGuard.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\Uninstall.exe" /S'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" $0
SectionEnd

Section "Shortcuts (Start menu and desktop)" SecShortcuts
  CreateDirectory "$SMPROGRAMS\Homograph Guard"
  CreateShortcut "$SMPROGRAMS\Homograph Guard\Homograph Guard.lnk" "$INSTDIR\HomographGuard.exe"
  CreateShortcut "$SMPROGRAMS\Homograph Guard\Add the browser extension.lnk" "$INSTDIR\extension-setup.html"
  CreateShortcut "$SMPROGRAMS\Homograph Guard\Uninstall Homograph Guard.lnk" "$INSTDIR\Uninstall.exe"
  CreateShortcut "$DESKTOP\Homograph Guard.lnk" "$INSTDIR\HomographGuard.exe"
SectionEnd

Section "Browser extension helper (Edge, Chrome, Brave, Firefox)" SecExtension
  DetailPrint "Registering the browser helper with Edge, Chrome, Brave and Firefox..."
  nsExec::ExecToLog '"$INSTDIR\homograph-guard.exe" native-host install'
  Pop $0
SectionEnd

Section "Daily threat-database updates" SecUpdates
  DetailPrint "Creating the daily update task..."
  nsExec::ExecToLog '"$INSTDIR\homograph-guard.exe" setup schedule install'
  Pop $0
  DetailPrint "Downloading the threat database (public phishing and malware lists)..."
  ExecWait '"$INSTDIR\hg-update.exe" --now' $0
  ${If} $0 != 0
    DetailPrint "The download did not complete; the daily task finishes it (after you sign in, then hourly)."
  ${EndIf}
SectionEnd

Section /o "Firewall rules (asks for administrator rights)" SecFirewall
  DetailPrint "Adding Windows Firewall rules for Homograph Guard's programs (administrator approval needed)..."
  ExecShellWait "runas" "$INSTDIR\homograph-guard.exe" 'setup firewall install --install-dir "$INSTDIR"' SW_HIDE
  WriteRegStr HKCU "${APP_KEY}" "Firewall" "1"
SectionEnd

Section "-Finish"
  WriteRegStr HKCU "${APP_KEY}" "InstallState" "complete"
SectionEnd

LangString DESC_App ${LANG_ENGLISH} "The desktop app, the command-line tool, the browser helper and the updater."
LangString DESC_Shortcuts ${LANG_ENGLISH} "Start menu and desktop shortcuts."
LangString DESC_Extension ${LANG_ENGLISH} "Lets the browser extension use the threat database and your lists on this computer. The extension itself is added in the browser (a guide opens at the end)."
LangString DESC_Updates ${LANG_ENGLISH} "Downloads public phishing and malware lists once a day, and finishes interrupted downloads on its own. Nothing about your browsing is sent."
LangString DESC_Firewall ${LANG_ENGLISH} "Blocks inbound connections to Homograph Guard and limits its programs to the DNS resolvers and HTTPS feed downloads."
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecApp} $(DESC_App)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecShortcuts} $(DESC_Shortcuts)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecExtension} $(DESC_Extension)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecUpdates} $(DESC_Updates)
  !insertmacro MUI_DESCRIPTION_TEXT ${SecFirewall} $(DESC_Firewall)
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ------------------------------------------------------------------ interruption-safe installation
Function .onVerifyInstDir
  ; Updates swap whole folders, so never accept a folder that holds other programs or files.
  ${DirState} "$INSTDIR" $R9
  ${If} $R9 == 1
  ${AndIfNot} ${FileExists} "$INSTDIR\HomographGuard.exe"
    Abort
  ${EndIf}
FunctionEnd

Function CheckFolder
  ; The same rule for silent installs (/D=...), which do not show the folder page.
  ${DirState} "$INSTDIR" $R9
  ${If} $R9 == 1
  ${AndIfNot} ${FileExists} "$INSTDIR\HomographGuard.exe"
    MessageBox MB_OK|MB_ICONSTOP "$INSTDIR already contains other files. Choose a new or empty folder." /SD IDOK
    Abort "Choose a new or empty folder."
  ${EndIf}
FunctionEnd

Function StopRunningCopies
  ; Files that are running cannot be replaced. The window is asked to close; the background
  ; helpers are stopped (the browser extension reconnects to the new helper by itself).
  FindWindow $R1 "TkTopLevel" "Homograph Guard"
  ${If} $R1 <> 0
    MessageBox MB_OKCANCEL|MB_ICONINFORMATION "Homograph Guard is open. Setup will close it to install version ${VERSION}." /SD IDOK IDOK +2
    Abort "Installation cancelled: Homograph Guard is still open."
    SendMessage $R1 ${WM_CLOSE} 0 0
    Sleep 1500
    nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM HomographGuard.exe'
    Pop $0
  ${EndIf}
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM hg-update.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM hg-native-host.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM homograph-guard.exe'
  Pop $0
FunctionEnd

Function RestoreInterruptedSwap
  ; An earlier run stopped between the two renames: put the previous version back first.
  ${IfNot} ${FileExists} "$INSTDIR\HomographGuard.exe"
  ${AndIf} ${FileExists} "$INSTDIR.old\HomographGuard.exe"
    DetailPrint "Restoring the version that an interrupted update had set aside..."
    RMDir "$INSTDIR"  ; only if empty: never delete files that are not ours
    Rename "$INSTDIR.old" "$INSTDIR"
  ${EndIf}
FunctionEnd

Function SwapInNewVersion
  ; Two renames, each atomic on NTFS: installed -> .old, new -> installed. Whenever the computer
  ; stops, the folder holds the complete old or the complete new version (RestoreInterruptedSwap
  ; handles the moment between the two).
  RMDir /r "$INSTDIR.old"
  ${If} ${FileExists} "$INSTDIR\*.*"
    StrCpy $R8 0
    ${Do}
      ClearErrors
      Rename "$INSTDIR" "$INSTDIR.old"
      ${IfNot} ${Errors}
        ${ExitDo}
      ${EndIf}
      IntOp $R8 $R8 + 1
      ${If} $R8 >= 20  ; 10 seconds: an antivirus scan or an Explorer window may hold a file briefly
        MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION "Some Homograph Guard files are still in use. Close Homograph Guard and any window showing its folder, then choose Retry." /SD IDCANCEL IDRETRY +3
        RMDir /r "$INSTDIR.new"
        Abort "Installation stopped; the installed version was not changed."
        StrCpy $R8 0
      ${EndIf}
      Sleep 500
    ${Loop}
  ${EndIf}
  ClearErrors
  Rename "$INSTDIR.new" "$INSTDIR"
  ${If} ${Errors}
    Rename "$INSTDIR.old" "$INSTDIR"
    Abort "Could not put the new version in place; the previous version was kept."
  ${EndIf}
  RMDir /r "$INSTDIR.old"
FunctionEnd

Function .onInit
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/FIREWALL" $R1
  ${IfNot} ${Errors}
    !insertmacro SelectSection ${SecFirewall}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOSHORTCUTS" $R1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecShortcuts}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOEXTENSION" $R1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecExtension}
  ${EndIf}
  ClearErrors
  ${GetOptions} $R0 "/NOUPDATES" $R1
  ${IfNot} ${Errors}
    !insertmacro UnselectSection ${SecUpdates}
  ${EndIf}
FunctionEnd

; ------------------------------------------------------------------ uninstaller
Section "un.Homograph Guard" UnSecApp
  SectionIn RO
  FindWindow $R1 "TkTopLevel" "Homograph Guard"
  ${If} $R1 <> 0
    SendMessage $R1 ${WM_CLOSE} 0 0
    Sleep 1500
  ${EndIf}
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM hg-update.exe'
  Pop $0
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM hg-native-host.exe'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\homograph-guard.exe" setup schedule uninstall'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\homograph-guard.exe" native-host uninstall'
  Pop $0
  ReadRegStr $1 HKCU "${APP_KEY}" "Firewall"
  ${If} $1 == "1"
    DetailPrint "Removing the firewall rules (administrator approval needed)..."
    ExecShellWait "runas" "$INSTDIR\homograph-guard.exe" "setup firewall uninstall" SW_HIDE
  ${EndIf}
  nsExec::Exec '"$SYSDIR\taskkill.exe" /F /IM HomographGuard.exe'
  Pop $0
  Delete "$DESKTOP\Homograph Guard.lnk"
  RMDir /r "$SMPROGRAMS\Homograph Guard"
  RMDir /r "$INSTDIR"
  RMDir /r "$INSTDIR.new"  ; left over by an interrupted update
  RMDir /r "$INSTDIR.old"
  DeleteRegKey HKCU "${UNINST_KEY}"
  DeleteRegKey HKCU "${APP_KEY}"
SectionEnd

Section /o "un.Also delete my lists, reports and the threat database" UnSecData
  RMDir /r "$LOCALAPPDATA\HomographGuard"
SectionEnd

LangString DESC_UnApp ${LANG_ENGLISH} "Removes the programs, shortcuts, the daily task, the browser helper registration and the firewall rules."
LangString DESC_UnData ${LANG_ENGLISH} "Your allowlist, blocklist, reported links, settings and the downloaded threat database. Keep them if you plan to reinstall."
!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${UnSecApp} $(DESC_UnApp)
  !insertmacro MUI_DESCRIPTION_TEXT ${UnSecData} $(DESC_UnData)
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END

Function un.onInit
  ${GetParameters} $R0
  ClearErrors
  ${GetOptions} $R0 "/PURGE" $R1
  ${IfNot} ${Errors}
    !insertmacro SelectSection ${UnSecData}
  ${EndIf}
FunctionEnd
