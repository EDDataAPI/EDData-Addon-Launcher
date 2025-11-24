; Elite Dangerous Addon Launcher V2 Installer Script
; NSIS 3.x Installer mit Deinstallation, Lizenzanzeige und Installationspfad

!include "MUI2.nsh"
!include "x64.nsh"
!include "LogicLib.nsh"

; ==================== Allgemeine Einstellungen ====================

Name "Elite Dangerous Addon Launcher V2"
OutFile "Elite-Dangerous-Addon-Launcher-Setup.exe"
InstallDir "$PROGRAMFILES\Elite Dangerous Addon Launcher V2"
InstallDirRegKey HKCU "Software\Elite Dangerous Addon Launcher V2" ""
RequestExecutionLevel admin

; ==================== MUI-Einstellungen ====================

!define MUI_ABORTWARNING
!define MUI_ICON "installer\icon.ico"
!define MUI_UNICON "installer\icon.ico"
!define MUI_HEADERIMAGE
!ifdef HEADER_BMP
  !define MUI_HEADERIMAGE_BITMAP "installer\header.bmp"
!endif
!ifdef WIZARD_BMP
  !define MUI_WELCOMEFINISHPAGE_BITMAP "installer\wizard.bmp"
!endif

; ==================== Seiten ====================

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; ==================== Sprache ====================

!insertmacro MUI_LANGUAGE "German"
!insertmacro MUI_LANGUAGE "English"

; ==================== Installer-Sektion ====================

Section "Elite Dangerous Addon Launcher V2"
    SectionIn RO
    
    SetOutPath "$INSTDIR"
    
    ; Kopiere alle Dateien aus dem publish-Verzeichnis
    File /r "publish\*.*"
    
    ; Erstelle Startmenü-Einträge
    CreateDirectory "$SMPROGRAMS\Elite Dangerous Addon Launcher V2"
    CreateShortCut "$SMPROGRAMS\Elite Dangerous Addon Launcher V2\Elite Dangerous Addon Launcher.lnk" "$INSTDIR\Elite Dangerous Addon Launcher V2.exe"
    CreateShortCut "$SMPROGRAMS\Elite Dangerous Addon Launcher V2\Uninstall.lnk" "$INSTDIR\uninstall.exe"
    
    ; Erstelle Desktop-Verknüpfung (optional)
    CreateShortCut "$DESKTOP\Elite Dangerous Addon Launcher.lnk" "$INSTDIR\Elite Dangerous Addon Launcher V2.exe"
    
    ; Speichere Installationspfad in Registry
    WriteRegStr HKCU "Software\Elite Dangerous Addon Launcher V2" "" "$INSTDIR"
    WriteRegStr HKCU "Software\Elite Dangerous Addon Launcher V2" "Version" "2.0.0"
    WriteRegStr HKCU "Software\Elite Dangerous Addon Launcher V2" "InstallDate" "$%DATE%"
    
    ; Erstelle Uninstall-Registry-Einträge
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "DisplayName" "Elite Dangerous Addon Launcher V2"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "DisplayVersion" "2.0.0"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "InstallLocation" "$INSTDIR"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "DisplayIcon" "$INSTDIR\Elite Dangerous Addon Launcher V2.exe"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "Publisher" "EDToolbox"
    WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2" "URLInfoAbout" "https://github.com/EDToolbox/Elite-Dangerous-Addon-Launcher-V2"
    
    ; Schreibe Uninstall-Programm
    WriteUninstaller "$INSTDIR\uninstall.exe"
    
SectionEnd

; ==================== Uninstaller-Sektion ====================

Section "Uninstall"
    
    ; Entferne Startmenü-Einträge
    Delete "$SMPROGRAMS\Elite Dangerous Addon Launcher V2\Elite Dangerous Addon Launcher.lnk"
    Delete "$SMPROGRAMS\Elite Dangerous Addon Launcher V2\Uninstall.lnk"
    RMDir "$SMPROGRAMS\Elite Dangerous Addon Launcher V2"
    
    ; Entferne Desktop-Verknüpfung
    Delete "$DESKTOP\Elite Dangerous Addon Launcher.lnk"
    
    ; Entferne Installationsdateien
    RMDir /r "$INSTDIR\*.*"
    RMDir "$INSTDIR"
    
    ; Entferne Registry-Einträge
    DeleteRegKey HKCU "Software\Elite Dangerous Addon Launcher V2"
    DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Elite Dangerous Addon Launcher V2"
    
SectionEnd

; ==================== Funktionen ====================

Function .onInit
    
    ; Überprüfe ob bereits installiert
    ReadRegStr $0 HKCU "Software\Elite Dangerous Addon Launcher V2" ""
    ${If} $0 != ""
        MessageBox MB_YESNO|MB_ICONQUESTION "Elite Dangerous Addon Launcher V2 ist bereits installiert.$\n$\nMöchten Sie es neu installieren?" IDYES proceed
        Abort
        proceed:
    ${EndIf}
    
FunctionEnd

Function un.onInit
    
    MessageBox MB_ICONQUESTION|MB_YESNO|MB_DEFBUTTON2 "Möchten Sie Elite Dangerous Addon Launcher V2 deinstallieren?" IDYES +2
    Abort
    
FunctionEnd

Function un.onUninstSuccess
    MessageBox MB_ICONINFORMATION|MB_OK "Elite Dangerous Addon Launcher V2 wurde erfolgreich deinstalliert."
FunctionEnd
