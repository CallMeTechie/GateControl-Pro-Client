; GateControl Pro - NSIS-Anpassungen (electron-builder "nsis.include")

; Edition dieses Installers. Muss zu gatecontrol-client-core
; src/services/editions.js passen (Kill-Switch-Regelpraefix, Name der
; RDP-Freigaberegel sowie GUID und productName der jeweils ANDEREN
; Edition); test/installer-nsh.test.js prueft das.
!define GC_KS_PREFIX "GateControl_Pro_KS"
!define GC_RDP_RULE "GateControl_Pro_RDP_Allow_In_3389"
!define GC_OTHER_EDITION_GUID "aa07f3aa-9926-52f3-be30-dbe287d6b2ea"
!define GC_OTHER_EDITION_PRODUCT "GateControl Community Client"

; ======================================================================
; Kill-Switch-Aufraeumen beim Deinstallieren
; (Dieser Block ist in Pro- und Community-Client identisch; die Edition
; steckt nur in den Defines GC_KS_PREFIX / GC_OTHER_EDITION_* oben.)
;
; Der Kill-Switch (gatecontrol-client-core, services/killswitch.js) legt
; Firewall-Regeln mit dem Praefix "${GC_KS_PREFIX}_" an (pro Edition
; eigenes Praefix, abgeleitet in core services/editions.js) und setzt die
; Outbound-Policy der Profile Domain/Private/Public auf "blockoutbound".
; Wird deinstalliert, waehrend er aktiv ist, bliebe der PC ohne Internet.
; Regeln der anderen Edition werden nie angefasst.
;
; Altregeln: Versionen vor der Trennung nutzten in BEIDEN Apps das
; Praefix "GateControl_KS_". Diese Regeln tragen kein program= und sind
; keiner App zuzuordnen. Sie werden nur mitgeloescht, wenn die andere
; Edition weder installiert ist (Registry Software\<GUID> in HKLM/HKCU,
; Exe im Programmverzeichnis) noch laeuft (tasklist, deckt die portable
; Version ab) - sonst koennten sie zum aktiven Kill-Switch einer alten
; Version der anderen App gehoeren. Dieselbe Regel gilt im Core.
;
; Ablauf (die App ist zu diesem Zeitpunkt bereits beendet: electron-builder
; ruft CHECK_APP_RUNNING in un.onInit bzw. am Anfang der Uninstall-Section
; auf, also vor customUnInstall):
;   0. Pruefen, ob die andere Edition vorhanden ist ($6).
;   1. Alle Regeln, deren Anzeigename mit "${GC_KS_PREFIX}_" (und ggf.
;      "GateControl_KS_") beginnt, per PowerShell suchen. netsh "name="
;      setzt den Anzeigenamen (DisplayName); der interne Name ist eine
;      GUID. Deshalb wird nach DisplayName gefiltert. Das erfasst auch
;      dynamische Namen wie <Praefix>_Allow_PhysNet_<Subnetz>. Bei -like
;      ist "_" kein Platzhalter; "GateControl_KS_*" passt daher nicht auf
;      "GateControl_Pro_KS_..." oder "GateControl_Community_KS_...".
;   2. Nur wenn solche Regeln existierten: fuer jedes Profil mit
;      Outbound "Block" die Outbound-Policy auf "Allow" (Windows-Standard)
;      zuruecksetzen. Der Inbound-Teil bleibt unveraendert.
;   3. Die Regeln loeschen.
;   4. Fallback, falls PowerShell/NetSecurity nicht nutzbar ist: bekannte
;      feste Regelnamen per netsh loeschen (netsh "name=" ist ein exakter
;      Vergleich, keine Wildcard) und die Policy per netsh (Inbound-Teil
;      erhalten) zuruecksetzen, falls dabei Regeln gefunden wurden.
;
; Sicherheitsentscheidung: Die gesicherte Original-Policy in
; %APPDATA%\...\killswitch-state.json wird bewusst NICHT gelesen. Die
; Datei ist vom Benutzer beschreibbar, der Deinstaller laeuft mit
; Administratorrechten; ihr Inhalt darf keine Firewall-Einstellungen
; steuern. Stattdessen gilt: Existieren noch Kill-Switch-Regeln dieser
; App, stammt ein "blockoutbound" praktisch sicher vom Kill-Switch
; (dieselbe Annahme wie _repairPolicyIfLeftover() im Core), also wird der
; Windows-Standard "allowoutbound" wiederhergestellt. Existieren keine,
; bleibt die Policy unangetastet - der Benutzer koennte "blockoutbound"
; absichtlich eingestellt haben.
;
; Die Zustandsdatei selbst wird nicht geloescht: Der Deinstaller behaelt
; die Benutzerdaten (deleteAppDataOnUninstall ist nicht gesetzt); nur mit
; --delete-app-data entfernt electron-builder %APPDATA%\<App> komplett
; und damit auch die Datei. Eine liegengebliebene Datei ist harmlos: Bei
; einer Neuinstallation raeumt recoverStaleState() im Core sie auf.
;
; Register: $0 = powershell.exe, $1 = netsh.exe, $2 = Regeln gefunden,
; $3 = Rueckgabewert, $4 = Ausgabe, $5 = Treffer, $6 = andere Edition
; vorhanden. Alle werden gesichert und wiederhergestellt.
; ======================================================================

; ${OUT} = 1, wenn ${HAYSTACK} ${NEEDLE} enthaelt (ohne Beachtung der
; Gross-/Kleinschreibung, da StrCmp/"==" in NSIS case-insensitive ist).
!macro GC_STR_CONTAINS OUT HAYSTACK NEEDLE
  Push $R7
  Push $R8
  Push $R9
  StrCpy ${OUT} 0
  StrLen $R8 "${NEEDLE}"
  StrCpy $R7 0
  ${Do}
    StrCpy $R9 "${HAYSTACK}" $R8 $R7
    ${If} $R9 == ""
      ${ExitDo}
    ${EndIf}
    ${If} $R9 == "${NEEDLE}"
      StrCpy ${OUT} 1
      ${ExitDo}
    ${EndIf}
    IntOp $R7 $R7 + 1
  ${Loop}
  Pop $R9
  Pop $R8
  Pop $R7
!macroend

; $6 = 1, wenn die andere Edition installiert ist oder laeuft; im Zweifel 1.
; Registry-Ansicht: electron-builder setzt in un.onInit bereits
; SetRegView 64 (x64), dieselbe Ansicht, in die auch die andere Edition
; ihren Schluessel Software\<GUID> schreibt.
!macro GC_DETECT_OTHER_EDITION
  StrCpy $6 0
  ReadRegStr $4 HKLM "Software\${GC_OTHER_EDITION_GUID}" InstallLocation
  ${If} $4 != ""
    StrCpy $6 1
  ${EndIf}
  ReadRegStr $4 HKCU "Software\${GC_OTHER_EDITION_GUID}" InstallLocation
  ${If} $4 != ""
    StrCpy $6 1
  ${EndIf}
  ${If} ${FileExists} "$PROGRAMFILES64\${GC_OTHER_EDITION_PRODUCT}\${GC_OTHER_EDITION_PRODUCT}.exe"
    StrCpy $6 1
  ${EndIf}
  ${If} ${FileExists} "$PROGRAMFILES32\${GC_OTHER_EDITION_PRODUCT}\${GC_OTHER_EDITION_PRODUCT}.exe"
    StrCpy $6 1
  ${EndIf}
  ${If} $6 == 0
    nsExec::ExecToStack `"$SYSDIR\tasklist.exe" /FI "IMAGENAME eq ${GC_OTHER_EDITION_PRODUCT}.exe" /FO CSV /NH`
    Pop $3
    Pop $4
    ${If} $3 != 0
      StrCpy $6 1
    ${Else}
      !insertmacro GC_STR_CONTAINS $5 $4 "${GC_OTHER_EDITION_PRODUCT}.exe"
      ${If} $5 == 1
        StrCpy $6 1
      ${EndIf}
    ${EndIf}
  ${EndIf}
!macroend

; Fallback: Regel per netsh loeschen; $2 = 1, wenn sie existierte.
!macro GC_NETSH_DELETE_KS_RULE NAME
  nsExec::ExecToLog `"$1" advfirewall firewall delete rule name=${NAME}`
  Pop $3
  ${If} $3 == 0
    StrCpy $2 1
  ${EndIf}
!macroend

; Fallback: alle festen Regelnamen aus killswitch.js (Core) plus aeltere
; Versionen mit dem Praefix ${PREFIX} loeschen. Dynamische Namen
; (Allow_PhysNet_<Subnetz>) erfasst nur PowerShell.
!macro GC_NETSH_DELETE_KS_RULES PREFIX
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_WG_Endpoint
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_WG_Endpoint_In
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_API
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_VPN_Out
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_VPN_Subnet
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_VPN_DNS
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_VPN_DNS_TCP
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_VPN_In
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_Loopback
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_Loopback_In
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_LAN_10_0_0_0_8
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_LAN_172_16_0_0_12
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_LAN_192_168_0_0_16
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_LAN_In_10_0_0_0_8
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_LAN_In_172_16_0_0_12
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_LAN_In_192_168_0_0_16
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_DHCP
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Allow_DHCP_In
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Block_All_Out
  !insertmacro GC_NETSH_DELETE_KS_RULE ${PREFIX}_Block_All_In
!macroend

; Fallback: steht die Policy von ${PROFILE} auf "${INBOUND},BlockOutbound",
; auf "${INBOUND},allowoutbound" setzen (Inbound-Teil bleibt erhalten).
; Erwartet die Ausgabe von "netsh advfirewall show <profil> firewallpolicy"
; in $4. Die Werte sind in netsh nicht lokalisiert, nur die Beschriftungen.
!macro GC_NETSH_RESTORE_OUTBOUND_IF PROFILE INBOUND
  !insertmacro GC_STR_CONTAINS $5 $4 "${INBOUND},BlockOutbound"
  ${If} $5 == 1
    DetailPrint "GateControl: ${PROFILE}profile ${INBOUND},BlockOutbound -> ${INBOUND},AllowOutbound"
    nsExec::ExecToLog `"$1" advfirewall set ${PROFILE}profile firewallpolicy ${INBOUND},allowoutbound`
    Pop $3
  ${EndIf}
!macroend

!macro GC_NETSH_RESTORE_OUTBOUND PROFILE
  nsExec::ExecToStack `"$1" advfirewall show ${PROFILE}profile firewallpolicy`
  Pop $3
  Pop $4
  ${If} $3 == 0
    ; "BlockInbound,BlockOutbound" ist kein Teilstring von
    ; "BlockInboundAlways,BlockOutbound" - die Muster schliessen sich aus.
    !insertmacro GC_NETSH_RESTORE_OUTBOUND_IF ${PROFILE} BlockInboundAlways
    !insertmacro GC_NETSH_RESTORE_OUTBOUND_IF ${PROFILE} BlockInbound
    !insertmacro GC_NETSH_RESTORE_OUTBOUND_IF ${PROFILE} AllowInbound
    !insertmacro GC_NETSH_RESTORE_OUTBOUND_IF ${PROFILE} NotConfigured
  ${EndIf}
!macroend

!macro GC_CLEANUP_KILLSWITCH_FIREWALL
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6

  ; Der Deinstaller ist ein 32-Bit-Prozess. Ueber Sysnative werden auf
  ; 64-Bit-Windows die nativen 64-Bit-Programme gestartet.
  ${If} ${FileExists} "$WINDIR\Sysnative\netsh.exe"
    StrCpy $0 "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    StrCpy $1 "$WINDIR\Sysnative\netsh.exe"
  ${Else}
    StrCpy $0 "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
    StrCpy $1 "$SYSDIR\netsh.exe"
  ${EndIf}

  !insertmacro GC_DETECT_OTHER_EDITION
  ${If} $6 == 1
    DetailPrint "GateControl: ${GC_OTHER_EDITION_PRODUCT} vorhanden - Altregeln GateControl_KS_* bleiben erhalten."
  ${EndIf}

  DetailPrint "GateControl: Kill-Switch-Firewallregeln (${GC_KS_PREFIX}_*) entfernen ..."
  StrCpy $2 0

  ; Exit-Codes: 10 = Regeln gefunden, Policy geprueft und Regeln geloescht;
  ; 0 = keine Kill-Switch-Regeln vorhanden (Policy bleibt unveraendert);
  ; alles andere (auch "error" von nsExec) = Fallback ueber netsh.
  ; Hinweis: "$$" ist in NSIS ein literales "$" fuer PowerShell.
  ${If} $6 == 1
    ; Nur eigene Regeln
    nsExec::ExecToLog `"$0" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference='Stop'; try { $$ks = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $$_.DisplayName -like '${GC_KS_PREFIX}_*' }); if ($$ks.Count -eq 0) { exit 0 }; foreach ($$p in 'Domain','Private','Public') { if ((Get-NetFirewallProfile -PolicyStore PersistentStore -Name $$p).DefaultOutboundAction -eq 'Block') { Set-NetFirewallProfile -PolicyStore PersistentStore -Name $$p -DefaultOutboundAction Allow } }; $$ks | Remove-NetFirewallRule; exit 10 } catch { exit 2 }"`
  ${Else}
    ; Eigene Regeln plus Altregeln (andere Edition nicht vorhanden)
    nsExec::ExecToLog `"$0" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference='Stop'; try { $$ks = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $$_.DisplayName -like '${GC_KS_PREFIX}_*' -or $$_.DisplayName -like 'GateControl_KS_*' }); if ($$ks.Count -eq 0) { exit 0 }; foreach ($$p in 'Domain','Private','Public') { if ((Get-NetFirewallProfile -PolicyStore PersistentStore -Name $$p).DefaultOutboundAction -eq 'Block') { Set-NetFirewallProfile -PolicyStore PersistentStore -Name $$p -DefaultOutboundAction Allow } }; $$ks | Remove-NetFirewallRule; exit 10 } catch { exit 2 }"`
  ${EndIf}
  Pop $3

  ${If} $3 == 10
    DetailPrint "GateControl: Kill-Switch-Regeln entfernt, Outbound-Policy wiederhergestellt."
  ${ElseIf} $3 == 0
    DetailPrint "GateControl: Keine Kill-Switch-Regeln vorhanden."
  ${Else}
    DetailPrint "GateControl: PowerShell nicht nutzbar ($3), Fallback ueber netsh."
    !insertmacro GC_NETSH_DELETE_KS_RULES ${GC_KS_PREFIX}
    ${If} $6 == 0
      !insertmacro GC_NETSH_DELETE_KS_RULES GateControl_KS
    ${EndIf}

    ${If} $2 == 1
      !insertmacro GC_NETSH_RESTORE_OUTBOUND domain
      !insertmacro GC_NETSH_RESTORE_OUTBOUND private
      !insertmacro GC_NETSH_RESTORE_OUTBOUND public
    ${Else}
      DetailPrint "GateControl: Keine Kill-Switch-Regeln gefunden, Policy bleibt unveraendert."
    ${EndIf}
  ${EndIf}

  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
!macroend
; ====================== Ende Kill-Switch-Aufraeumen =====================

; ======================================================================
; RDP-Freigabe aufraeumen beim Deinstallieren
; (Dieser Block ist in Pro- und Community-Client identisch; die Edition
; steckt nur in den Defines GC_RDP_RULE / GC_OTHER_EDITION_* oben.)
;
; rdp-allow.js im Core legt die eingehende Regel "${GC_RDP_RULE}"
; (TCP 3389 aus dem VPN-Subnetz) an - pro Edition eigener Name, siehe
; core services/editions.js. Die Regel der anderen Edition wird nie
; angefasst.
;
; Altregel: Versionen vor der Trennung nutzten in BEIDEN Apps den Namen
; "GateControl_RDP_Allow_In_3389". Sie ist keiner App zuzuordnen und wird
; nur geloescht, wenn die andere Edition weder installiert ist noch
; laeuft (GC_DETECT_OTHER_EDITION, im Zweifel "vorhanden"). Dieselbe
; Regel gilt im Core (RdpAllow.removeLegacyRule()).
;
; netsh "name=" ist ein exakter Vergleich des Anzeigenamens, keine
; Wildcard. Register $1, $3-$6 werden gesichert und wiederhergestellt.
; ======================================================================
!define GC_LEGACY_RDP_RULE "GateControl_RDP_Allow_In_3389"

!macro GC_CLEANUP_RDP_FIREWALL
  Push $1
  Push $3
  Push $4
  Push $5
  Push $6

  ${If} ${FileExists} "$WINDIR\Sysnative\netsh.exe"
    StrCpy $1 "$WINDIR\Sysnative\netsh.exe"
  ${Else}
    StrCpy $1 "$SYSDIR\netsh.exe"
  ${EndIf}

  DetailPrint "GateControl: RDP-Freigabe (${GC_RDP_RULE}) entfernen ..."
  nsExec::ExecToLog `"$1" advfirewall firewall delete rule name=${GC_RDP_RULE}`
  Pop $3

  !insertmacro GC_DETECT_OTHER_EDITION
  ${If} $6 == 0
    nsExec::ExecToLog `"$1" advfirewall firewall delete rule name=${GC_LEGACY_RDP_RULE}`
    Pop $3
  ${Else}
    DetailPrint "GateControl: ${GC_OTHER_EDITION_PRODUCT} vorhanden - Altregel ${GC_LEGACY_RDP_RULE} bleibt erhalten."
  ${EndIf}

  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $1
!macroend
; ====================== Ende RDP-Freigabe-Aufraeumen ====================

!macro customInstall
  ; Add firewall rules for WireGuard tunnel
  ; Programmpfad ueber ${APP_EXECUTABLE_FILENAME} (von electron-builder aus
  ; productName/executableName abgeleitet, hier "GateControl Pro Client.exe"),
  ; damit er nicht erneut vom echten Dateinamen abweicht.
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro WireGuard"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="GateControl Pro WireGuard" dir=out action=allow program="$INSTDIR\${APP_EXECUTABLE_FILENAME}" enable=yes'

  ; Allow mstsc.exe outbound (usually already allowed, but ensure)
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="GateControl Pro RDP" dir=out action=allow program="%SystemRoot%\system32\mstsc.exe" enable=yes'
!macroend

!macro customUnInstall
  ; Bei einem Update (--updated) laeuft der alte Deinstaller vor der neuen
  ; Installation. Dann bleibt der Kill-Switch-Zustand erhalten; die neue
  ; Version raeumt ihn beim Start ueber recoverStaleState() auf bzw. aktiviert
  ; ihn neu. Waehrend des Updates bleibt der Verkehr also gesperrt (fail-closed),
  ; wie es der Kill-Switch vorsieht.
  ${IfNot} ${isUpdated}
    ; Zuerst Internet wiederherstellen (Kill-Switch-Regeln + Policy)
    !insertmacro GC_CLEANUP_KILLSWITCH_FIREWALL

    ; RDP-Freigabe dieser Edition (Altregel nur ohne andere Edition)
    !insertmacro GC_CLEANUP_RDP_FIREWALL
  ${EndIf}

  ; Remove firewall rules
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro WireGuard"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro RDP"'

  ; Cleanup any stale TERMSRV credentials
  nsExec::ExecToLog 'cmd /c "for /f "tokens=2 delims= " %a in (''cmdkey /list ^| findstr TERMSRV'') do cmdkey /delete:%a"'

  ; Cleanup temp RDP files
  nsExec::ExecToLog 'cmd /c "del /q %TEMP%\gatecontrol_rdp_*.rdp 2>nul"'
!macroend
