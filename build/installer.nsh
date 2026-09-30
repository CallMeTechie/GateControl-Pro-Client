; GateControl Pro - NSIS-Anpassungen (electron-builder "nsis.include")

; ======================================================================
; Kill-Switch-Aufraeumen beim Deinstallieren
; (Dieser Block ist in Pro- und Community-Client identisch.)
;
; Der Kill-Switch (gatecontrol-client-core, services/killswitch.js) legt
; Firewall-Regeln mit dem Praefix "GateControl_KS_" an und setzt die
; Outbound-Policy der Profile Domain/Private/Public auf "blockoutbound".
; Wird deinstalliert, waehrend er aktiv ist, bliebe der PC ohne Internet.
;
; Ablauf (die App ist zu diesem Zeitpunkt bereits beendet: electron-builder
; ruft CHECK_APP_RUNNING in un.onInit bzw. am Anfang der Uninstall-Section
; auf, also vor customUnInstall):
;   1. Alle Regeln, deren Anzeigename mit "GateControl_KS_" beginnt, per
;      PowerShell suchen. netsh "name=" setzt den Anzeigenamen
;      (DisplayName); der interne Name ist eine GUID. Deshalb wird nach
;      DisplayName gefiltert. Das erfasst auch dynamische Namen wie
;      GateControl_KS_Allow_PhysNet_<Subnetz>.
;   2. Nur wenn solche Regeln existierten: fuer jedes Profil mit
;      Outbound "Block" die Outbound-Policy auf "Allow" (Windows-Standard)
;      zuruecksetzen. Der Inbound-Teil bleibt unveraendert.
;   3. Die Regeln loeschen.
;   4. Fallback, falls PowerShell/NetSecurity nicht nutzbar ist: bekannte
;      feste Regelnamen per netsh loeschen und die Policy per netsh
;      (Inbound-Teil erhalten) zuruecksetzen, falls dabei Regeln gefunden
;      wurden.
;
; Sicherheitsentscheidung: Die gesicherte Original-Policy in
; %APPDATA%\...\killswitch-state.json wird bewusst NICHT gelesen. Die
; Datei ist vom Benutzer beschreibbar, der Deinstaller laeuft mit
; Administratorrechten; ihr Inhalt darf keine Firewall-Einstellungen
; steuern. Stattdessen gilt: Existieren noch GateControl_KS_-Regeln,
; stammt ein "blockoutbound" praktisch sicher vom Kill-Switch (dieselbe
; Annahme wie _repairPolicyIfLeftover() im Core), also wird der
; Windows-Standard "allowoutbound" wiederhergestellt. Existieren keine
; Kill-Switch-Regeln, bleibt die Policy unangetastet - der Benutzer
; koennte "blockoutbound" absichtlich eingestellt haben.
;
; Die Zustandsdatei selbst wird nicht geloescht: Der Deinstaller behaelt
; die Benutzerdaten (deleteAppDataOnUninstall ist nicht gesetzt); nur mit
; --delete-app-data entfernt electron-builder %APPDATA%\<App> komplett
; und damit auch die Datei. Eine liegengebliebene Datei ist harmlos: Bei
; einer Neuinstallation raeumt recoverStaleState() im Core sie auf.
;
; Register: $0 = powershell.exe, $1 = netsh.exe, $2 = Regeln gefunden,
; $3 = Rueckgabewert, $4 = netsh-Ausgabe, $5 = Treffer. Alle werden
; gesichert und wiederhergestellt.
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

; Fallback: Regel per netsh loeschen; $2 = 1, wenn sie existierte.
!macro GC_NETSH_DELETE_KS_RULE NAME
  nsExec::ExecToLog `"$1" advfirewall firewall delete rule name=${NAME}`
  Pop $3
  ${If} $3 == 0
    StrCpy $2 1
  ${EndIf}
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

  ; Der Deinstaller ist ein 32-Bit-Prozess. Ueber Sysnative werden auf
  ; 64-Bit-Windows die nativen 64-Bit-Programme gestartet.
  ${If} ${FileExists} "$WINDIR\Sysnative\netsh.exe"
    StrCpy $0 "$WINDIR\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
    StrCpy $1 "$WINDIR\Sysnative\netsh.exe"
  ${Else}
    StrCpy $0 "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
    StrCpy $1 "$SYSDIR\netsh.exe"
  ${EndIf}

  DetailPrint "GateControl: Kill-Switch-Firewallregeln entfernen ..."
  StrCpy $2 0

  ; Exit-Codes: 10 = Regeln gefunden, Policy geprueft und Regeln geloescht;
  ; 0 = keine Kill-Switch-Regeln vorhanden (Policy bleibt unveraendert);
  ; alles andere (auch "error" von nsExec) = Fallback ueber netsh.
  ; Hinweis: "$$" ist in NSIS ein literales "$" fuer PowerShell.
  nsExec::ExecToLog `"$0" -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$$ErrorActionPreference='Stop'; try { $$ks = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $$_.DisplayName -like 'GateControl_KS_*' }); if ($$ks.Count -eq 0) { exit 0 }; foreach ($$p in 'Domain','Private','Public') { if ((Get-NetFirewallProfile -PolicyStore PersistentStore -Name $$p).DefaultOutboundAction -eq 'Block') { Set-NetFirewallProfile -PolicyStore PersistentStore -Name $$p -DefaultOutboundAction Allow } }; $$ks | Remove-NetFirewallRule; exit 10 } catch { exit 2 }"`
  Pop $3

  ${If} $3 == 10
    DetailPrint "GateControl: Kill-Switch-Regeln entfernt, Outbound-Policy wiederhergestellt."
  ${ElseIf} $3 == 0
    DetailPrint "GateControl: Keine Kill-Switch-Regeln vorhanden."
  ${Else}
    DetailPrint "GateControl: PowerShell nicht nutzbar ($3), Fallback ueber netsh."
    ; Feste Regelnamen aus killswitch.js (Core) plus aeltere Versionen.
    ; Dynamische Namen (Allow_PhysNet_<Subnetz>) erfasst nur PowerShell.
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_WG_Endpoint
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_WG_Endpoint_In
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_API
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_VPN_Out
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_VPN_Subnet
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_VPN_DNS
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_VPN_DNS_TCP
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_VPN_In
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_Loopback
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_Loopback_In
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_LAN_10_0_0_0_8
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_LAN_172_16_0_0_12
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_LAN_192_168_0_0_16
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_LAN_In_10_0_0_0_8
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_LAN_In_172_16_0_0_12
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_LAN_In_192_168_0_0_16
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_DHCP
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Allow_DHCP_In
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Block_All_Out
    !insertmacro GC_NETSH_DELETE_KS_RULE GateControl_KS_Block_All_In

    ${If} $2 == 1
      !insertmacro GC_NETSH_RESTORE_OUTBOUND domain
      !insertmacro GC_NETSH_RESTORE_OUTBOUND private
      !insertmacro GC_NETSH_RESTORE_OUTBOUND public
    ${Else}
      DetailPrint "GateControl: Keine Kill-Switch-Regeln gefunden, Policy bleibt unveraendert."
    ${EndIf}
  ${EndIf}

  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
!macroend
; ====================== Ende Kill-Switch-Aufraeumen =====================

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

    ; RDP-Freigabe (rdp-allow.js im Core, Regel GateControl_RDP_Allow_In_3389)
    Push $0
    nsExec::ExecToLog 'netsh advfirewall firewall delete rule name=GateControl_RDP_Allow_In_3389'
    Pop $0
    Pop $0
  ${EndIf}

  ; Remove firewall rules
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro WireGuard"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro RDP"'

  ; Cleanup any stale TERMSRV credentials
  nsExec::ExecToLog 'cmd /c "for /f "tokens=2 delims= " %a in (''cmdkey /list ^| findstr TERMSRV'') do cmdkey /delete:%a"'

  ; Cleanup temp RDP files
  nsExec::ExecToLog 'cmd /c "del /q %TEMP%\gatecontrol_rdp_*.rdp 2>nul"'
!macroend
