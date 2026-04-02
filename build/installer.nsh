!macro customInstall
  ; Add firewall rules for WireGuard tunnel
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro WireGuard"'
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="GateControl Pro WireGuard" dir=out action=allow program="$INSTDIR\GateControl Pro.exe" enable=yes'

  ; Allow mstsc.exe outbound (usually already allowed, but ensure)
  nsExec::ExecToLog 'netsh advfirewall firewall add rule name="GateControl Pro RDP" dir=out action=allow program="%SystemRoot%\system32\mstsc.exe" enable=yes'
!macroend

!macro customUnInstall
  ; Remove firewall rules
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro WireGuard"'
  nsExec::ExecToLog 'netsh advfirewall firewall delete rule name="GateControl Pro RDP"'

  ; Cleanup any stale TERMSRV credentials
  nsExec::ExecToLog 'cmd /c "for /f "tokens=2 delims= " %a in (''cmdkey /list ^| findstr TERMSRV'') do cmdkey /delete:%a"'

  ; Cleanup temp RDP files
  nsExec::ExecToLog 'cmd /c "del /q %TEMP%\gatecontrol_rdp_*.rdp 2>nul"'
!macroend
