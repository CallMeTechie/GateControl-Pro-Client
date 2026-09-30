# RDP-Vertrauen: keine .rdp-Signatur, kein globaler Registry-Override

## Hintergrund

Bis Version 1.22.0 hat der Pro-Client zwei maschinenweite Vertrauensänderungen
vorgenommen, um Warndialoge von `mstsc.exe` zu unterdrücken:

1. `HKCU\SOFTWARE\Microsoft\Terminal Server Client\AuthenticationLevelOverride = 0`
   — schaltete die Warnung zum Serverzertifikat für **alle** RDP-Verbindungen
   des Benutzers ab, nicht nur für GateControl.
2. Ein selbstsigniertes Code-Signing-Zertifikat `CN=GateControl RDP Signing`
   in `Cert:\CurrentUser\My`, `\Root` und `\TrustedPublisher`, mit dem
   `rdpsign.exe` die erzeugten `.rdp`-Dateien signierte. Ein vertrauenswürdiger
   Root mit Code-Signing-EKU erlaubt jedem, der an den Schlüssel kommt, Code zu
   signieren, dem Windows vertraut.

## Heute

- **Serverauthentifizierung pro Verbindung:** `RdpConfigBuilder` schreibt
  `authentication level:i:0` in die generierte `.rdp`-Datei. Das gilt nur für
  diese eine GateControl-Verbindung; das globale Verhalten von mstsc bleibt
  unverändert. Der globale Override darf nicht wieder eingeführt werden.
- **Keine .rdp-Signatur mehr:** Eine Signatur mit einem selbstsignierten
  Zertifikat unterdrückt die Herausgeber-Warnung nur, wenn das Zertifikat als
  Root vertraut wird — genau das wollen wir nicht. Die Verbindung funktioniert
  unsigniert unverändert; mstsc zeigt lediglich den Herausgeber-Hinweis
  („Unbekannter Herausgeber“), der pro Zielrechner mit „Nicht erneut
  nachfragen“ bestätigt werden kann.

## Migration beim Start (`src/services/rdp/rdp-trust-migration.js`)

Läuft einmalig unter Windows; jeder Schritt wird nach Erfolg in
electron-store vermerkt (`migrations.rdpAuthOverrideRemoved`,
`migrations.rdpSigningCertRemoved`) und bei Fehlern beim nächsten Start
wiederholt.

1. `AuthenticationLevelOverride` wird nur gelöscht, wenn es exakt
   `REG_DWORD 0` ist (der Wert, den alte Versionen geschrieben haben). Andere
   Werte stammen nicht von uns und bleiben unangetastet. Gelöscht statt
   wiederhergestellt, weil der Wert auf einem Standard-Windows nicht existiert
   und nie ein Vorgängerwert gesichert wurde.
2. Das Legacy-Zertifikat wird aus `Root`, `TrustedPublisher` und `My`
   entfernt — nur wenn Subject und Issuer exakt `CN=GateControl RDP Signing`
   sind, die einzige EKU Code Signing ist, (in `My`) der FriendlyName passt
   und, sofern `rdp-signing\thumbprint.txt` noch existiert, der Thumbprint
   übereinstimmt. Danach werden `rdp-signing\` und die aus WinSxS kopierte
   `bin\rdpsign.exe` gelöscht.

Hinweis: Beim Entfernen aus `CurrentUser\Root` zeigt Windows eine
Bestätigungsabfrage. Lehnt der Benutzer ab, wird es beim nächsten Start
erneut versucht.
