# GateControl Pro Client

Windows VPN client with integrated Remote Desktop (RDP) management.

## Features
- WireGuard VPN with auto-connect, kill-switch, split-tunneling
- One-click RDP connections to VMs in the GateControl network
- Slide-out RDP panel with pin support
- E2EE credential handling
- Wake-on-LAN integration
- Session tracking and audit

## Development
```bash
npm install
npm run dev
```

## Core-Abhängigkeit (gatecontrol-client-core)

Die gemeinsame Logik liegt in [gatecontrol-client-core](https://github.com/CallMeTechie/gatecontrol-client-core). Welcher Core-Stand gebaut wird, ist in **`core.ref`** als vollständiger 40-stelliger Commit-SHA festgelegt. Alle Workflows (PR-Check, Security, Release) holen genau diesen Commit nach `.core` (`scripts/fetch-core.sh --link`) – ein neuer Merge in Core ändert einen Client-Build also erst, wenn `core.ref` angehoben wird.

**Lokale Entwicklung:** `package.json` zeigt auf den Nachbar-Checkout `../gatecontrol-client-core`. Diesen auf den gepinnten Stand bringen (legt das Verzeichnis bei Bedarf an, bricht bei uncommitteten Änderungen ab):

```bash
npm run core:fetch -- ../gatecontrol-client-core
npm install
```

**Core anheben:**

```bash
npm run core:bump             # core.ref auf aktuellen core master setzen
npm run core:bump -- <SHA>    # oder auf einen bestimmten Commit
npm run core:fetch -- ../gatecontrol-client-core && npm test
```

Die Änderung an `core.ref` per Pull Request einreichen; der PR-Check testet dann gegen den neuen Core-Stand.

## Build
```bash
npm run build:installer   # NSIS installer
npm run build:portable    # Portable ZIP
```

## Signierte Updates

Der Client hat kein Authenticode-Zertifikat. Auto-Updates sind deshalb mit einem eigenen Ed25519-Schlüssel abgesichert:

- Die Release-Pipeline (`scripts/sign-update.js`) schreibt zu jedem Release `update-manifest.json` (Produkt, Version, Dateiname, SHA-256 und Größe des Installers) und die Signatur `update-manifest.json.sig` und lädt beide als Release-Assets hoch. Der private Schlüssel liegt ausschließlich im GitHub-Secret `UPDATE_SIGNING_KEY`.
- Der Client installiert nur Updates, deren Manifest mit dem Public Key aus `build/update-signing.pub` gültig signiert ist und deren Download Größe und SHA-256 aus dem Manifest trifft. Unsignierte Updates werden abgelehnt.
- Solange `build/update-signing.pub` den Platzhalter `REPLACE_WITH_UPDATE_PUBLIC_KEY` enthält, ist der Auto-Updater im Client deaktiviert und die Release-Pipeline bricht ab.

**Einmalig einrichten** (lokal, der private Schlüssel verlässt den Rechner nur als Secret):

```bash
# Schlüsselpaar erzeugen (OpenSSL)
openssl genpkey -algorithm ed25519 -out gc-update-signing.pem
openssl pkey -in gc-update-signing.pem -pubout -out update-signing.pub

# Alternative ohne OpenSSL (Node.js)
node -e "const c=require('crypto'),fs=require('fs');const {publicKey,privateKey}=c.generateKeyPairSync('ed25519');fs.writeFileSync('gc-update-signing.pem',privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});fs.writeFileSync('update-signing.pub',publicKey.export({type:'spki',format:'pem'}))"
```

1. Secret `UPDATE_SIGNING_KEY` mit dem **Inhalt** von `gc-update-signing.pem` in **beiden** Client-Repos (Pro und Community) anlegen – derselbe Schlüssel für beide, z. B. `gh secret set UPDATE_SIGNING_KEY < gc-update-signing.pem` (einmal pro Repo).
2. `update-signing.pub` in **beiden** Repos als `build/update-signing.pub` committen (ersetzt den Platzhalter).
3. `gc-update-signing.pem` sicher offline aufbewahren (Passwort-Manager/Tresor) und vom Arbeitsrechner löschen. Geht der Schlüssel verloren, muss ein neuer Public Key ausgeliefert werden; installierte Clients mit dem alten Key nehmen danach signierte Updates erst nach einer manuellen Neuinstallation an.

## Update-Kanal und Pflicht-Updates

Welche Builds ein Client angeboten bekommt, legt der GateControl-Server fest (Einstellungen → Client-Updates bzw. pro Peer):

- **Kanal** `stable` (Standard, neueste reguläre Version) oder `beta` (zusätzlich GitHub-Pre-Releases). Der Client zeigt den zugewiesenen Kanal unter Einstellungen → Über nur an; wählen kann er ihn nicht.
- **Mindestversion** pro Produkt. Liegt die installierte Version darunter und ist ein geprüftes, neueres Update heruntergeladen, erscheint „Update erforderlich“: ein nicht ausblendbares Banner auf der Übersicht, die Update-Karte in der Seitenleiste ohne „Später“, ein Eintrag ganz oben im Tray-Menü und eine Benachrichtigung (bei jedem App-Start erneut).
- Kanal, Mindestversion und `mandatory` sind **nicht** signiert und dienen nur der Anzeige. Signatur, Produkt, Version (strikt neuer – kein Downgrade), Größe und SHA-256 werden immer geprüft; der Server kann so weder unsignierte Builds noch ältere Versionen ausrollen.
- Ein Pflicht-Update wird **nicht automatisch** installiert: Der Installer beendet die App und trennt den VPN-Tunnel (Kill-Switch wird vorher gelöst). Das soll nicht ohne Zutun mitten in einer Sitzung passieren – der Nutzer startet die Installation über Banner, Karte oder Tray.

## Client-Richtlinien vom Server

Der Administrator kann auf dem Server (Einstellungen → Client-Richtlinien, pro Peer-Gruppe oder pro Peer) festlegen, was der Client erzwingt. Der Client lädt die Richtlinie über `GET /api/v1/client/policy`, speichert die zuletzt bekannte verschlüsselt im Config-Store und wendet sie auch offline an. Ist der Server nicht erreichbar, bleibt die letzte bekannte Richtlinie aktiv; wurde nie eine geladen, gibt es keine Einschränkung.

| Richtlinie | Wirkung im Client |
|---|---|
| Kill-Switch erzwungen | Kill-Switch an, Schalter (Einstellungen, Übersicht, Tray) gesperrt |
| Automatisch verbinden erzwungen / immer verbunden | Auto-Connect an und gesperrt; bei „immer verbunden“ kein manuelles Trennen, Neuverbindung im Minutentakt |
| Autostart erzwungen / verboten | Autostart an bzw. aus, Schalter gesperrt |
| Split-Tunnel-Modi | nur erlaubte Modi wählbar (Windows: „Gesamter Verkehr“ / „Nur ausgewählte Ziele“; bleibt keiner übrig, gilt Full Tunnel) |
| Einstellungen sperren | alle Einstellungen außer Sprache und Design gesperrt |
| Serverwechsel ausblenden | Server-/Einrichtungsbereich ausgeblendet, `server:setup` und Config-Import abgelehnt |

Gesperrte Einstellungen zeigen den Hinweis „Vom Administrator festgelegt“. Die Sperren prüft der Main-Prozess (IPC), nicht nur die Oberfläche. Die Richtlinie ist eine Verwaltungshilfe und **keine Sicherheitsgrenze** gegen Benutzer mit lokalen Administratorrechten.
