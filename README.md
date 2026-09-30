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
