# gc-drive-sync – GateControl Drive im Explorer

Kleines Sync-Programm (Rust) neben dem Pro-Client: GateControl Drive als Ordner **„GateControl Drive“** im
Windows-Explorer mit **Dateien bei Bedarf** über die Windows Cloud Files API (cfapi, wie OneDrive). Etappe W3a; die
Oberfläche im Pro-Client folgt (W3b).

Warum ein eigenes Programm und nicht Electron: Die Cloud Files API ruft aus eigenen Threads zurück und muss auch
antworten, wenn das Fenster zu ist; ein kleines natives Programm ohne Laufzeit ist dafür robuster.

## Was es tut

- **Sync-Root** `%USERPROFILE%\GateControl Drive`, je Bereich ein Unterordner („Meine Dateien“, „Familie“, Team-Ordner,
  …), registriert über `StorageProviderSyncRootManager.Register` (Anzeigename „GateControl Drive“, Symbol des
  Pro-Clients aus der Exe, Eintrag im Navigationsbereich). Klappt WinRT nicht, `CfRegisterSyncRoot`.
- **Platzhalter** für alle Ordner und Dateien der Bereiche (Größe, Zeiten; Identität = Knoten-ID, `rev`, Bereich,
  Medien-ID). Öffnen einer Datei → `FETCH_DATA` → Download mit HTTP Range → `CfExecute TRANSFER_DATA` in Stücken zu
  1 MiB, Fortschritt per `CfReportProviderProgress` (Windows zeigt ihn an). `CANCEL_FETCH_DATA` bricht ab.
- **Änderungen vom Server**: `GET changes?since=` alle 45 s, sofort auf `sync-now` (der Pro-Client schickt es beim
  Push-Ereignis `changed` des Plugins), dazu alle 6 h ein voller Vergleich. Neue/umbenannte/verschobene/gelöschte
  Knoten werden lokal nachgezogen; eine neue Fassung dehydriert den Platzhalter (angeheftet: gleich neu laden).
- **Änderungen auf dem PC** (`ReadDirectoryChangesW`, rekursiv; 2 s Ruhe abwarten):
  neue Dateien → `uploads/check` (SHA-256; schon da → nur Platzhalter) → Medien-Upload (bis 8 MiB ein PUT mit
  `Repr-Digest`, darüber fortsetzbar in 8-MiB-Teilen) → `uploads/commit` → Platzhalter, `in sync`.
  Geänderte Platzhalter → neue Fassung mit `baseRev`. Neue Ordner → `POST nodes`. Umbenennen/Verschieben → `PATCH`.
  Löschen → Papierkorb des Servers (`NOTIFY_DELETE`, bei Rechten nur zum Lesen abgelehnt; ebenso `NOTIFY_RENAME`).
- **Konflikte** gehen nie verloren: Antwortet der Server `409`, bleibt die lokale Fassung als
  `Name (Konflikt <Gerät> <JJJJ-MM-TT HH-MM>).ext` und wird hochgeladen; die Server-Fassung bekommt den Namen.
- **Pin-Zustände**: „Immer auf diesem Gerät behalten“ (pinned, auch für Ordner) → vollständig laden;
  „Speicher freigeben“ (unpinned) → `CfDehydratePlaceholder`.
- **Zustand** (Baum mit Namen/`rev`/Medien-ID, Bereichsordner, Cursor `since`) in
  `%LOCALAPPDATA%\GateControl\drive-sync\state-<hash des Servers>.json`, Log `drive-sync.log` daneben (1 MiB, eine
  Vorgängerdatei). **Kein Token auf der Platte** – es kommt nur über die Pipe (PROTOCOL.md) und lebt im Speicher.
- **Abmelden** (`unregister` über die Pipe, `gc-drive-sync.exe unregister` beim Deinstallieren): Platzhalter „nur
  online“ werden gelöscht, geladene und geänderte Dateien bleiben als normale Dateien, die Sync-Root wird abgemeldet.

### Richtlinien der Sync-Root

| Richtlinie | Wahl | Warum |
|---|---|---|
| Hydration | **Progressive** | Programme lesen, sobald der angefragte Bereich da ist (Videos, große PDFs starten sofort); Windows fordert Bereiche an, der Server liefert Range. „Full“ würde jedes Öffnen bis zum letzten Byte warten lassen. |
| Population | **AlwaysFull** | Das Programm legt alle Platzhalter selbst an. Das Änderungsprotokoll des Plugins liefert ohnehin alle Änderungen der sichtbaren Bereiche; ein vollständiger lokaler Baum macht Suche, Offline-Ansicht und Umbenennen/Verschieben einfach und schnell, und der Explorer wartet nie auf einen `FETCH_PLACEHOLDERS`-Rückruf übers Netz. Preis: der erste Abgleich listet alle Ordner (Seiten zu 1000). „Partial/Full“ (bei Bedarf) lohnt erst bei sehr großen Bäumen – siehe Grenzen. |
| In-Sync | Default | Inhaltsänderungen löschen „in sync“, der Abgleich lädt dann hoch. |

### Was bewusst nicht abgeglichen wird

- Kinder-Ordner, die ein Elternteil nur **einsehen** darf (`via: parent`): Jedes Auflisten meldet dem Kind
  „angesehen“ – im Hintergrund wäre das täglich.
- Leere Dateien (der Medien-Upload nimmt 0 Byte nicht an) – sobald Inhalt da ist, geht die Datei hoch.
- Sperr- und Zwischendateien (`~$…`, `.~lock.…#`, `*.tmp`, `*.crdownload`, `desktop.ini`, `Thumbs.db`).
- Namen, die Windows nicht kennt (z. B. `CON.txt`) – Fehler `name_unsupported` im Status.
- Dateien direkt im Sync-Root (außerhalb eines Bereichs) – Fehler `outside_area`.
- Massenlöschung, während das Programm nicht lief (> 500 Dateien oder > 20 %): nicht übertragen, die Platzhalter kommen
  zurück, Fehler `mass_delete` (die Nachfrage „wirklich löschen?“ kommt mit der Oberfläche in W3b).

## Aufbau

```
src/core/          ohne Windows, mit cargo test auf jedem System prüfbar
  model.rs         Antworten des Plugins
  api.rs           HTTP-Client (reqwest blocking + rustls; Zertifikate über den Windows-Speicher via
                   rustls-platform-verifier, Proxy wie das System)
  remote.rs        Schnittstelle „Server“ (ApiClient oder Fake)
  localfs.rs       Schnittstelle „Platzhalter-Dateisystem“ (WinFs oder Fake)
  engine.rs        der Abgleich (voll, Änderungsprotokoll, lokale Änderungen, Konflikte, Pins)
  hydrate.rs       FETCH_DATA: Bereich planen (4-KiB-Regeln), Range laden, in Stücken übergeben
  state.rs         Zustand + Pfad↔Knoten
  names.rs         gültige Namen, Konfliktnamen, Bereichsordner
  identity.rs      FileIdentity der Platzhalter
  protocol.rs      Pipe-Protokoll (PROTOCOL.md)
  service.rs       Befehle, Abgleich-Thread, Rückruf-Logik, Download-Threads, Status
  testing.rs       FakeDrive (Plugin im Speicher) und FakeFs (Platzhalter im Speicher)
src/win/           Windows
  syncroot.rs      Registrieren/Abmelden
  cfapi.rs         CfConnectSyncRoot + Rückrufe
  winfs.rs         Platzhalter (CfCreatePlaceholders, CfUpdatePlaceholder, CfConvertToPlaceholder, …)
  watcher.rs       ReadDirectoryChangesW
  pipe.rs          benannte Pipe mit ACL
  main.rs          Programmstart (run | unregister | info)
tests/
  api_http.rs      ApiClient gegen einen HTTP-Fake des Plugins (tiny_http): Routen, Token, Fehler, Upload, Range
  cfapi_windows.rs echte Sync-Root (nur Windows), siehe CI
build.rs           Symbol (../build/icon.ico) und Versionsangaben in die Exe
```

Der Pro-Client steuert das Programm über `src/main/drive-ondemand.js` (standardmäßig **aus**, Einstellung
`driveOnDemand.enabled`), IPC-Kanäle `drive-ondemand:*`, Preload `gatecontrol.driveOnDemand`. Die Namen sind nicht
„drive-sync“, weil „Ordner sichern“ (W2) `drive:sync:*` und den Store-Schlüssel `driveSync` belegt.

## Bauen und Testen

```
cd drive-sync
cargo test                         # alle plattformunabhängigen Tests (Linux/macOS/Windows)
cargo clippy --all-targets -- -D warnings
cargo build --release              # unter Windows: target/release/gc-drive-sync.exe
```

Von Linux aus prüfen: `rustup target add x86_64-pc-windows-gnu`, MinGW (`gcc-mingw-w64-x86-64`) installieren, dann
`cargo clippy --target x86_64-pc-windows-gnu --all-targets -- -D warnings` bzw. `cargo build --release --target …`.

CI (`.github/workflows/drive-sync.yml`): Linux – Format, Clippy, Tests; Windows – Clippy, Tests, Release-Build und
der Integrations-Test mit echter Sync-Root gegen den Fake-Server (registrieren, Platzhalter, Öffnen aus einem
anderen Prozess → Laden, Speicher freigeben, anheften → Laden, neue lokale Datei → Upload, Server-Änderung →
`sync-now`, abmelden). Ist die Cloud Files API auf dem Runner nicht nutzbar, steht `CFAPI-SKIPPED: <Grund>` im Log
und als Warnung in der Zusammenfassung – der Test meldet dann kein „bestanden“.

Release (`release.yml`): `cargo build --release` vor electron-builder; `package.json` → `extraResources` legt
`gc-drive-sync.exe` nach `resources\drive-sync\` (Installer und Portable). Signatur wie bei der App: kein
Authenticode-Zertifikat im Projekt; der Installer ist über das Ed25519-signierte Update-Manifest abgesichert, damit
auch die darin enthaltene `gc-drive-sync.exe`. Beim Deinstallieren ruft `build/installer.nsh`
`gc-drive-sync.exe unregister` auf.

## Grenzen (W3a)

- **Ohne Authenticode**: SmartScreen/Defender kennen die Exe nicht; wie bei der App.
- **Läuft mit Administratorrechten**, weil der Pro-Client erhöht läuft (`requireAdministrator`) und es startet. Die
  Sync-Root gehört trotzdem dem angemeldeten Benutzer (gleiche SID); Dateien, die das Programm anlegt, gehören
  allerdings der Administratorengruppe. Ein Start mit normalen Rechten ist für W3b vorgemerkt.
- **Nur solange der Pro-Client läuft** (Fenster darf zu sein); ohne ihn lassen sich nur geladene Dateien öffnen.
- **Konto-/Serverwechsel**: neuer Zustand je Server; vorher `unregister` (W3b: automatisch beim Abmelden).
- **Sehr große Bäume** (≫ 100 000 Einträge): erster Abgleich listet alles; ggf. später Population „Full“.
- **Löschen offline**: Löschungen, während der Server nicht erreichbar ist, werden lokal ausgeführt und beim nächsten
  Abgleich übertragen (Papierkorb des Servers); umgekehrt gewinnt eine Server-Änderung gegen eine lokale Löschung.
- Bekannte Ordner verlegen (`SHSetKnownFolderPath`), Explorer-Kontextmenü (Link teilen, Versionen) und die
  Oberfläche: W3b.
