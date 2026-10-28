# gc-drive-sync – GateControl Drive im Explorer

Kleines Sync-Programm (Rust) neben dem Pro-Client: GateControl Drive als Ordner **„GateControl Drive“** im
Windows-Explorer mit **Dateien bei Bedarf** über die Windows Cloud Files API (cfapi, wie OneDrive). Etappe W3a, dazu
W3b: Oberfläche im Pro-Client (Drive-Seite › „Ordner sichern“ › „GateControl Drive im Explorer“), Start mit
Benutzerrechten, Windows-Ordner verlegen, Explorer-Kontextmenü, Nachfrage bei Massenlöschung.

Warum ein eigenes Programm und nicht Electron: Die Cloud Files API ruft aus eigenen Threads zurück und muss auch
antworten, wenn das Fenster zu ist; ein kleines natives Programm ohne Laufzeit ist dafür robuster.

## Was es tut

- **Sync-Root** `%USERPROFILE%\GateControl Drive`, je Bereich ein Unterordner („Meine Dateien“, „Familie“, Team-Ordner,
  …), registriert über `StorageProviderSyncRootManager.Register` (Anzeigename „GateControl Drive“, Symbol des
  Pro-Clients aus der Exe, Eintrag im Navigationsbereich). Klappt WinRT nicht, `CfRegisterSyncRoot`.
- **Platzhalter** für alle Ordner und Dateien der Bereiche (Größe, Zeiten; Identität = Knoten-ID, `rev`, Bereich,
  Medien-ID). Öffnen einer Datei → `FETCH_DATA` → Download des angefragten Pflichtbereichs mit HTTP Range →
  `CfExecute TRANSFER_DATA` in Stücken zu 1 MiB, Fortschritt per `CfReportProviderProgress` (Windows zeigt ihn an).
  Windows schickt für große Dateien mehrere Anfragen parallel (bis zu 4 werden gleichzeitig geladen); eine von Windows
  beendete Anfrage (0x8007018E) gilt nicht als Fehler. `CANCEL_FETCH_DATA` bricht ab.
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
- **Abmelden** (`unregister` über die Pipe = „Ausschalten“ in der Oberfläche): zuerst wird geprüft, dass nichts
  verloren geht – liegt ein Windows-Ordner im Drive, Fehler `relocated` (erst zurücklegen); dann wird Ausstehendes
  hochgeladen, und bleibt eine Änderung übrig (neue oder geänderte Datei, z. B. offen oder offline), Fehler `unsynced`
  mit den Pfaden – es bleibt alles an. Erst mit `force` (in der Oberfläche „Trotzdem ausschalten“) bleiben solche
  Dateien als normale Dateien im Ordner; nicht vollständig geladene, geänderte Dateien werden vorher geladen. Danach:
  Platzhalter „nur online“ werden gelöscht (sie sind im Drive), geladene und angeheftete Dateien bleiben als normale
  Dateien, Kontextmenü und Sync-Root werden abgemeldet. `gc-drive-sync.exe unregister` (Deinstallation) arbeitet wie
  `force`: nichts wird gelöscht, was nur lokal ist. Verlegte Windows-Ordner lehnen aber auch hier ab (`relocated`,
  Exit-Code 4) – auch `force` meldet dann nichts ab.
- **Start mit Benutzerrechten** (`launch`, `src/win/launch.rs`): Der Pro-Client läuft mit Administratorrechten
  (`requireAdministrator`), gc-drive-sync soll aber als der angemeldete Benutzer laufen – sonst gehörten neue Dateien
  der Gruppe Administratoren und `SHSetKnownFolderPath` träfe nicht das richtige Profil. Der Starter nimmt das Token
  der Shell (Explorer, `GetShellWindow`) und startet `run` mit `CreateProcessWithTokenW` (Dienst „Sekundäre Anmeldung“);
  ist der abgeschaltet, mit dem Explorer als Elternprozess (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, Standard-Handles
  werden dafür kurz in den Explorer dupliziert). Läuft nichts erhöht (Benutzerkontensteuerung aus, Test) oder gibt es
  keine Shell, läuft der Dienst im Starter selbst – mit `elevated: true` im Status (die Oberfläche zeigt es); läuft der
  Pro-Client dabei als anderes Konto („Als Administrator“ mit fremdem Konto), Fehler `wrong_user` statt einer Sync-Root
  im falschen Profil. Erwogen und verworfen: eine geplante Aufgabe „nur wenn angemeldet“ – ohne stdout (die
  Pipe-Adresse), ohne Prozess-ID, Argumente je Start in der Aufgabe. Der Starter reicht die `ready`-Zeile (geprüfte
  Prozess-ID, `launch`, `elevated`) weiter und bleibt als Wächter; das Kind liest stdin (`--watch-stdin`) und endet
  sauber, wenn der Starter endet. Die Pipe-ACL nimmt zusätzlich das Konto des Pro-Clients auf, wenn es ein anderes ist
  (`--client-sid`).
- **Windows-Ordner verlegen** (`relocate` / `restore`, `src/core/relocate.rs`, `src/win/known.rs`): Desktop, Dokumente,
  Bilder, Videos, Musik nach `GateControl Drive\<Meine Dateien>\<Name>` – nur auf ausdrücklichen Wunsch je Ordner in der
  Oberfläche. Jeder Eintrag wird einzeln verschoben (anderes Laufwerk: erst kopieren, dann das Original löschen);
  scheitert einer (Datei geöffnet), wandert alles zurück; erst danach `SHSetKnownFolderPath`, scheitert das, ebenfalls
  zurück. Gleichnamiges im Drive (anderer PC) wird nicht überschrieben (Konfliktname). Zurücklegen: Ausstehendes hoch,
  alles vollständig laden (scheitert eine Datei, bricht es ab, bevor sich etwas ändert), Platzhalter zurückverwandeln
  (so löst das Herausschieben kein Löschen beim Server aus), an den alten Ort, Pfad zurück; die Einträge verlassen den
  Zustand, der nächste Abgleich legt den Drive-Ordner wieder „nur online“ an – im Drive bleibt alles. Ein Ordner, den
  „Ordner sichern“ (W2) sichert, wird nicht verlegt und umgekehrt (Pro-Client: Oberfläche und Hauptprozess).
- **Explorer-Kontextmenü** „GateControl Drive ›“ mit „Link teilen …“, „Im Portal öffnen“, „Ältere Versionen“
  (`src/win/shellmenu.rs`, `src/win/actions.rs`): ohne Shell-Erweiterungs-DLL als statische Verben unter
  `HKCU\Software\Classes\*\shell` und `…\Directory\shell`, begrenzt auf den Sync-Root (`AppliesTo`). Ein Eintrag ruft
  `gc-drive-sync.exe action <a> "%1"` (Benutzerrechte, keine UAC-Abfrage) → Aktions-Pipe des laufenden Dienstes →
  Ereignis `action` an den Pro-Client, der den Dialog der Drive-Seite öffnet. Läuft nichts, startet der Aufruf den
  Pro-Client mit `--drive-action <a> --drive-path <p>` (UAC, weil der Pro-Client Administratorrechte braucht;
  läuft er schon, kommt es über Electrons second-instance an). Unter Windows 11 stehen statische Verben unter
  „Weitere Optionen anzeigen“; ins neue Menü kämen sie nur mit Paket-Identität (MSIX). Entfernt beim Abmelden.
- **Massenlöschung** (Explorer und offline): Löschungen werden gesammelt, bis 2 s Ruhe ist; betreffen sie mehr als 500
  Dateien oder mehr als 20 % (ab 10; ein Ordner zählt mit allen Dateien darunter, innerhalb von 60 s zusammengezählt),
  gehen sie nicht an den Server, sondern warten (Status `massDelete`) auf „Löschen übertragen“ oder „Wiederherstellen“
  (Befehl `deletes`). Weitere Löschungen während der Nachfrage warten mit.
- **Leere Dateien** (Drive 1.5, nur wenn `me.features` `emptyFiles` nennt): gehen ohne Medium hoch
  (`uploads/commit { size: 0 }`); leere Platzhalter brauchen kein Laden. Ältere Drives: wie bisher ausgelassen.
- **Schutz vor Erpressungstrojanern** (Drive 1.6 `guard`, `src/core/guard.rs`): Jeder Commit nennt die Entropie der
  ersten 64 KB (`entropy`). Lehnt Drive Schreibanfragen mit 423 `device_locked` ab (oder meldet `me.guard.locked`, oder
  der Pro-Client schickt `guard {locked: true}`), lädt das Programm sofort nichts mehr hoch und löscht nichts (Zustand
  `locked`), bis Drive das Gerät freigibt; nach „Rückgängig machen“ (`guard {undo: true}`) kommen die Fassungen aus
  Drive, lokal abweichende bleiben als zurückgehaltene Konfliktkopie. Vor dem Hochladen prüft es selbst: werden viele
  bestehende Dateien plötzlich hoch-entropisch oder bekommen eine Ransomware-Endung (≥ 50 oder ≥ 20 % eines Ordners mit
  ≥ 20 Dateien, 10-Minuten-Fenster), geht nichts hoch (Zustand `suspect`, Befehl `suspect upload|keep`).

### Richtlinien der Sync-Root

| Richtlinie | Wahl | Warum |
|---|---|---|
| Hydration | **Progressive** | Programme lesen, sobald der angefragte Bereich da ist (Videos, große PDFs starten sofort); Windows fordert Bereiche an, der Server liefert Range. „Full“ würde jedes Öffnen bis zum letzten Byte warten lassen. |
| Population | **AlwaysFull** | Das Programm legt alle Platzhalter selbst an. Das Änderungsprotokoll des Plugins liefert ohnehin alle Änderungen der sichtbaren Bereiche; ein vollständiger lokaler Baum macht Suche, Offline-Ansicht und Umbenennen/Verschieben einfach und schnell, und der Explorer wartet nie auf einen `FETCH_PLACEHOLDERS`-Rückruf übers Netz. Preis: der erste Abgleich listet alle Ordner (Seiten zu 1000). „Partial/Full“ (bei Bedarf) lohnt erst bei sehr großen Bäumen – siehe Grenzen. |
| In-Sync | Default | Inhaltsänderungen löschen „in sync“, der Abgleich lädt dann hoch. |

### Was bewusst nicht abgeglichen wird

- Kinder-Ordner, die ein Elternteil nur **einsehen** darf (`via: parent`): Jedes Auflisten meldet dem Kind
  „angesehen“ – im Hintergrund wäre das täglich.
- Leere Dateien auf Drives vor 1.5 (der Medien-Upload nimmt 0 Byte nicht an) – sobald Inhalt da ist, geht die Datei
  hoch.
- Sperr- und Zwischendateien (`~$…`, `.~lock.…#`, `*.tmp`, `*.crdownload`, `desktop.ini`, `Thumbs.db`).
- Namen, die Windows nicht kennt (z. B. `CON.txt`) – Fehler `name_unsupported` im Status.
- Dateien direkt im Sync-Root (außerhalb eines Bereichs) – Fehler `outside_area`.
- Massenlöschung (> 500 Dateien oder > 20 %), im Explorer oder während das Programm nicht lief: nicht übertragen, bis
  die Antwort kommt (siehe oben).

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
  relocate.rs      Windows-Ordner verlegen / zurücklegen, belegter Platz
  service.rs       Befehle, Abgleich-Thread, Rückruf-Logik, Download-Threads, Status
  testing.rs       FakeDrive (Plugin im Speicher) und FakeFs (Platzhalter im Speicher)
src/win/           Windows
  syncroot.rs      Registrieren/Abmelden
  cfapi.rs         CfConnectSyncRoot + Rückrufe
  winfs.rs         Platzhalter (CfCreatePlaceholders, CfUpdatePlaceholder, CfConvertToPlaceholder, …)
  watcher.rs       ReadDirectoryChangesW
  pipe.rs          benannte Pipe mit ACL
  launch.rs        Start mit Benutzerrechten aus dem erhöhten Pro-Client (Token der Shell)
  known.rs         Windows-Ordner (SHGetKnownFolderPath / SHSetKnownFolderPath)
  shellmenu.rs     Explorer-Kontextmenü (Registry, HKCU)
  actions.rs       Aktions-Pipe des Kontextmenüs
  main.rs          Programmstart (run | launch | unregister | info | action)
tests/
  api_http.rs      ApiClient gegen einen HTTP-Fake des Plugins (tiny_http): Routen, Token, Fehler, Upload, Range
  cfapi_windows.rs echte Sync-Root (nur Windows), siehe CI
  launch_windows.rs Start über den Starter (nur Windows)
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

CI (`.github/workflows/drive-sync.yml`): Linux – Format, Clippy, Tests; Windows – Clippy, Tests, Release-Build, der
Starter-Test (`launch`: Pipe-Übergabe, Startweg in der Zusammenfassung) und der Integrations-Test mit echter
Sync-Root gegen den Fake-Server (registrieren, Platzhalter, Öffnen aus einem anderen Prozess → Laden, Speicher
freigeben, anheften → Laden, neue lokale Datei → Upload, Server-Änderung → `sync-now`, Kontextmenü in der Registry
und über die Aktions-Pipe, Massenlöschung aus einem anderen Prozess → Nachfrage → Wiederherstellen, Windows-Ordner
verlegen und zurücklegen mit einem Test-Ordner statt der echten Windows-Ordner, Abmelden mit offener Datei abgelehnt,
abmelden). Ist die Cloud Files API auf dem Runner nicht nutzbar, steht `CFAPI-SKIPPED: <Grund>` im Log
und als Warnung in der Zusammenfassung – der Test meldet dann kein „bestanden“.

Release (`release.yml`): `cargo build --release` vor electron-builder; `package.json` → `extraResources` legt
`gc-drive-sync.exe` nach `resources\drive-sync\` (Installer und Portable). Signatur wie bei der App: kein
Authenticode-Zertifikat im Projekt; der Installer ist über das Ed25519-signierte Update-Manifest abgesichert, damit
auch die darin enthaltene `gc-drive-sync.exe`. Beim Deinstallieren ruft `build/installer.nsh`
`gc-drive-sync.exe unregister` auf. Vorher (`customUnInit`, nur echte Deinstallation, kein Update) prüft es mit
`gc-drive-sync.exe relocated`, ob Windows-Ordner im Drive liegen; dann bricht die Deinstallation mit Hinweis ab
(„Drive › Ordner sichern“ → zurücklegen), auch still (`/S`, Exit-Code 4), und es wird nichts abgemeldet.

## Grenzen

- **Ohne Authenticode**: SmartScreen/Defender kennen die Exe nicht; wie bei der App.
- **Benutzerrechte**: Programme desselben Benutzers können die Pipe öffnen (wenn der Pro-Client gerade nicht verbunden
  ist) und den Speicher des Prozesses lesen – wie bei jedem Sync-Programm auf Benutzerebene; andere Benutzer und das
  Netz nicht. Ohne Shell oder bei abgeschalteter Benutzerkontensteuerung läuft es erhöht (Hinweis in der Oberfläche).
- **Nur solange der Pro-Client läuft** (Fenster darf zu sein); ohne ihn lassen sich nur geladene Dateien öffnen.
- **Konto-/Serverwechsel**: neuer Zustand je Server; vorher `unregister` (W3b: automatisch beim Abmelden).
- **Sehr große Bäume** (≫ 100 000 Einträge): erster Abgleich listet alles; ggf. später Population „Full“.
- **Löschen offline**: Löschungen, während der Server nicht erreichbar ist, werden lokal ausgeführt und beim nächsten
  Abgleich übertragen (Papierkorb des Servers); umgekehrt gewinnt eine Server-Änderung gegen eine lokale Löschung.
- **Verlegte Windows-Ordner**: der Desktop zeigt den neuen Ort manchmal erst nach dem nächsten Anmelden. Verlegen
  mehrere PCs denselben Ordner, ist er auf allen derselbe (gewollt, wie OneDrive).
- **Kontextmenü**: „Im Portal öffnen“ öffnet die Drive-Seite des Portals, nicht die Datei (das Portal hat keinen
  Sprung zu einer Datei). Ohne laufendes Programm fragt Windows nach Administratorrechten (Start des Pro-Clients).
- **Verzögertes Löschen** (Drive 1.5 `deleteAfter`) nutzt gc-drive-sync nicht: Löschen geht in den Papierkorb des
  Servers.
