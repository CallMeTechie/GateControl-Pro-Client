# Pipe-Protokoll Pro-Client ↔ gc-drive-sync

Version 3. Der Pro-Client (`src/main/drive-ondemand.js`) startet `gc-drive-sync.exe` und spricht mit ihm über eine
benannte Pipe. (Version 1 → 2: `launch`, `unregister` mit Prüfung, `deletes`, `known-folders`, `relocate`, `restore`,
`usage`, `action`, Ereignisse `progress` und `action`, Status `massDelete`/`elevated`, Fehler mit `data`. Version 2 → 3:
`guard`, `suspect`, Zustände `locked`/`suspect`, Status `locked`/`suspect`/`held`, `entropy` im Commit an Drives mit `guard`.) Server-Adresse und Geräte-Token gehen **nur** über diese Pipe – nie über die Kommandozeile, die Umgebung
oder eine Datei. gc-drive-sync hält das Token nur im Speicher; nach einem Neustart schickt der Pro-Client es erneut.

## Start und Verbindung

```
gc-drive-sync.exe launch --parent-pid <pid des Pro-Clients>
```

`launch` startet `run` mit den Rechten des angemeldeten Benutzers (README, „Start mit Benutzerrechten“) und bleibt als
Wächter, bis das Kind endet; `run --parent-pid …` geht weiter direkt (dann mit den Rechten des Aufrufers). Die
**erste Zeile auf stdout** nennt die Pipe:

```json
{"event":"ready","pipe":"\\\\.\\pipe\\gatecontrol-drive-sync-S-1-5-21-…-1001-3f9c…e1","pid":4242,"version":"0.1.0","protocol":3,"launch":"token","elevated":false}
```

`launch`: `token` (CreateProcessWithTokenW), `parent` (Explorer als Elternprozess), `inprocess` (im Starter);
`elevated`: der Dienst läuft mit Administratorrechten.

Bei einem Fehler steht dort stattdessen `{"event":"error","code":"already_running"|"pipe"|"sid"|"mutex"|"parent"|"launch"|"wrong_user","message":"…"}`
und das Programm endet (Exit-Code 3 bei `already_running`, sonst 1).

Die Pipe:

| Eigenschaft | Wert |
|---|---|
| Name | `\\.\pipe\gatecontrol-drive-sync-<SID des Benutzers>-<128 Bit Zufall, hex>` – neu bei jedem Start, steht nur auf stdout des Programms |
| Zugriff | DACL `D:P(A;;GA;;;<SID>)(A;;GA;;;SY)`: nur der angemeldete Benutzer und SYSTEM; geerbte Rechte gesperrt. Läuft der Pro-Client als anderes Konto, nimmt `launch` dessen SID dazu (`--client-sid`) |
| Netz | `PIPE_REJECT_REMOTE_CLIENTS` |
| Übernahme | `FILE_FLAG_FIRST_PIPE_INSTANCE`: existiert der Name schon, startet das Programm nicht |
| Instanzen | eine; nach dem Trennen wird dieselbe Instanz wiederverwendet (der Name wird nie frei) |

Ein Client zur Zeit. Trennt er sich, läuft der Abgleich weiter und das Programm wartet auf die nächste Verbindung
(z. B. nach einem Neustart des Fensters). Endet der Prozess `--parent-pid`, beendet sich gc-drive-sync (Sync-Root
getrennt, Platzhalter bleiben). Nur eine Instanz je Windows-Benutzer (Mutex `Local\GateControlDriveSync-<SID>`).

## Format

UTF-8, eine JSON-Nachricht pro Zeile (`\n`), höchstens 64 KiB je Zeile.

```
Anfrage    {"id": 1, "cmd": "<befehl>", …}
Antwort    {"id": 1, "ok": true, "result": {…}}
           {"id": 1, "ok": false, "error": {"code": "<code>", "message": "<text>"}}
           Fehler mit Angaben: {"id": 1, "ok": false, "error": {"code": "unsynced", "message": "…", "data": {"count": 2, "paths": […]}}}
Ereignis   {"event": "status", …}   |   {"event": "log", "level": "info|warn", "message": "…", "at": "<ISO>"}
           {"event": "progress", "op": "relocate|restore", "folder": "documents", "phase": "move|load", "done": 3, "total": 12}
           {"event": "action", "action": "share|portal|versions", "path": "C:\\…", "node": 812, "area": "mine:2", "isDir": false}
```

`id` (Zahl oder String) kommt unverändert zurück; Ereignisse haben kein `id`. Unlesbare Zeilen beantwortet das
Programm mit `bad_json`, unbekannte Befehle mit `unknown_command`.

## Befehle

| Befehl | Felder | Ergebnis | Fehler |
|---|---|---|---|
| `hello` | `version` (des Pro-Clients), `lang` (`de`/`en`, Texte des Kontextmenüs), `appExe` (Pro-Client-Exe, für das Kontextmenü, wenn gc-drive-sync nicht läuft) – alle optional | `{protocol, version, pid, syncRoot, state, elevated, knownFolders}` | – |
| `configure` | `serverUrl` (http/https, ohne Benutzer/Query), `token` (sichtbares ASCII, ≤ 4096), `deviceName` (für Konfliktnamen, ≤ 100), `headers` (optional, nur `X-Client-Version`, `X-Client-Platform`, `X-Client-Type`, `X-Machine-Fingerprint`) | `{configured: true}` – läuft der Abgleich und ändert sich etwas, startet er mit den neuen Werten neu | `invalid` |
| `start` | – | Status (s. u.): Sync-Root registrieren, verbinden, beobachten, abgleichen | `not_configured`, `register_failed`, `connect_failed`, `watch_failed` |
| `stop` | – | `{stopped: true}`: Abgleich beenden, Sync-Root trennen (Platzhalter bleiben, Öffnen geht dann nicht) | – |
| `pause` / `resume` | – | `{paused}`: keine Abfragen/Uploads; Öffnen (Laden) geht weiter | – |
| `status` | – | Status | – |
| `sync-now` | – | `{queued: true}`: sofort `changes?since=` (z. B. nach dem Push-Ereignis `changed`) | `not_running` |
| `unregister` | `force` (optional) | `{unregistered: true}`: Ausstehendes hochladen; dann Abgleich beenden, Platzhalter „nur online“ löschen, geladene Dateien als normale Dateien behalten, Kontextmenü und Sync-Root abmelden, Zustand löschen | `relocated` (`data.folders`: verlegte Windows-Ordner – erst zurücklegen), `unsynced` (`data.count`, `data.paths` ≤ 20: nicht hochgeladene Änderungen; mit `force` bleiben sie als normale Dateien), `unregister_failed` |
| `deletes` | `decision`: `apply` \| `restore` | `{decided, apply}`: zurückgehaltene Massenlöschung an den Server geben (Papierkorb) oder die Platzhalter wiederherstellen | `not_running`, `invalid` |
| `known-folders` | – | `{folders: [{key, path, inDrive, from}], syncRoot}` – `key`: `desktop` \| `documents` \| `pictures` \| `videos` \| `music`; `from`: alter Ort eines verlegten Ordners | `unsupported` |
| `relocate` | `folder` (key), `name` (optional, Ordnername im Drive) | `{folder, from, to, moved}` (Fortschritt: Ereignis `progress`) | `not_running`, `already_relocated`, `folder_missing`, `no_area`, `read_only`, `target_taken`, `move_failed` (zurückgeschoben; `data.left`: was nicht zurück konnte), `set_failed` |
| `restore` | `folder` (key) | `{folder, from, to, moved}` | `not_running`, `not_relocated`, `hydrate_failed` (nichts geändert), `revert_failed`, `move_failed`, `set_failed`, `target_taken` |
| `usage` | – | `{localBytes, totalBytes, files, localFiles, pinnedFiles}` | – |
| `action` | `action` (`share` \| `portal` \| `versions`), `path` (im Sync-Root) | `{queued: true}` + Ereignis `action` (Pro-Client mit `--drive-action` gestartet) | `invalid` |
| `guard` | `locked` (bool), `undo` (bool, optional) | `{locked, undo}`: Drive 1.6 – Drive hat das Gerät gestoppt (`locked: true`: sofort nichts mehr hochladen/löschen) bzw. freigegeben; `undo`: Drive hat die Änderungen rückgängig gemacht – der nächste Vollabgleich holt die Fassungen aus Drive, lokal abweichende bleiben als Konfliktkopie **zurückgehalten** (nicht hochgeladen), ebenso neue lokale Dateien | `not_running`, `invalid` |
| `suspect` | `decision`: `upload` \| `keep` | `{upload}`: Antwort auf die lokale Prüfung – hochladen bzw. pausiert lassen (wie `pause`) | `not_running`, `invalid` |
| `shutdown` | – | `{shutdown: true}`, danach endet das Programm | – |

## Status

Als Antwort auf `status`/`start` und als Ereignis `{"event":"status", …}` bei jeder Änderung:

```json
{
  "state": "idle",
  "pending": 0,
  "transferring": 1,
  "errors": [{"code": "read_only", "message": "Nur Lesen – nicht hochgeladen", "path": "C:\\Users\\max\\GateControl Drive\\Team\\x.txt", "at": "2026-10-27T10:00:00Z"}],
  "lastSync": "2026-10-27T10:00:00+00:00",
  "syncRoot": "C:\\Users\\max\\GateControl Drive",
  "registered": true,
  "massDelete": {"files": 640, "items": 1, "offline": false, "sample": ["C:\\Users\\max\\GateControl Drive\\Meine Dateien\\Fotos"]},
  "elevated": false,
  "locked": false,
  "suspect": {"count": 63, "sample": ["Brief.docx", "Steuer.xlsx"], "why": "entropy"},
  "held": 0
}
```

| `state` | Bedeutung |
|---|---|
| `unconfigured` | noch kein `configure` |
| `stopped` | konfiguriert, aber nicht gestartet / gestoppt |
| `starting` | gestartet, erster Kontakt zum Server steht aus |
| `syncing` | Abgleich läuft |
| `idle` | abgeglichen |
| `paused` | pausiert |
| `offline` | Server nicht erreichbar oder Token abgelehnt (401) – neuer Versuch nach 15 s … 5 min |
| `locked` | Drive 1.6 `guard`: Drive hat das Gerät gestoppt (423 `device_locked`, `me.guard.locked` oder `guard {locked: true}`) – nichts geht hoch, nichts wird gelöscht; Öffnen geht weiter; alle 5 min `me`, bis frei |
| `suspect` | lokale Prüfung angeschlagen (s. u.) – wartet auf `suspect` |
| `error` | anderer Fehler (siehe `errors`) |

`massDelete`: zurückgehaltene Massenlöschung (sonst `null`), Antwort mit `deletes`. `elevated`: läuft mit
Administratorrechten.

`suspect` (lokale Prüfung vor dem Hochladen, `src/core/guard.rs`, dieselben Regeln wie core `utils/drive-guard.js`):
viele **bestehende** Dateien wurden zu hoch-entropischem Inhalt (Entropie der ersten 64 KB > 7,5, vorher < 7,0 bzw.
unbekannt bei Dateitypen, die nicht ohnehin komprimiert sind) oder bekamen eine Ransomware-Endung – mindestens 50 oder
mindestens 20 % eines Ordners mit mindestens 20 Dateien (verdächtige Änderungen der letzten 10 Minuten zählen mit). Dann
geht nichts hoch, `why`: `entropy` | `extension`, `sample`: bis zu 5 Namen. `held`: nach `guard {undo}` zurückgehaltene
Dateien. Die Entropie jeder hochgeladenen Fassung geht als `entropy` im Commit mit (nur an Drives mit `guard`) und bleibt im
Zustand als Vergleich.

Die Textebene von PDFs liest gc-drive-sync **nicht** aus (kein PDF-Parser im Dienst mit Benutzerrechten, Größe der
Exe); der Pro-Client schickt den Text bei Uploads über die Drive-Seite und „Ordner sichern“ mit.

`pending`: wartende lokale Änderungen und Löschungen. `transferring`: laufende Uploads und Downloads (Öffnen).
Fehlercodes in `errors` u. a.: `network`, `timeout`, `http_<status>`, Codes des Plugins (`forbidden`, `quota`, …),
`read_only`, `outside_area`, `name_unsupported`, `empty_file`, `mass_delete`, `suspect`, `local_io`, `hydrate`, `dehydrate`.

## Weitere Aufrufe

```
gc-drive-sync.exe unregister [--root <dir>] [--data-dir <dir>]   Deinstallation (installer.nsh); stdout: {"unregistered":true}; liegen Windows-Ordner
                                                                 im Drive: {"unregistered":false,"error":"relocated","folders":[…]}, Exit-Code 4
gc-drive-sync.exe relocated [--data-dir <dir>]                   {"relocated":[…]}; Exit-Code 0 = keiner verlegt, 4 = verlegt (installer.nsh, customUnInit)
gc-drive-sync.exe info                                           {"cfapi":true,"build":…,"registered":…,"launch":{…},"menu":…} oder {"cfapi":false,…}
gc-drive-sync.exe action <share|portal|versions> <Pfad>          Kontextmenü → Aktions-Pipe \\.\pipe\gatecontrol-drive-actions-<SID>
                                                                 ({"action","path"} je Zeile, nur der Benutzer); läuft nichts: Pro-Client mit
                                                                 --drive-action <a> --drive-path <p> starten
gc-drive-sync.exe --version
```
