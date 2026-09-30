'use strict';

/**
 * Statische Pruefung des NSIS-Deinstaller-Skripts (NSIS laeuft nicht unter
 * Linux/CI). Stellt sicher, dass beim Deinstallieren die Kill-Switch-Regeln
 * entfernt und die Outbound-Policy wiederhergestellt wird.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const NSH_PATH = path.join(ROOT, 'build/installer.nsh');
const nsh = fs.readFileSync(NSH_PATH, 'utf8');
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

// Kommentare entfernen, damit nur ausfuehrbarer Code geprueft wird.
const code = nsh.split('\n').filter(l => !/^\s*;/.test(l)).join('\n');

// Edition dieser App (Kill-Switch-Regelpraefix, siehe core editions.js)
const EDITION = 'pro';
const OWN_PREFIX = 'GateControl_Pro_KS';
const OTHER_PREFIX = 'GateControl_Community_KS';
const LEGACY_PREFIX = 'GateControl_KS';

// !define NAME "WERT" aus dem Skript
const defines = Object.fromEntries([...code.matchAll(/^!define (\w+) "([^"]*)"/gm)].map(m => [m[1], m[2]]));
// ${NAME} durch den Define-Wert ersetzen (wie makensis beim Kompilieren)
const resolveDefines = (s) => s.replace(/\$\{(GC_[A-Z_]+)\}/g, (m, n) => (n in defines ? defines[n] : m));

// Alle PowerShell-Befehle des Kill-Switch-Aufraeumens (Defines aufgeloest)
function psCommands() {
  const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
  const cmds = [...body.matchAll(/-Command "([^"]*)"/g)].map(m => resolveDefines(m[1]));
  assert.ok(cmds.length > 0, 'kein PowerShell-Befehl gefunden');
  return cmds;
}

function coreModule(rel) {
  const candidates = [];
  try { candidates.push(require.resolve('@gatecontrol/client-core/' + rel)); } catch { /* nicht installiert */ }
  candidates.push(path.join(ROOT, '..', 'gatecontrol-client-core', rel));
  return candidates.find(c => fs.existsSync(c)) || null;
}

function macroBody(name) {
  const m = code.match(new RegExp('!macro ' + name + '\\b[^\\n]*\\n([\\s\\S]*?)!macroend'));
  assert.ok(m, 'Makro ' + name + ' fehlt');
  return m[1];
}

function coreKillswitchSource() {
  const file = coreModule('src/services/killswitch.js');
  return file ? fs.readFileSync(file, 'utf8') : null;
}

// Dateiname der App-Exe, wie electron-builder ihn bildet
// (appInfo.productFilename: win.executableName ?? executableName ?? productName).
function expectedExeFilename() {
  const b = pkg.build || {};
  const name = (b.win && b.win.executableName) || b.executableName || b.productName || pkg.productName || pkg.name;
  return name + '.exe';
}

// Alle Verweise auf eine Exe im Installationsverzeichnis ($INSTDIR\...exe).
function instdirExeRefs() {
  return [...code.matchAll(/\$INSTDIR\\([^"'\r\n]*?\.exe)/gi)].map(m => m[1]);
}

describe('NSIS installer script (build/installer.nsh)', () => {
  it('is wired into electron-builder via nsis.include', () => {
    assert.equal(pkg.build.nsis.include, 'build/installer.nsh');
  });

  it('is plain ASCII (makensis reads files without BOM as ANSI)', () => {
    assert.ok(!/[^\x00-\x7F]/.test(nsh), 'Nicht-ASCII-Zeichen im Skript');
  });

  it('customUnInstall runs the kill-switch cleanup, but not on updates', () => {
    const body = macroBody('customUnInstall');
    assert.match(body, /\$\{IfNot\} \$\{isUpdated\}\s+(;[^\n]*\s+)?!insertmacro GC_CLEANUP_KILLSWITCH_FIREWALL/);
  });

  it('uses this edition\'s kill-switch prefix, derived like the core does', () => {
    assert.equal(defines.GC_KS_PREFIX, OWN_PREFIX);
    const editionsFile = coreModule('src/services/editions.js');
    if (!editionsFile) return;
    const editions = require(editionsFile);
    assert.equal(editions.killSwitchRulePrefix(EDITION), OWN_PREFIX);
    assert.equal(editions.LEGACY_KILLSWITCH_RULE_PREFIX, LEGACY_PREFIX);
    // Die eigene Edition im Core passt zur package.json dieser App
    const own = editions.getEdition(EDITION);
    assert.equal(own.appId, pkg.build.appId);
    assert.equal(own.productName, pkg.build.productName);
    // Die andere Edition: GUID/productName fuer die Erkennung im Deinstaller
    const [other] = editions.otherEditions(EDITION);
    assert.equal(editions.killSwitchRulePrefix(other.id), OTHER_PREFIX);
    assert.equal(defines.GC_OTHER_EDITION_GUID, other.guid);
    assert.equal(defines.GC_OTHER_EDITION_PRODUCT, other.productName);
  });

  it('core edition GUIDs match electron-builder\'s UUID v5 of the appId', (t) => {
    const editionsFile = coreModule('src/services/editions.js');
    let UUID;
    try { ({ UUID } = require('builder-util-runtime')); } catch { /* nicht installiert */ }
    if (!editionsFile || !UUID) { t.skip('core oder builder-util-runtime nicht gefunden'); return; }
    const ns = UUID.parse('50e065bc-3134-11e6-9bab-38c9862bdaf3');
    for (const e of Object.values(require(editionsFile).EDITIONS)) {
      assert.equal(e.guid, UUID.v5(e.appId, ns), e.id);
    }
  });

  it('main process passes its edition to the core kill switch', () => {
    const main = fs.readFileSync(path.join(ROOT, 'src/main/main.js'), 'utf8');
    assert.match(main, /killSwitchSvc = new KillSwitch\(log, \{ edition: 'pro' \}\)/);
    assert.ok(!/new KillSwitch\(log\)/.test(main), 'KillSwitch ohne Edition erzeugt');
  });

  it('never references the other edition\'s kill-switch prefix', () => {
    assert.ok(!resolveDefines(code).includes(OTHER_PREFIX), OTHER_PREFIX + ' im Skript');
    // Auch nicht per Wildcard: das Legacy-Muster passt nicht auf neue Namen
    assert.ok(!(OTHER_PREFIX + '_Allow_API').startsWith(LEGACY_PREFIX + '_'));
    assert.ok(!(OWN_PREFIX + '_Allow_API').startsWith(LEGACY_PREFIX + '_'));
    assert.ok(!resolveDefines(code).includes("-like 'GateControl_*'"));
    assert.ok(!/-like '[^']*\*[^']*_KS_/.test(resolveDefines(code)), 'Wildcard vor _KS_ wuerde fremde Praefixe treffen');
  });

  it('finds kill-switch rules by DisplayName prefix via PowerShell', () => {
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    for (const ps of psCommands()) {
      assert.match(ps, new RegExp("Get-NetFirewallRule -PolicyStore PersistentStore \\| Where-Object \\{ \\$\\$_\\.DisplayName -like '" + OWN_PREFIX + "_\\*'"));
      assert.match(ps, /\$\$ks \| Remove-NetFirewallRule/);
    }
    assert.match(body, /!insertmacro GC_NETSH_DELETE_KS_RULES \$\{GC_KS_PREFIX\}/);
  });

  it('removes legacy GateControl_KS_ rules only when the other edition is absent', () => {
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    // Erkennung laeuft vor dem Aufraeumen
    assert.ok(body.indexOf('!insertmacro GC_DETECT_OTHER_EDITION') >= 0);
    assert.ok(body.indexOf('!insertmacro GC_DETECT_OTHER_EDITION') < body.indexOf('-Command'));
    // PowerShell: genau ein Befehl mit Legacy-Muster, im Zweig "$6 != 1"
    const withLegacy = psCommands().filter(ps => ps.includes("'" + LEGACY_PREFIX + "_*'"));
    assert.equal(withLegacy.length, 1);
    // Der If-Zweig darf kein ${EndIf} ueberspringen (erste $6-Abfrage ist nur DetailPrint)
    const m = body.match(/\$\{If\} \$6 == 1\n((?:(?!\$\{EndIf\})[\s\S])*?)\$\{Else\}\n([\s\S]*?)\$\{EndIf\}/);
    assert.ok(m, 'Verzweigung ueber $6 fehlt');
    assert.ok(!m[1].includes(LEGACY_PREFIX + '_*'), 'Legacy-Muster im Zweig "andere Edition vorhanden"');
    assert.ok(m[2].includes("-like '" + LEGACY_PREFIX + "_*'"));
    // netsh-Fallback: Altregeln nur bei $6 == 0
    assert.match(body, /\$\{If\} \$6 == 0\s+!insertmacro GC_NETSH_DELETE_KS_RULES GateControl_KS\s+\$\{EndIf\}/);
    assert.equal([...body.matchAll(/GC_NETSH_DELETE_KS_RULES GateControl_KS\b/g)].length, 1);
  });

  it('detects the other edition via registry, install dir and running process (fail-safe)', () => {
    const det = macroBody('GC_DETECT_OTHER_EDITION');
    assert.match(det, /StrCpy \$6 0/);
    for (const root of ['HKLM', 'HKCU']) {
      assert.match(det, new RegExp('ReadRegStr \\$4 ' + root + ' "Software\\\\\\$\\{GC_OTHER_EDITION_GUID\\}" InstallLocation'));
    }
    assert.match(det, /\$\{FileExists\} "\$PROGRAMFILES64\\\$\{GC_OTHER_EDITION_PRODUCT\}\\\$\{GC_OTHER_EDITION_PRODUCT\}\.exe"/);
    assert.match(det, /tasklist\.exe" \/FI "IMAGENAME eq \$\{GC_OTHER_EDITION_PRODUCT\}\.exe"/);
    // tasklist nicht ausfuehrbar -> als vorhanden werten
    assert.match(det, /\$\{If\} \$3 != 0\s+StrCpy \$6 1/);
    // $6 wird gesichert und wiederhergestellt
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    assert.match(body, /Push \$6/);
    assert.match(body, /Pop \$6/);
  });

  it('restores outbound policy only when kill-switch rules existed, keeping inbound', () => {
    for (const ps of psCommands()) {
    // Keine Regeln -> sofort beenden, bevor die Policy angefasst wird
    const early = ps.indexOf('if ($$ks.Count -eq 0) { exit 0 }');
    assert.ok(early > 0 && early < ps.indexOf('Set-NetFirewallProfile'));
    assert.match(ps, /foreach \(\$\$p in 'Domain','Private','Public'\)/);
    assert.match(ps, /DefaultOutboundAction -eq 'Block'\) \{ Set-NetFirewallProfile -PolicyStore PersistentStore -Name \$\$p -DefaultOutboundAction Allow \}/);
    // Nur Outbound setzen, Inbound nie
    assert.ok(!/DefaultInboundAction|AllowInboundRules/.test(ps));
    // Policy zuruecksetzen, bevor die Regeln geloescht werden
    assert.ok(ps.indexOf('Set-NetFirewallProfile') < ps.indexOf('Remove-NetFirewallRule'));
    }
  });

  it('never reads the user-writable kill-switch state file', () => {
    assert.ok(!/killswitch-state/i.test(code));
    assert.ok(!/APPDATA|LOCALAPPDATA/.test(code));
  });

  it('escapes every PowerShell variable as $$ for NSIS', () => {
    for (const ps of psCommands()) {
    // Jedes $ im PowerShell-Teil muss verdoppelt sein
    const unescaped = ps.replace(/\$\$/g, '').match(/\$/g);
    assert.equal(unescaped, null, 'einfaches $ im PowerShell-Befehl: ' + ps);
    for (const v of ['ErrorActionPreference', 'ks', '_', 'p']) {
      assert.ok(ps.includes('$$' + v), 'PowerShell-Variable $' + v + ' fehlt/unescaped');
    }
    }
  });

  it('falls back to netsh and keeps the inbound part of the policy', () => {
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    assert.match(body, /\$\{If\} \$3 == 10/);
    assert.match(body, /\$\{ElseIf\} \$3 == 0/);
    for (const p of ['domain', 'private', 'public']) {
      assert.match(body, new RegExp('!insertmacro GC_NETSH_RESTORE_OUTBOUND ' + p + '\\b'));
    }
    const restore = macroBody('GC_NETSH_RESTORE_OUTBOUND');
    for (const inbound of ['BlockInboundAlways', 'BlockInbound', 'AllowInbound', 'NotConfigured']) {
      assert.match(restore, new RegExp('GC_NETSH_RESTORE_OUTBOUND_IF \\$\\{PROFILE\\} ' + inbound + '\\n'));
    }
    const restoreIf = macroBody('GC_NETSH_RESTORE_OUTBOUND_IF');
    assert.match(restoreIf, /firewallpolicy \$\{INBOUND\},allowoutbound/);
  });

  it('netsh fallback covers every fixed rule name the core kill switch creates', (t) => {
    const src = coreKillswitchSource();
    if (!src) { t.skip('gatecontrol-client-core nicht gefunden'); return; }
    const names = new Set();
    for (const m of src.matchAll(/`\$\{this\.rulePrefix\}(_[A-Za-z0-9_]+)`/g)) names.add(m[1]);
    // LAN-Regeln werden in einer Schleife ueber feste Subnetze erzeugt
    const lan = src.match(/for \(const subnet of \[([^\]]+)\]\)/);
    assert.ok(lan, 'LAN-Subnetzliste im Core nicht gefunden');
    for (const s of lan[1].match(/'[^']+'/g)) {
      const suffix = s.slice(1, -1).replace(/[./]/g, '_');
      names.add('_Allow_LAN_' + suffix);
      names.add('_Allow_LAN_In_' + suffix);
    }
    assert.ok(names.size >= 10, 'zu wenige Regelnamen aus dem Core extrahiert');
    // Namen im Makro GC_NETSH_DELETE_KS_RULES sind "${PREFIX}<Suffix>"
    const fallback = new Set([...macroBody('GC_NETSH_DELETE_KS_RULES').matchAll(/!insertmacro GC_NETSH_DELETE_KS_RULE \$\{PREFIX\}(\S+)/g)].map(m => m[1]));
    for (const n of names) assert.ok(fallback.has(n), 'Fallback-Loeschliste fehlt <Praefix>' + n);
  });

  it('references the app exe only by its real file name', () => {
    const exe = expectedExeFilename();
    // electron-builder: !define APP_EXECUTABLE_FILENAME "${PRODUCT_FILENAME}.exe"
    const resolved = instdirExeRefs().map(r => r.replace('${APP_EXECUTABLE_FILENAME}', exe));
    for (const ref of resolved) {
      assert.equal(ref, exe, 'falscher Exe-Pfad $INSTDIR\\' + ref + ' (erwartet ' + exe + ')');
    }
  });

  it('customInstall allows the real app exe (not "GateControl Pro.exe") through the firewall', () => {
    assert.equal(expectedExeFilename(), 'GateControl Pro Client.exe');
    const body = macroBody('customInstall');
    const m = body.match(/add rule name="GateControl Pro WireGuard"[^\n]*program="\$INSTDIR\\([^"]+)"/);
    assert.ok(m, 'Firewall-Regel "GateControl Pro WireGuard" mit $INSTDIR-Programm fehlt');
    assert.equal(m[1].replace('${APP_EXECUTABLE_FILENAME}', expectedExeFilename()), expectedExeFilename());
    assert.ok(!/GateControl Pro\.exe/.test(code), 'veralteter Exe-Name "GateControl Pro.exe" im Skript');
  });

  it('release workflow patches the real app exe in win-unpacked', () => {
    const wf = fs.readFileSync(path.join(ROOT, '.github/workflows/release.yml'), 'utf8');
    const refs = [...wf.matchAll(/win-unpacked\/([^"'\n]+\.exe)/g)].map(m => m[1]);
    assert.ok(refs.length > 0, 'kein win-unpacked-Exe-Pfad in release.yml gefunden');
    for (const ref of refs) assert.equal(ref, expectedExeFilename());
  });
});
