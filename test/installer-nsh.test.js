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

function macroBody(name) {
  const m = code.match(new RegExp('!macro ' + name + '\\b[^\\n]*\\n([\\s\\S]*?)!macroend'));
  assert.ok(m, 'Makro ' + name + ' fehlt');
  return m[1];
}

function coreKillswitchSource() {
  const candidates = [];
  try { candidates.push(require.resolve('@gatecontrol/client-core/src/services/killswitch.js')); } catch { /* nicht installiert */ }
  candidates.push(path.join(ROOT, '..', 'gatecontrol-client-core', 'src', 'services', 'killswitch.js'));
  for (const c of candidates) {
    if (fs.existsSync(c)) return fs.readFileSync(c, 'utf8');
  }
  return null;
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

  it('finds kill-switch rules by DisplayName prefix via PowerShell', () => {
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    assert.match(body, /Get-NetFirewallRule -PolicyStore PersistentStore \| Where-Object \{ \$\$_\.DisplayName -like 'GateControl_KS_\*' \}/);
    assert.match(body, /\$\$ks \| Remove-NetFirewallRule/);
  });

  it('restores outbound policy only when kill-switch rules existed, keeping inbound', () => {
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    const ps = body.match(/-Command "([^"]*)"/)[1];
    // Keine Regeln -> sofort beenden, bevor die Policy angefasst wird
    const early = ps.indexOf('if ($$ks.Count -eq 0) { exit 0 }');
    assert.ok(early > 0 && early < ps.indexOf('Set-NetFirewallProfile'));
    assert.match(ps, /foreach \(\$\$p in 'Domain','Private','Public'\)/);
    assert.match(ps, /DefaultOutboundAction -eq 'Block'\) \{ Set-NetFirewallProfile -PolicyStore PersistentStore -Name \$\$p -DefaultOutboundAction Allow \}/);
    // Nur Outbound setzen, Inbound nie
    assert.ok(!/DefaultInboundAction|AllowInboundRules/.test(ps));
    // Policy zuruecksetzen, bevor die Regeln geloescht werden
    assert.ok(ps.indexOf('Set-NetFirewallProfile') < ps.indexOf('Remove-NetFirewallRule'));
  });

  it('never reads the user-writable kill-switch state file', () => {
    assert.ok(!/killswitch-state/i.test(code));
    assert.ok(!/APPDATA|LOCALAPPDATA/.test(code));
  });

  it('escapes every PowerShell variable as $$ for NSIS', () => {
    const body = macroBody('GC_CLEANUP_KILLSWITCH_FIREWALL');
    const ps = body.match(/-Command "([^"]*)"/)[1];
    // Jedes $ im PowerShell-Teil muss verdoppelt sein
    const unescaped = ps.replace(/\$\$/g, '').match(/\$/g);
    assert.equal(unescaped, null, 'einfaches $ im PowerShell-Befehl: ' + ps);
    for (const v of ['ErrorActionPreference', 'ks', '_', 'p']) {
      assert.ok(ps.includes('$$' + v), 'PowerShell-Variable $' + v + ' fehlt/unescaped');
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
    for (const m of src.matchAll(/`\$\{this\.rulePrefix\}(_[A-Za-z0-9_]+)`/g)) names.add('GateControl_KS' + m[1]);
    // LAN-Regeln werden in einer Schleife ueber feste Subnetze erzeugt
    const lan = src.match(/for \(const subnet of \[([^\]]+)\]\)/);
    assert.ok(lan, 'LAN-Subnetzliste im Core nicht gefunden');
    for (const s of lan[1].match(/'[^']+'/g)) {
      const suffix = s.slice(1, -1).replace(/[./]/g, '_');
      names.add('GateControl_KS_Allow_LAN_' + suffix);
      names.add('GateControl_KS_Allow_LAN_In_' + suffix);
    }
    assert.ok(names.size >= 10, 'zu wenige Regelnamen aus dem Core extrahiert');
    const fallback = new Set([...code.matchAll(/!insertmacro GC_NETSH_DELETE_KS_RULE (\S+)/g)].map(m => m[1]));
    for (const n of names) assert.ok(fallback.has(n), 'Fallback-Loeschliste fehlt ' + n);
  });
});
