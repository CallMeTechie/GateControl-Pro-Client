'use strict';

/**
 * Ed25519-Public-Key für signierte Auto-Updates.
 *
 * Einzige Quelle ist build/update-signing.pub (SPKI-PEM). electron-builder
 * legt die Datei per extraResources nach resources/update-signing.pub; die
 * Release-Pipeline (scripts/sign-update.js) prüft ihre Signatur gegen dieselbe
 * Datei. Solange dort der Platzhalter steht, liefert loadUpdatePublicKey()
 * null und der Updater bleibt deaktiviert.
 */

const fs = require('fs');
const path = require('path');

const PLACEHOLDER = 'REPLACE_WITH_UPDATE_PUBLIC_KEY';
const FILE_NAME = 'update-signing.pub';

function candidatePaths() {
  const paths = [];
  // Installierte App: <Installationsordner>/resources/update-signing.pub
  if (process.resourcesPath) paths.push(path.join(process.resourcesPath, FILE_NAME));
  // Entwicklung (electron .) und Tests: build/update-signing.pub im Repo
  paths.push(path.join(__dirname, '..', '..', 'build', FILE_NAME));
  return paths;
}

/**
 * @param {string[]} [paths] - nur für Tests
 * @returns {string|null} PEM-Text oder null (fehlt / Platzhalter / kein PEM)
 */
function loadUpdatePublicKey(paths = candidatePaths()) {
  for (const p of paths) {
    let text;
    try {
      text = fs.readFileSync(p, 'utf8');
    } catch {
      continue;
    }
    if (text.includes(PLACEHOLDER) || !text.includes('-----BEGIN PUBLIC KEY-----')) return null;
    return text;
  }
  return null;
}

module.exports = { loadUpdatePublicKey, PLACEHOLDER };
