#!/usr/bin/env node
'use strict';

/**
 * Signiertes Update-Manifest für den Windows-Installer erzeugen.
 *
 *   node scripts/sign-update.js --product pro --check
 *     Nur Vorprüfung (vor dem Versions-Commit): Public Key im Repo ist echt
 *     (kein Platzhalter), Secret UPDATE_SIGNING_KEY ist gesetzt und passt
 *     zum Public Key.
 *
 *   node scripts/sign-update.js --product pro [--dist dist] [--pub datei]
 *     Sucht genau einen NSIS-Installer (*Setup*.exe) in dist/, benennt ihn
 *     auf den Namen um, unter dem GitHub ihn als Release-Asset speichert
 *     (Leerzeichen → Punkte), und schreibt
 *       dist/update-manifest.json      kanonisches JSON, ohne Zeilenumbruch
 *       dist/update-manifest.json.sig  Base64-Ed25519-Signatur über die
 *                                      exakten Bytes des Manifests
 *     Danach wird die Signatur gegen build/update-signing.pub geprüft.
 *     Gibt fileName=<Asset-Name> für $GITHUB_OUTPUT aus.
 *
 * Der private Schlüssel (PKCS#8-PEM) kommt ausschließlich aus der
 * Umgebungsvariable UPDATE_SIGNING_KEY (GitHub-Actions-Secret). Jeder Fehler
 * bricht mit Exit-Code 1 ab – ein Release ohne gültige Signatur entsteht nicht.
 * Keine Abhängigkeiten außer node:crypto/fs/path.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
let PUBLIC_KEY_FILE = path.join(ROOT, 'build', 'update-signing.pub');
const PLACEHOLDER = 'REPLACE_WITH_UPDATE_PUBLIC_KEY';
const ASSET_NAME_RE = /^[A-Za-z0-9._-]{1,200}\.exe$/;
const PRODUCTS = ['pro', 'community'];

function die(msg) {
  console.error(`::error::sign-update: ${msg}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { dist: 'dist', check: false, product: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--check') args.check = true;
    else if (a === '--product') args.product = argv[++i];
    else if (a === '--dist') args.dist = argv[++i];
    else if (a === '--pub') PUBLIC_KEY_FILE = path.resolve(argv[++i]);
    else die(`unbekanntes Argument ${a}`);
  }
  if (!PRODUCTS.includes(args.product)) die(`--product muss ${PRODUCTS.join('|')} sein`);
  return args;
}

function loadPublicKey() {
  let pem;
  try {
    pem = fs.readFileSync(PUBLIC_KEY_FILE, 'utf8');
  } catch {
    die(`${path.relative(ROOT, PUBLIC_KEY_FILE)} fehlt`);
  }
  if (pem.includes(PLACEHOLDER)) {
    die(`${path.relative(ROOT, PUBLIC_KEY_FILE)} enthält noch den Platzhalter – echten Ed25519-Public-Key committen (siehe README, „Signierte Updates“)`);
  }
  let key;
  try {
    key = crypto.createPublicKey(pem);
  } catch (err) {
    die(`Public Key nicht lesbar: ${err.message}`);
  }
  if (key.asymmetricKeyType !== 'ed25519') die(`Public Key ist ${key.asymmetricKeyType}, erwartet ed25519`);
  return key;
}

function loadPrivateKey() {
  const pem = process.env.UPDATE_SIGNING_KEY;
  if (!pem || !pem.trim()) die('Secret UPDATE_SIGNING_KEY fehlt oder ist leer');
  let key;
  try {
    key = crypto.createPrivateKey(pem);
  } catch (err) {
    die(`UPDATE_SIGNING_KEY nicht lesbar (PKCS#8-PEM erwartet): ${err.message}`);
  }
  if (key.asymmetricKeyType !== 'ed25519') die(`UPDATE_SIGNING_KEY ist ${key.asymmetricKeyType}, erwartet ed25519`);
  return key;
}

function assertKeyPair(privateKey, publicKey) {
  const probe = crypto.randomBytes(32);
  const sig = crypto.sign(null, probe, privateKey);
  if (!crypto.verify(null, probe, publicKey, sig)) {
    die(`UPDATE_SIGNING_KEY passt nicht zu ${path.relative(ROOT, PUBLIC_KEY_FILE)}`);
  }
}

function sha256File(file) {
  const hash = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  const buf = Buffer.alloc(1024 * 1024);
  try {
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) hash.update(buf.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return hash.digest('hex');
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const publicKey = loadPublicKey();
  const privateKey = loadPrivateKey();
  assertKeyPair(privateKey, publicKey);
  if (args.check) {
    console.log('sign-update: Schlüssel geprüft (Public Key im Repo, Secret passt)');
    return;
  }

  const version = require(path.join(ROOT, 'package.json')).version;
  if (!/^\d+\.\d+\.\d+$/.test(version)) die(`package.json-Version ${version} ist kein X.Y.Z`);

  const dist = path.resolve(ROOT, args.dist);
  const installers = fs.readdirSync(dist).filter((f) => /Setup.*\.exe$/.test(f) && !f.startsWith('__'));
  if (installers.length !== 1) die(`genau ein *Setup*.exe in ${args.dist} erwartet, gefunden: ${JSON.stringify(installers)}`);

  // GitHub speichert Asset-Namen mit Punkten statt Leerzeichen. Die Datei wird
  // vorher umbenannt, damit Manifest, Upload und Asset-Name identisch sind.
  const original = installers[0];
  const fileName = original.replace(/ /g, '.');
  if (!ASSET_NAME_RE.test(fileName)) die(`Installer-Name ${fileName} enthält unerlaubte Zeichen`);
  if (!fileName.includes(version)) die(`Installer-Name ${fileName} enthält die Version ${version} nicht`);
  if (fileName !== original) fs.renameSync(path.join(dist, original), path.join(dist, fileName));

  const installerPath = path.join(dist, fileName);
  const size = fs.statSync(installerPath).size;
  if (!(size > 0)) die('Installer ist leer');

  // Feste Schlüsselreihenfolge, keine Leerzeichen, kein Zeilenumbruch.
  const manifest = JSON.stringify({
    schema: 1,
    product: args.product,
    version,
    fileName,
    sha256: sha256File(installerPath),
    size,
  });
  const bytes = Buffer.from(manifest, 'utf8');
  const signature = crypto.sign(null, bytes, privateKey).toString('base64');

  const manifestPath = path.join(dist, 'update-manifest.json');
  const sigPath = path.join(dist, 'update-manifest.json.sig');
  fs.writeFileSync(manifestPath, bytes);
  fs.writeFileSync(sigPath, signature);

  // Gegenprobe mit dem committeten Public Key über die geschriebenen Dateien.
  const ok = crypto.verify(null, fs.readFileSync(manifestPath), publicKey, Buffer.from(fs.readFileSync(sigPath, 'utf8'), 'base64'));
  if (!ok) die(`Signatur lässt sich mit ${path.relative(ROOT, PUBLIC_KEY_FILE)} nicht verifizieren`);

  console.log(`sign-update: ${manifest}`);
  console.log(`fileName=${fileName}`);
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `fileName=${fileName}\n`);
}

main();
