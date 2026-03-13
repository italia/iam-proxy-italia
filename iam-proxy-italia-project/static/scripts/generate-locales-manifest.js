#!/usr/bin/env node
/**
 * Generate locales/languages.json from existing locale files.
 * Scans locales/ for {prefix}-{lang}.json and builds per-page supported languages.
 * Add this to package.json scripts and run on postinstall or before deploy.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const localesDir = path.join(__dirname, '..', 'locales');
const manifestPath = path.join(localesDir, 'languages.json');
// Matches {prefix}-{lang}.json (e.g. error-en.json, eid-it.json, qr-de.json)
const filePattern = /^(.+)-([a-z]{2,}(?:-[a-z]{2,})?)\.json$/;

const manifest = {};

if (!fs.existsSync(localesDir)) {
  console.warn('locales/ not found, writing default manifest');
  fs.writeFileSync(manifestPath, JSON.stringify({ error: ['en'], eid: ['en'], qr: ['en'] }, null, 2));
  process.exit(0);
}

const files = fs.readdirSync(localesDir);
for (const file of files) {
  if (file === 'languages.json') continue;
  const m = file.match(filePattern);
  if (m) {
    const [, prefix, lang] = m;
    const baseLang = lang.split('-')[0].toLowerCase();
    if (!manifest[prefix]) manifest[prefix] = [];
    if (!manifest[prefix].includes(baseLang)) manifest[prefix].push(baseLang);
  }
}

for (const key of Object.keys(manifest)) {
  manifest[key].sort();
}

fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
console.log('Generated', manifestPath, manifest);
