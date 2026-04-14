/**
 * Copy Bootstrap Italia dist assets from node_modules to static folders.
 * Run from iam-proxy-italia-project/static: npm run update-bootstrap-italia
 * See: https://italia.github.io/bootstrap-italia/docs/come-iniziare/introduzione/
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'node_modules', 'bootstrap-italia', 'dist');

if (!fs.existsSync(SRC)) {
  console.warn('Bootstrap Italia not found in node_modules. Run: npm install');
  process.exit(0);
}

const copies = [
  { src: 'css/bootstrap-italia.min.css', dest: 'css/bootstrap-italia.min.css' },
  { src: 'js/bootstrap-italia.bundle.min.js', dest: 'js/bootstrap-italia.bundle.min.js' },
];

// Copy fonts and svg into bootstrap-italia/ so existing style.css paths work
function copyDir(srcDir, destDir) {
  if (!fs.existsSync(srcDir)) return;
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
  for (const name of fs.readdirSync(srcDir)) {
    const srcPath = path.join(srcDir, name);
    const destPath = path.join(destDir, name);
    if (fs.statSync(srcPath).isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

for (const { src, dest } of copies) {
  const srcPath = path.join(SRC, src);
  const destPath = path.join(ROOT, dest);
  if (fs.existsSync(srcPath)) {
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
    console.log('Copied:', dest);
  }
}

const fontsSrc = path.join(SRC, 'fonts');
const fontsDest = path.join(ROOT, 'bootstrap-italia', 'fonts');
if (fs.existsSync(fontsSrc)) {
  copyDir(fontsSrc, fontsDest);
  console.log('Copied: bootstrap-italia/fonts/');
}

const svgSrc = path.join(SRC, 'svg');
const svgDest = path.join(ROOT, 'bootstrap-italia', 'svg');
if (fs.existsSync(svgSrc)) {
  copyDir(svgSrc, svgDest);
  console.log('Copied: bootstrap-italia/svg/');
}

console.log('Bootstrap Italia assets updated.');
