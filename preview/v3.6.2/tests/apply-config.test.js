/**
 * Unit + integration tests for the branding/deploy config build.
 * Run with the Node built-in test runner:
 *   npm run test:config        (node --test tests/apply-config.test.js)
 *
 * The integration tests read the real config + static files but never write to
 * disk: the build core (`applyToSources`) is pure and operates on in-memory
 * copies.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  STATIC_ROOT,
  DEFAULT_CONFIG_PATH,
  setByPath,
  setHtmlAttrById,
  setHtmlAttrByClass,
  setHtmlTextById,
  rewriteStaticBasePath,
  setCacheBustVersion,
  setPublicFontsPath,
  setHeaderLogo,
  setErrorHeaderLogo,
  buildJsonEdits,
  targetFiles,
  applyToSources,
  validateConfig,
  loadConfig,
  runBuild,
  NGINX_STATIC_ROOT,
} from '../scripts/apply-config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadDefaultConfig() {
  return JSON.parse(fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8'));
}

function readSources(config) {
  const sources = {};
  for (const rel of targetFiles(config)) {
    sources[rel] = fs.readFileSync(path.join(STATIC_ROOT, rel), 'utf8');
  }
  return sources;
}

function deepClone(value) {
  return JSON.parse(JSON.stringify(value));
}

// ---------------------------------------------------------------------------
// Generic helpers
// ---------------------------------------------------------------------------

test('setByPath sets a nested value, creating intermediate objects', () => {
  const obj = { header: { region_name: 'old' } };
  setByPath(obj, 'header.region_name', 'new');
  assert.equal(obj.header.region_name, 'new');

  setByPath(obj, 'a.b.c', 1);
  assert.deepEqual(obj.a, { b: { c: 1 } });
});

// ---------------------------------------------------------------------------
// HTML transforms
// ---------------------------------------------------------------------------

test('setHtmlAttrById replaces only the attribute on the matching element', () => {
  const html = '<a id="footer-legal" href="#" class="x">Legal</a><a id="other" href="#">Other</a>';
  const out = setHtmlAttrById(html, 'footer-legal', 'href', 'https://legal.example');
  assert.match(out, /id="footer-legal" href="https:\/\/legal\.example"/);
  assert.match(out, /id="other" href="#"/);
});

test('setHtmlAttrById is a no-op for an unknown id', () => {
  const html = '<a id="footer-legal" href="#">Legal</a>';
  assert.equal(setHtmlAttrById(html, 'missing', 'href', 'x'), html);
});

test('setHtmlAttrByClass targets the element by class and respects word boundaries', () => {
  const html = '<img src="old.svg" alt="" class="it-wallet-navbar-logo" height="32">';
  const out = setHtmlAttrByClass(html, 'it-wallet-navbar-logo', 'src', 'new.svg');
  assert.match(out, /src="new\.svg"/);

  const other = '<img src="x.svg" class="it-wallet-navbar-logo-extra">';
  assert.equal(setHtmlAttrByClass(other, 'it-wallet-navbar-logo', 'src', 'new.svg'), other);
});

test('setHtmlTextById replaces text content, not attribute lookalikes', () => {
  const html =
    '<svg aria-labelledby="eid-title"></svg>' +
    '<span id="eid-title" class="visually-hidden">Il tuo logo</span>';
  const out = setHtmlTextById(html, 'eid-title', 'ACME');
  assert.match(out, /<span id="eid-title" class="visually-hidden">ACME<\/span>/);
  // The aria-labelledby reference must be untouched.
  assert.match(out, /aria-labelledby="eid-title"/);
});

test('rewriteStaticBasePath rewrites /static prefixes and is idempotent', () => {
  const html = '<link href="./css/style.css"><use xlink:href="./svg/s.svg#i">';
  const once = rewriteStaticBasePath(html, '/app/static');
  assert.match(once, /href="\/app\/static\/css\/style\.css"/);
  assert.match(once, /xlink:href="\/app\/static\/svg\/s\.svg#i"/);
  // Running again must not double-rewrite.
  assert.equal(rewriteStaticBasePath(once, '/app/static'), once);
});

test('rewriteStaticBasePath leaves relative references untouched', () => {
  const html = '<link href="css/style.css"><script src="js/app.js">';
  assert.equal(rewriteStaticBasePath(html, '/app/static'), html);
});

test('setCacheBustVersion replaces every ?v= token', () => {
  const html = 'a.css?v=old"></a><script src="b.js?v=old">';
  const out = setCacheBustVersion(html, 'rel-2');
  assert.equal(out.match(/\?v=rel-2/g).length, 2);
  assert.doesNotMatch(out, /\?v=old/);
});

test('setPublicFontsPath replaces the __PUBLIC_PATH__ value', () => {
  const html = '<script>window.__PUBLIC_PATH__ = "spid/fonts"</script>';
  const out = setPublicFontsPath(html, 'assets/fonts');
  assert.match(out, /window\.__PUBLIC_PATH__ = "assets\/fonts"/);
});

const SVG_PLACEHOLDER =
  '<span id="eid-title" class="visually-hidden">Il tuo logo</span>\n' +
  '          <svg id="header-logo" class="it-header-logo-placeholder" role="img" aria-labelledby="eid-title"\n' +
  '            xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 40" height="32" focusable="false">\n' +
  '            <text id="header-logo-text" class="it-header-logo-placeholder__text" x="0" y="28" aria-hidden="true">Il tuo logo</text>\n' +
  '          </svg>';

test('setHeaderLogo: empty image keeps the SVG placeholder untouched', () => {
  const out = setHeaderLogo(SVG_PLACEHOLDER, { image: '', altText: 'ACME' });
  assert.equal(out, SVG_PLACEHOLDER);
});

test('setHeaderLogo: a configured image replaces the SVG with an <img>', () => {
  const out = setHeaderLogo(SVG_PLACEHOLDER, { image: 'img/acme.svg', altText: 'ACME' });
  assert.match(out, /<img id="header-logo" class="it-header-logo-image" src="img\/acme\.svg" alt="ACME" height="32">/);
  assert.doesNotMatch(out, /<svg id="header-logo"/);
  // The accessible label span must survive.
  assert.match(out, /<span id="eid-title"/);
});

test('setHeaderLogo: re-running with the same image is idempotent', () => {
  const once = setHeaderLogo(SVG_PLACEHOLDER, { image: 'img/acme.svg', altText: 'ACME' });
  const twice = setHeaderLogo(once, { image: 'img/acme.svg', altText: 'ACME' });
  assert.equal(twice, once);
});

test('setHeaderLogo: clearing the image restores the text placeholder', () => {
  const asImage = setHeaderLogo(SVG_PLACEHOLDER, { image: 'img/acme.svg', altText: 'ACME' });
  const restored = setHeaderLogo(asImage, { image: '', altText: 'ACME' });
  assert.match(restored, /<svg id="header-logo"/);
  assert.match(restored, /<text id="header-logo-text"[^>]*>ACME<\/text>/);
  assert.doesNotMatch(restored, /<img id="header-logo"/);
});

test('setHeaderLogo: escapes quotes in image path and alt text', () => {
  const out = setHeaderLogo(SVG_PLACEHOLDER, { image: 'a&b.svg', altText: 'A "B"' });
  assert.match(out, /src="a&amp;b\.svg"/);
  assert.match(out, /alt="A &quot;B&quot;"/);
});

const ERROR_LOGO_BLOCK =
  '<svg class="icon icon-lg me-2" aria-hidden="true">\n' +
  '              <!-- YOUR LOGO HERE (same as disco) -->\n' +
  '              <use xlink:href="svg/sprites.svg#it-code-circle"></use>\n' +
  '            </svg>\n' +
  '            <h2 id="error-header-logo-title" class="mb-0" data-i18n="header.logo_title">Il tuo logo</h2>';

test('setErrorHeaderLogo: empty image keeps the icon and the title heading', () => {
  const out = setErrorHeaderLogo(ERROR_LOGO_BLOCK, { image: '' });
  assert.equal(out, ERROR_LOGO_BLOCK);
});

test('setErrorHeaderLogo: a configured image replaces the icon with a decorative <img>', () => {
  const out = setErrorHeaderLogo(ERROR_LOGO_BLOCK, { image: 'img/acme.svg' });
  assert.match(out, /<img class="it-header-logo-image me-2" src="img\/acme\.svg" alt="" aria-hidden="true" height="32">/);
  assert.doesNotMatch(out, /it-code-circle/);
  // The visible title heading must survive.
  assert.match(out, /<h2 id="error-header-logo-title"/);
});

test('setErrorHeaderLogo: idempotent when image already applied', () => {
  const once = setErrorHeaderLogo(ERROR_LOGO_BLOCK, { image: 'img/acme.svg' });
  const twice = setErrorHeaderLogo(once, { image: 'img/acme.svg' });
  assert.equal(twice, once);
});

test('setErrorHeaderLogo: clearing the image restores the icon', () => {
  const asImage = setErrorHeaderLogo(ERROR_LOGO_BLOCK, { image: 'img/acme.svg' });
  const restored = setErrorHeaderLogo(asImage, { image: '' });
  assert.match(restored, /sprites\.svg#it-code-circle/);
  assert.doesNotMatch(restored, /it-header-logo-image/);
});

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

test('the shipped default config is valid and loadable', () => {
  const config = loadConfig();
  assert.ok(config.organizationName.it.length > 0);
});

test('validateConfig rejects a malformed config', () => {
  const bad = deepClone(loadDefaultConfig());
  delete bad.organizationName.en;
  assert.throws(() => validateConfig(bad), /organizationName\.en/);
});

test('validateConfig requires logo.image and logo.alt', () => {
  const bad = deepClone(loadDefaultConfig());
  delete bad.logo.image;
  assert.throws(() => validateConfig(bad), /logo\.image/);
});

// ---------------------------------------------------------------------------
// Integration: default config
// ---------------------------------------------------------------------------

test('applying the default config is stable (idempotent) on real files', () => {
  const config = loadDefaultConfig();
  const sources = readSources(config);
  const once = applyToSources(config, sources);
  const twice = applyToSources(config, once);
  for (const rel of Object.keys(once)) {
    assert.equal(twice[rel], once[rel], `second build changed ${rel}`);
  }
});

test('default config injects the configured values into the locale JSON', () => {
  const config = loadDefaultConfig();
  const sources = readSources(config);
  const out = applyToSources(config, sources);

  const eidIt = JSON.parse(out['locales/eid-it.json']);
  assert.equal(eidIt.header.region_name, config.organizationName.it);
  assert.equal(eidIt.titles.login_logo, config.logo.alt.it);
  assert.equal(eidIt.titles.find_how_to_get_digital_id_url, config.identityProviders.findDigitalIdUrl);
  assert.equal(eidIt.digital_id.cie.login_url, config.identityProviders.cieSaml2LoginUrl);
  assert.equal(eidIt.digital_id.cie_oidc.login_url, config.identityProviders.cieOidcLoginUrl);
  assert.equal(eidIt.footer.legal_notice, config.footerText.legal.it);

  const errorIt = JSON.parse(out['locales/error-it.json']);
  // The build harmonizes the organization name across all pages.
  assert.equal(errorIt.header.region_name, config.organizationName.it);
  assert.equal(errorIt.header.organization_name, config.organizationName.it);
  assert.equal(errorIt.footer.organization_name, config.organizationName.it);
  // Footer link labels share the same source as disco/it-wallet.
  assert.equal(errorIt.footer.legal_notes, config.footerText.legal.it);
  assert.equal(errorIt.footer.privacy, config.footerText.privacy.it);
  assert.equal(errorIt.footer.accessibility, config.footerText.accessibility.it);
  assert.equal(errorIt.footer.privacy, eidIt.footer.privacy_policy);
});

// ---------------------------------------------------------------------------
// Integration: overrides
// ---------------------------------------------------------------------------

test('overriding the organization name updates every locale file', () => {
  const config = deepClone(loadDefaultConfig());
  config.organizationName.it = 'Comune di Esempio';
  config.organizationName.en = 'Example Municipality';

  const sources = readSources(config);
  const out = applyToSources(config, sources);

  assert.equal(JSON.parse(out['locales/eid-it.json']).header.region_name, 'Comune di Esempio');
  assert.equal(JSON.parse(out['locales/eid-en.json']).header.region_name, 'Example Municipality');
  assert.equal(JSON.parse(out['locales/it-wallet-it.json']).header.region_name, 'Comune di Esempio');
  assert.equal(JSON.parse(out['locales/error-en.json']).header.organization_name, 'Example Municipality');
});

test('overriding the static base path rewrites disco.html and it-wallet.html only', () => {
  const config = deepClone(loadDefaultConfig());
  config.staticBasePath = '/proxy/static';

  const sources = readSources(config);
  const out = applyToSources(config, sources);

  assert.match(out['disco.html'], /href="\/proxy\/static\/css\/style\.css"/);
  assert.doesNotMatch(out['disco.html'], /"\/static\//);
  assert.match(out['it-wallet.html'], /\/proxy\/static\/svg\/sprites\.svg/);
});

test('overriding footer link URLs sets the hrefs in disco.html and it-wallet.html', () => {
  const config = deepClone(loadDefaultConfig());
  config.footerLinks.legalUrl = 'https://example.org/legal';
  config.footerLinks.privacyUrl = 'https://example.org/privacy';
  config.footerLinks.accessibilityUrl = 'https://example.org/a11y';

  const sources = readSources(config);
  const out = applyToSources(config, sources);

  for (const rel of ['disco.html', 'it-wallet.html']) {
    assert.match(out[rel], /id="footer-legal" href="https:\/\/example\.org\/legal"/);
    assert.match(out[rel], /id="footer-privacy" href="https:\/\/example\.org\/privacy"/);
    assert.match(out[rel], /id="footer-accessibility" href="https:\/\/example\.org\/a11y"/);
  }
});

test('overriding error page URLs and fonts path updates error_page.html', () => {
  const config = deepClone(loadDefaultConfig());
  config.errorPage.privacyUrl = 'https://example.org/privacy';
  config.errorPage.assistanceUrl = 'https://example.org/help';
  config.assets.fontsPublicPath = 'assets/fonts';

  const sources = readSources(config);
  const out = applyToSources(config, sources);

  assert.match(out['error_page.html'], /id="error-footer-privacy" href="https:\/\/example\.org\/privacy"/);
  // In error_page.html the assistance link declares href before class.
  assert.match(out['error_page.html'], /<a href="https:\/\/example\.org\/help" class="error-page-assistance"/);
  assert.match(out['error_page.html'], /window\.__PUBLIC_PATH__ = "assets\/fonts"/);
});

test('a logo image swaps the error page icon for an <img>; default keeps the icon', () => {
  const base = loadDefaultConfig();
  const baseSources = readSources(base);
  const defaultOut = applyToSources(base, baseSources);
  assert.match(defaultOut['error_page.html'], /sprites\.svg#it-code-circle/);
  assert.doesNotMatch(defaultOut['error_page.html'], /it-header-logo-image/);

  const config = deepClone(base);
  config.logo.image = 'img/my-org-logo.svg';
  const out = applyToSources(config, readSources(config));
  assert.match(out['error_page.html'], /<img class="it-header-logo-image me-2" src="img\/my-org-logo\.svg"/);
  assert.doesNotMatch(out['error_page.html'], /it-code-circle/);
  assert.match(out['error_page.html'], /<h2 id="error-header-logo-title"/);
});

test('configuring a logo image swaps the SVG placeholder in disco and it-wallet', () => {
  const config = deepClone(loadDefaultConfig());
  config.logo.image = 'img/my-org-logo.svg';

  const sources = readSources(config);
  const out = applyToSources(config, sources);

  for (const rel of ['disco.html', 'it-wallet.html']) {
    assert.match(out[rel], /<img id="header-logo" class="it-header-logo-image" src="img\/my-org-logo\.svg" alt="Il tuo logo" height="32">/);
    assert.doesNotMatch(out[rel], /<svg id="header-logo"/);
    // Accessible label span is preserved.
    assert.match(out[rel], /<span id="eid-title"/);
  }
});

test('the default config (empty logo image) leaves the SVG placeholder in place', () => {
  const config = loadDefaultConfig();
  const sources = readSources(config);
  const out = applyToSources(config, sources);
  for (const rel of ['disco.html', 'it-wallet.html']) {
    assert.match(out[rel], /<svg id="header-logo"/);
    assert.doesNotMatch(out[rel], /<img id="header-logo"/);
  }
});

test('overriding the cache-bust version updates it-wallet.html tokens', () => {
  const config = deepClone(loadDefaultConfig());
  config.assets.cacheBustVersion = 'release-2027';

  const sources = readSources(config);
  const out = applyToSources(config, sources);

  assert.match(out['it-wallet.html'], /\?v=release-2027/);
  assert.doesNotMatch(out['it-wallet.html'], /wallet-ui-20260422/);
});

test('an override changes only the targeted JSON leaf, leaving siblings intact', () => {
  const config = deepClone(loadDefaultConfig());
  config.footerText.legal.it = 'Note legali (custom)';

  const sources = readSources(config);
  const baseline = JSON.parse(applyToSources(loadDefaultConfig(), sources)['locales/eid-it.json']);
  const out = JSON.parse(applyToSources(config, sources)['locales/eid-it.json']);

  assert.equal(out.footer.legal_notice, 'Note legali (custom)');
  assert.equal(out.footer.privacy_policy, baseline.footer.privacy_policy);
  assert.equal(out.footer.accessibility_statement, baseline.footer.accessibility_statement);
});

// ---------------------------------------------------------------------------
// Mapping sanity
// ---------------------------------------------------------------------------

test('NGINX_STATIC_ROOT points at the deployment mirror', () => {
  assert.match(NGINX_STATIC_ROOT.replace(/\\/g, '/'), /Docker-compose\/nginx\/html\/static$/);
});

test('runBuild applies config to every provided root and skips missing files', () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgbuild-'));
  try {
    // Seed a partial mirror: one locale file with a stale value + error_page.html.
    fs.mkdirSync(path.join(tmpRoot, 'locales'), { recursive: true });
    const stale = JSON.parse(fs.readFileSync(path.join(STATIC_ROOT, 'locales/eid-it.json'), 'utf8'));
    stale.header.region_name = 'STALE NAME';
    fs.writeFileSync(path.join(tmpRoot, 'locales/eid-it.json'), `${JSON.stringify(stale, null, 2)}\n`);
    fs.copyFileSync(
      path.join(STATIC_ROOT, 'error_page.html'),
      path.join(tmpRoot, 'error_page.html')
    );

    const { changed, failed } = runBuild({ roots: [tmpRoot], dryRun: false });

    // The seeded locale value is synced to the config default.
    const synced = JSON.parse(fs.readFileSync(path.join(tmpRoot, 'locales/eid-it.json'), 'utf8'));
    assert.equal(synced.header.region_name, loadDefaultConfig().organizationName.it);
    assert.ok(changed.some((rel) => rel.endsWith('locales/eid-it.json')));
    assert.equal(failed.length, 0);

    // Missing files (e.g. disco.html) are silently skipped, not created.
    assert.equal(fs.existsSync(path.join(tmpRoot, 'disco.html')), false);

    // Idempotent: a second run reports no changes for this root.
    const again = runBuild({ roots: [tmpRoot], dryRun: false });
    assert.equal(again.changed.length, 0);
  } finally {
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('runBuild reports unwritable files instead of aborting', { skip: typeof process.getuid === 'function' && process.getuid() === 0 ? 'cannot test read-only as root' : false }, () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'cfgbuild-ro-'));
  const rel = 'locales/eid-it.json';
  try {
    fs.mkdirSync(path.join(tmpRoot, 'locales'), { recursive: true });
    const stale = JSON.parse(fs.readFileSync(path.join(STATIC_ROOT, rel), 'utf8'));
    stale.header.region_name = 'STALE NAME';
    const target = path.join(tmpRoot, rel);
    fs.writeFileSync(target, `${JSON.stringify(stale, null, 2)}\n`);
    fs.chmodSync(target, 0o444);

    const { changed, failed } = runBuild({ roots: [tmpRoot], dryRun: false });
    assert.ok(changed.some((f) => f.endsWith(rel)));
    assert.ok(failed.some((f) => f.file.endsWith(rel)));
    // The read-only file is left untouched.
    assert.equal(JSON.parse(fs.readFileSync(target, 'utf8')).header.region_name, 'STALE NAME');
  } finally {
    try { fs.chmodSync(path.join(tmpRoot, rel), 0o644); } catch { /* ignore */ }
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});

test('buildJsonEdits covers all six locale files', () => {
  const edits = buildJsonEdits(loadDefaultConfig());
  assert.deepEqual(Object.keys(edits).sort(), [
    'locales/eid-en.json',
    'locales/eid-it.json',
    'locales/error-en.json',
    'locales/error-it.json',
    'locales/it-wallet-en.json',
    'locales/it-wallet-it.json',
  ]);
});
