/**
 * Apply branding/deploy configuration to the static files.
 *
 * The defaults that ship in `config/branding.config.json` mirror the values
 * already present in the HTML/locale/data files. Editing the config and then
 * running this script rewrites only the configured values into the target
 * files (locale JSON, disco/it-wallet/error HTML).
 *
 * Run from `iam-proxy-italia-project/static`:
 *   npm run build:config
 *
 * All transforms are pure functions (exported for the test suite) and
 * idempotent: re-running with the same config produces byte-identical output.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const STATIC_ROOT = path.resolve(__dirname, '..');
export const DEFAULT_CONFIG_PATH = path.join(STATIC_ROOT, 'config', 'branding.config.json');

export const REPO_ROOT = path.resolve(STATIC_ROOT, '..', '..');
// Deployment mirror served by nginx (git-ignored artifact). Included as a build
// target so config changes propagate to the deployed copy too. Skipped if absent.
export const NGINX_STATIC_ROOT = path.join(REPO_ROOT, 'Docker-compose', 'nginx', 'html', 'static');
export const BUILD_ROOTS = [STATIC_ROOT, NGINX_STATIC_ROOT];

// ----------------------------------------------------------------------------
// Generic helpers (pure)
// ----------------------------------------------------------------------------

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Escape a value so it is safe inside a double-quoted HTML attribute. */
function escapeHtmlAttr(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Set a nested value on `obj` using a dot path (e.g. "header.region_name"). */
export function setByPath(obj, dottedPath, value) {
  const parts = dottedPath.split('.');
  let cursor = obj;
  for (let i = 0; i < parts.length - 1; i += 1) {
    const key = parts[i];
    if (cursor[key] == null || typeof cursor[key] !== 'object') {
      cursor[key] = {};
    }
    cursor = cursor[key];
  }
  cursor[parts[parts.length - 1]] = value;
  return obj;
}

// ----------------------------------------------------------------------------
// HTML transforms (pure)
// ----------------------------------------------------------------------------

/** Replace an attribute value inside a single opening tag string. */
function setAttrInTag(tag, attr, value) {
  const attrRe = new RegExp(`(\\s${escapeRegExp(attr)}=")[^"]*(")`);
  if (attrRe.test(tag)) {
    return tag.replace(attrRe, `$1${value}$2`);
  }
  // Attribute missing: insert it just before the tag close.
  return tag.replace(/\/?>$/, (end) => ` ${attr}="${value}"${end}`);
}

/** Set an attribute on the element identified by `id`. No-op if not found. */
export function setHtmlAttrById(html, id, attr, value) {
  const tagRe = new RegExp(`<[^>]*\\sid="${escapeRegExp(id)}"[^>]*>`);
  return html.replace(tagRe, (tag) => setAttrInTag(tag, attr, value));
}

/** Set an attribute on the first element whose class list contains `className`. */
export function setHtmlAttrByClass(html, className, attr, value) {
  // Match `className` only as a whole space-delimited class token, so that
  // e.g. "it-wallet-navbar-logo" does not match "it-wallet-navbar-logo-extra".
  const token = escapeRegExp(className);
  const tagRe = new RegExp(
    `<[^>]*\\sclass="[^"]*(?<![\\w-])${token}(?![\\w-])[^"]*"[^>]*>`
  );
  return html.replace(tagRe, (tag) => setAttrInTag(tag, attr, value));
}

/** Replace the text content of the element identified by `id`. No-op if not found. */
export function setHtmlTextById(html, id, value) {
  const re = new RegExp(`(\\sid="${escapeRegExp(id)}"[^>]*>)([\\s\\S]*?)(<)`);
  return html.replace(re, (match, open, _text, lt) => `${open}${value}${lt}`);
}

/**
 * Rewrite the static base path prefix on `href`/`src`/`xlink:href` attributes
 * that currently point to `./...`. Idempotent: only values that literally
 * start with `./` are rewritten.
 */
export function rewriteStaticBasePath(html, basePath) {
  const base = String(basePath).replace(/\/+$/, '');
  return html.replace(/((?:href|src|xlink:href)=")\/static\//g, `$1${base}/`);
}

/** Replace every `?v=...` cache-busting token. */
export function setCacheBustVersion(html, version) {
  return html.replace(/(\?v=)[^"'&\s]+/g, `$1${version}`);
}

/** Replace the value of `window.__PUBLIC_PATH__ = "..."`. */
export function setPublicFontsPath(html, value) {
  return html.replace(
    /(window\.__PUBLIC_PATH__\s*=\s*")[^"]*(")/,
    `$1${value}$2`
  );
}

const HEADER_LOGO_SVG_RE = /<svg id="header-logo"[\s\S]*?<\/svg>/;
const HEADER_LOGO_IMG_RE = /<img id="header-logo"[^>]*>/;

/** Canonical text placeholder (used when no logo image is configured). */
function headerLogoSvg(altText) {
  return (
    '<svg id="header-logo" class="it-header-logo-placeholder" role="img" aria-labelledby="eid-title"\n' +
    '            xmlns="http://www.w3.org/2000/svg" viewBox="0 0 240 40" height="32" focusable="false">\n' +
    `            <text id="header-logo-text" class="it-header-logo-placeholder__text" x="0" y="28" aria-hidden="true">${altText}</text>\n` +
    '          </svg>'
  );
}

/**
 * Switch the `#header-logo` element between the text placeholder (SVG) and an
 * actual logo `<img>` (SVG/PNG), driven by config.
 *
 * - image set: render `<img id="header-logo" ...>` (alt = localized logo text).
 * - image empty: keep/restore the SVG text placeholder.
 *
 * Idempotent and a no-op when the element is already in the desired form with
 * matching attributes. The `#eid-title` accessible label is left untouched
 * (it is populated separately).
 */
export function setHeaderLogo(html, { image, altText }) {
  const hasSvg = HEADER_LOGO_SVG_RE.test(html);
  const hasImg = HEADER_LOGO_IMG_RE.test(html);

  if (image) {
    const imgTag =
      `<img id="header-logo" class="it-header-logo-image" src="${escapeHtmlAttr(image)}" ` +
      `alt="${escapeHtmlAttr(altText)}" height="32">`;
    if (hasSvg) return html.replace(HEADER_LOGO_SVG_RE, imgTag);
    if (hasImg) return html.replace(HEADER_LOGO_IMG_RE, imgTag);
    return html;
  }

  // No image configured: ensure the text placeholder is present.
  if (hasImg) return html.replace(HEADER_LOGO_IMG_RE, headerLogoSvg(altText));
  return html;
}

// error_page.html uses a different header: a generic icon (`#it-code-circle`)
// next to a visible `<h2>` title. We anchor on the icon content (and on the
// injected image class) so the swap works without requiring an id and without
// editing the template, on both the source and the nginx copy.
const ERROR_LOGO_SVG_RE = /<svg\b[^>]*>[\s\S]*?sprites\.svg#it-code-circle[\s\S]*?<\/svg>/;
const ERROR_LOGO_IMG_RE = /<img\b[^>]*\bit-header-logo-image\b[^>]*>/;

function errorHeaderLogoSvg() {
  return (
    '<svg class="icon icon-lg me-2" aria-hidden="true">\n' +
    '              <!-- YOUR LOGO HERE (same as disco) -->\n' +
    '              <use href="svg/sprites.svg#it-code-circle"></use>\n' +
    '            </svg>'
  );
}

/**
 * Swap the error page header logo between the generic icon and a real logo
 * `<img>`. The image is decorative (`alt=""`, `aria-hidden`) because the
 * adjacent `#error-header-logo-title` heading already carries the visible name.
 * Idempotent; no-op when already in the desired form.
 */
export function setErrorHeaderLogo(html, { image }) {
  const hasSvg = ERROR_LOGO_SVG_RE.test(html);
  const hasImg = ERROR_LOGO_IMG_RE.test(html);

  if (image) {
    const imgTag =
      `<img class="it-header-logo-image me-2" src="${escapeHtmlAttr(image)}" ` +
      'alt="" aria-hidden="true" height="32">';
    if (hasSvg) return html.replace(ERROR_LOGO_SVG_RE, imgTag);
    if (hasImg) return html.replace(ERROR_LOGO_IMG_RE, imgTag);
    return html;
  }

  if (hasImg) return html.replace(ERROR_LOGO_IMG_RE, errorHeaderLogoSvg());
  return html;
}

// ----------------------------------------------------------------------------
// Config -> target mapping
// ----------------------------------------------------------------------------

/** JSON edits keyed by file (relative to STATIC_ROOT): { dotPath: value }. */
export function buildJsonEdits(config) {
  const org = config.organizationName;
  const logo = config.logo.alt;
  const footer = config.footerText;
  const idp = config.identityProviders;

  const idpEdits = {
    'titles.find_how_to_get_digital_id_url': idp.findDigitalIdUrl,
    'digital_id.cie.login_url': idp.cieSaml2LoginUrl,
    'digital_id.cie_oidc.login_url': idp.cieOidcLoginUrl,
    'digital_id.eidas.login_url': idp.eidasLoginUrl,
    'alternative_id.idem.login_url': idp.idemLoginUrl,
  };

  const eid = (lang) => ({
    'header.region_name': org[lang],
    'titles.login_logo': logo[lang],
    'footer.legal_notice': footer.legal[lang],
    'footer.privacy_policy': footer.privacy[lang],
    'footer.accessibility_statement': footer.accessibility[lang],
    ...idpEdits,
  });

  const wallet = (lang) => ({
    'header.region_name': org[lang],
    'titles.logo_title': logo[lang],
    'footer.legal_notice': footer.legal[lang],
    'footer.privacy_policy': footer.privacy[lang],
    'footer.accessibility_statement': footer.accessibility[lang],
  });

  const error = (lang) => ({
    'header.region_name': org[lang],
    'header.organization_name': org[lang],
    'header.logo_title': logo[lang],
    'footer.organization_name': org[lang],
    'footer.legal_notes': footer.legal[lang],
    'footer.privacy': footer.privacy[lang],
    'footer.accessibility': footer.accessibility[lang],
  });

  return {
    'locales/eid-it.json': eid('it'),
    'locales/eid-en.json': eid('en'),
    'locales/it-wallet-it.json': wallet('it'),
    'locales/it-wallet-en.json': wallet('en'),
    'locales/error-it.json': error('it'),
    'locales/error-en.json': error('en'),
  };
}

/** Ordered HTML transform pipelines keyed by file (relative to STATIC_ROOT). */
export function buildHtmlPipeline(config) {
  const base = config.staticBasePath;
  const logoIt = config.logo.alt.it;
  const logoImage = config.logo.image;
  const links = config.footerLinks;
  const errorPage = config.errorPage;

  const applyFooterLinks = (html) => {
    let next = setHtmlAttrById(html, 'footer-legal', 'href', links.legalUrl);
    next = setHtmlAttrById(next, 'footer-privacy', 'href', links.privacyUrl);
    next = setHtmlAttrById(next, 'footer-accessibility', 'href', links.accessibilityUrl);
    return next;
  };

  // Switch SVG placeholder <-> <img> first, then set the text/alt label.
  const applyHeaderLogo = (html) => setHeaderLogo(html, { image: logoImage, altText: logoIt });
  const applyHeaderLogoText = (html) => {
    let next = setHtmlTextById(html, 'header-logo-text', logoIt);
    next = setHtmlTextById(next, 'eid-title', logoIt);
    return next;
  };

  return {
    'disco.html': [
      (html) => rewriteStaticBasePath(html, base),
      applyHeaderLogo,
      applyHeaderLogoText,
      applyFooterLinks,
    ],
    'it-wallet.html': [
      (html) => rewriteStaticBasePath(html, base),
      (html) => setCacheBustVersion(html, config.assets.cacheBustVersion),
      (html) => setHtmlAttrByClass(html, 'it-wallet-navbar-logo', 'src', config.walletBrandLogo),
      applyHeaderLogo,
      applyHeaderLogoText,
      applyFooterLinks,
    ],
    'error_page.html': [
      (html) => rewriteStaticBasePath(html, base),
      (html) => setErrorHeaderLogo(html, { image: logoImage }),
      (html) => setHtmlTextById(html, 'error-header-region-name', config.organizationName.it),
      (html) => setHtmlTextById(html, 'error-header-logo-title', logoIt),
      (html) => setHtmlAttrByClass(html, 'error-page-cta', 'href', errorPage.loginUrl),
      (html) => setHtmlAttrByClass(html, 'error-page-assistance', 'href', errorPage.assistanceUrl),
      (html) => setHtmlAttrById(html, 'error-footer-privacy', 'href', errorPage.privacyUrl),
      (html) => setPublicFontsPath(html, config.assets.fontsPublicPath),
    ],
  };
}

/** List of all files (relative to STATIC_ROOT) that the build touches. */
export function targetFiles(config) {
  return [
    ...Object.keys(buildJsonEdits(config)),
    ...Object.keys(buildHtmlPipeline(config)),
  ];
}

/**
 * Apply the config to an in-memory map of `{ relativePath: content }`.
 * Returns a new map of `{ relativePath: newContent }`. Pure (no disk access).
 */
export function applyToSources(config, sources) {
  const jsonEdits = buildJsonEdits(config);
  const htmlPipeline = buildHtmlPipeline(config);
  const out = {};

  for (const [rel, content] of Object.entries(sources)) {
    if (jsonEdits[rel]) {
      const obj = JSON.parse(content);
      for (const [dotPath, value] of Object.entries(jsonEdits[rel])) {
        setByPath(obj, dotPath, value);
      }
      out[rel] = `${JSON.stringify(obj, null, 2)}\n`;
    } else if (htmlPipeline[rel]) {
      let html = content;
      for (const transform of htmlPipeline[rel]) {
        html = transform(html);
      }
      out[rel] = html;
    } else {
      out[rel] = content;
    }
  }
  return out;
}

// ----------------------------------------------------------------------------
// Config loading + validation
// ----------------------------------------------------------------------------

const LOCALIZED_KEYS = ['it', 'en'];

function assert(condition, message) {
  if (!condition) {
    throw new Error(`Invalid branding config: ${message}`);
  }
}

function assertLocalized(value, name) {
  assert(value && typeof value === 'object', `${name} must be an object with it/en`);
  for (const lang of LOCALIZED_KEYS) {
    assert(typeof value[lang] === 'string', `${name}.${lang} must be a string`);
  }
}

export function validateConfig(config) {
  assert(config && typeof config === 'object', 'config must be an object');
  assert(typeof config.staticBasePath === 'string', 'staticBasePath must be a string');
  assertLocalized(config.organizationName, 'organizationName');
  assert(config.logo && typeof config.logo === 'object', 'logo required');
  assert(typeof config.logo.image === 'string', 'logo.image must be a string');
  assertLocalized(config.logo.alt, 'logo.alt');
  assert(typeof config.walletBrandLogo === 'string', 'walletBrandLogo must be a string');

  assert(config.footerLinks && typeof config.footerLinks === 'object', 'footerLinks required');
  for (const key of ['legalUrl', 'privacyUrl', 'accessibilityUrl']) {
    assert(typeof config.footerLinks[key] === 'string', `footerLinks.${key} must be a string`);
  }

  assert(config.footerText && typeof config.footerText === 'object', 'footerText required');
  for (const key of ['legal', 'privacy', 'accessibility']) {
    assertLocalized(config.footerText[key], `footerText.${key}`);
  }

  assert(config.identityProviders && typeof config.identityProviders === 'object', 'identityProviders required');
  for (const key of ['findDigitalIdUrl', 'cieSaml2LoginUrl', 'cieOidcLoginUrl', 'eidasLoginUrl', 'idemLoginUrl']) {
    assert(typeof config.identityProviders[key] === 'string', `identityProviders.${key} must be a string`);
  }

  assert(config.errorPage && typeof config.errorPage === 'object', 'errorPage required');
  for (const key of ['loginUrl', 'assistanceUrl', 'privacyUrl']) {
    assert(typeof config.errorPage[key] === 'string', `errorPage.${key} must be a string`);
  }

  assert(config.assets && typeof config.assets === 'object', 'assets required');
  for (const key of ['cacheBustVersion', 'fontsPublicPath']) {
    assert(typeof config.assets[key] === 'string', `assets.${key} must be a string`);
  }
  return config;
}

export function loadConfig(configPath = DEFAULT_CONFIG_PATH) {
  const raw = fs.readFileSync(configPath, 'utf8');
  return validateConfig(JSON.parse(raw));
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

export function runBuild({ configPath = DEFAULT_CONFIG_PATH, roots = BUILD_ROOTS, dryRun = false } = {}) {
  const config = loadConfig(configPath);
  const files = targetFiles(config);
  const changed = [];
  const failed = [];

  for (const root of roots) {
    if (!fs.existsSync(root)) continue;

    const sources = {};
    const present = [];
    for (const rel of files) {
      const abs = path.join(root, rel);
      if (fs.existsSync(abs)) {
        sources[rel] = fs.readFileSync(abs, 'utf8');
        present.push(rel);
      }
    }

    const output = applyToSources(config, sources);
    for (const rel of present) {
      if (output[rel] === sources[rel]) continue;
      const abs = path.join(root, rel);
      const label = path.relative(REPO_ROOT, abs) || rel;
      changed.push(label);
      if (dryRun) continue;
      // A read-only target (e.g. the root-owned nginx mirror) must not abort the
      // whole build: keep going and report the failures.
      try {
        fs.writeFileSync(abs, output[rel]);
      } catch (err) {
        failed.push({ file: label, error: err.message || String(err) });
      }
    }
  }
  return { changed, failed };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  const isCheck = process.argv.includes('--check');
  const dryRun = isCheck || process.argv.includes('--dry-run');
  // --check is the CI gate: it only verifies the version-controlled source root.
  // A real build (and --dry-run preview) covers the nginx mirror too.
  const roots = isCheck ? [STATIC_ROOT] : BUILD_ROOTS;
  try {
    const { changed, failed } = runBuild({ dryRun, roots });
    const written = changed.filter((rel) => !failed.some((f) => f.file === rel));
    if (changed.length === 0) {
      console.warn('apply-config: no changes (files already match config).');
    } else {
      const verb = dryRun ? 'Would update' : 'Updated';
      console.warn(`apply-config: ${verb} ${written.length} file(s):`);
      for (const rel of written) console.warn(`  - ${rel}`);
    }
    if (failed.length > 0) {
      console.warn(`apply-config: could not write ${failed.length} file(s) (skipped):`);
      for (const { file, error } of failed) console.warn(`  - ${file}: ${error}`);
      console.warn('  Hint: the nginx mirror is root-owned; re-run with adequate permissions to sync it.');
    }
    if (dryRun && changed.length > 0) {
      process.exitCode = 1;
    } else if (failed.length > 0) {
      process.exitCode = 3;
    }
  } catch (err) {
    console.error(err.message || err);
    process.exitCode = 2;
  }
}
