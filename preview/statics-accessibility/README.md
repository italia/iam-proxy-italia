# Static assets (discovery page, error page, Bootstrap Italia)

## Deploy configuration (branding / constants)

The deploy-impacting constants of the static pages (`disco.html`, `it-wallet.html`,
`error_page.html`) and their locale/data files are centralized in a single
configuration file:

- `config/branding.config.json` — editable, **ships with the default values**
  (the same values already present in the files).
- `config/branding.config.schema.json` — JSON schema (documentation + editor
  autocomplete via `$schema`).

Managed constants: static base path (`/static`), organization name (it/en),
header logo (`logo.image` + localized `logo.alt`), IT-Wallet brand logo, footer
link URLs, footer link text (it/en), IdP login URLs (CIE SAML2/OIDC, eIDAS, IDEM)
and "find digital identity" URL, error-page URLs (login / assistance / privacy),
cache-busting version, and the fonts public path.

### Header logo (image vs text)

`logo` controls the header logo of `disco.html`, `it-wallet.html` **and**
`error_page.html`:

```jsonc
"logo": {
  "image": "",                       // path to an SVG/PNG logo; empty = text/icon placeholder
  "alt": { "it": "Il tuo logo", "en": "Your Logo" }
}
```

- When `logo.image` is **empty**, the pages keep their placeholder: the text
  wordmark on disco/it-wallet, the generic icon next to the title on the error
  page. The localized text comes from the locale files (`logo.alt`).
- When `logo.image` is a **path** (e.g. `img/my-org-logo.svg`), the build swaps
  the placeholder for an `<img>`:
  - disco/it-wallet → `<img id="header-logo" src="…" alt="…">` (alt = `logo.alt`).
  - error page → decorative `<img>` replacing the icon (`alt=""`, `aria-hidden`),
    while the visible title heading keeps the `logo.alt` text.
  Drop your asset under `img/` (or any path you reference) and run the build.
  Clearing `logo.image` restores the placeholder.

### How i18n relates to the config

The locale files in `locales/` **are** the i18next translation files
(`loadPath: locales/<page>-{{lng}}.json`). The localized config values
(`*.it` / `*.en`) are written by the build into those JSON files, so editing the
config is the single source of truth for the translated header/footer text; at
runtime i18next loads `it` or `en` based on the header language selector.

### Workflow

1. Edit the values in `config/branding.config.json`.
2. Run the build from this directory:

```bash
npm run build:config
```

The build is **manual** and rewrites only the configured values into the target
files (locale JSON + HTML). It is idempotent: re-running with the same config
produces no further changes.

To verify in CI that the **source** files are in sync with the config (non-zero
exit if not; checks the source root only, not the nginx mirror):

```bash
npm run build:config:check
```

The npm scripts are just shortcuts: `apply-config.js` is a plain Node ESM CLI
with no runtime dependencies, so it can be run directly with `node` (handy for
CI, hooks or containers without `node_modules`). It resolves its own roots, so
the working directory does not matter:

```bash
node scripts/apply-config.js            # = build:config (source + nginx mirror)
node scripts/apply-config.js --check    # = build:config:check (source only, no writes)
node scripts/apply-config.js --dry-run  # preview every root without writing
```

#### Build targets (multiple roots)

The build applies to two roots:

1. `iam-proxy-italia-project/static/` — the source/canonical files.
2. `Docker-compose/nginx/html/static/` — the nginx deployment mirror
   (git-ignored). Included so config changes reach the deployed copy too.

Behavior across roots:
- Only files that **exist** in a root are touched; missing ones are skipped.
- Transforms are defensive: where a page's markup differs from the source
  (the nginx mirror may be an older generation), only the anchors that match are
  updated (e.g. footer hrefs, locale values), the rest is left as is.
- The nginx mirror is typically **root-owned**: if the build cannot write a file
  it does **not** abort — it finishes the writable root(s) and lists the skipped
  files (exit code `3`). To sync the live mirror, re-run with adequate
  permissions (e.g. `sudo npm run build:config`) or let the container build
  regenerate it.

Notes:
- Run the build on a clean checkout (it edits files in place).
- The first build harmonizes the organization name across all pages and
  normalizes locale JSON formatting (2-space indent, trailing newline).
- Exit codes: `0` ok · `1` `--check`/`--dry-run` found drift · `2` invalid
  config · `3` some target files could not be written.

### Tests

```bash
npm run test:config        # node --test tests/apply-config.test.js
```

Covers the pure transforms (HTML attribute/text/base-path/version rewrites, JSON
path edits), config validation, idempotency on the real files, and override
behavior.

## Bootstrap Italia

This project uses [Bootstrap Italia](https://italia.github.io/bootstrap-italia/docs/come-iniziare/introduzione/) for the discovery page and error page.

### Updating Bootstrap Italia

From this directory (`iam-proxy-italia-project/static`):

```bash
npm install
```

This installs `bootstrap-italia` and runs a postinstall script that copies:

- `dist/css/bootstrap-italia.min.css` → `css/`
- `dist/js/bootstrap-italia.bundle.min.js` → `js/`
- `dist/fonts/` → `bootstrap-italia/fonts/`
- `dist/svg/` → `bootstrap-italia/svg/`

To update assets without reinstalling:

```bash
npm run update-bootstrap-italia
```

## IT-Wallet official assets

Discovery page (IT-Wallet card) and QR code page use official IT-Wallet logos from [eid-wallet-it-docs official_resources](https://github.com/italia/eid-wallet-it-docs/tree/versione-corrente/official_resources):

- **Discovery page** (`disco.html`): `it-wallet/wallet_icon.svg` — white symbol on primary button (from IT-Wallet-Symbol-Negative-White).
- **QR code page** and backend config: `it-wallet/wallet-icon-blue.svg` — blue logo in QR center (from IT-Wallet-Logo-Primary-BlueItalia).

To refresh assets from the official repo:

```bash
npm run update-wallet-it-assets
```

Or run `bash scripts/update-wallet-it-assets.sh` from this directory.

## SPID discovery (`disco.html`)

The discovery page does **not** use the legacy AgID markup (`#spid-idp-list-*`). SPID is wired as follows:

| Component | Role |
|-----------|------|
| `js/eid-cards-loader.js` | Renders the SPID card: trigger `[spid-idp-button="#spid-idp-button-xlarge-post"]` and panel `#spid-idp-button-xlarge-post.ita-menu[data-spid-remote]` |
| `js/ita.min.js` (`Ita`) | Vanilla JS: loads IdPs from `js/spid-idps-default.json`, shuffles order, injects links into `[data-spid-remote]` menus |
| `spid/spid-sp-access-button.js` | jQuery plugin (AgID): opens/closes the IdP panel on `[spid-idp-button]` |
| `js/jquery-3.7.0.min.js` | Local jQuery bundle; required only by `spid-sp-access-button.js` |
| `js/spid-idps-default.json` | IdP list (`organization_name`, `entity_id`, `logo_uri`); align with [registry.spid.gov.it/entities-idp](https://registry.spid.gov.it/entities-idp) |

Removed legacy files (unused on `disco.html`): `spid/spid_button.js` (shuffle for `#spid-idp-list-*`) and `spid/spid-idps.js` (populate `ul#spid-idp-list-medium-root-get`).

### SPID IdP logos

Logos are served locally from `img/spid-idp-*.svg` and `spid/spid-ico-circle-bb.svg` (card icon). Sources: [italia/spid-graphics](https://github.com/italia/spid-graphics) (`idp-logos/`).

To refresh IdP logos from the official repo:

```bash
bash scripts/update-spid-idp-assets.sh
```

Run from the `static` directory. Note: the InfoCamere logo is not published in [italia/spid-graphics], so `img/spid-idp-infocamereid.svg` is bundled and maintained manually in this repo (the script does not download it).

## i18n

Both the discovery page and the error page use [i18next](https://www.i18next.com/) with locale files in `locales/`.

### Discovery page (`disco.html`)

- `locales/eid-it.json`, `locales/eid-en.json`
- Keys: `header.*` (incl. `lang_active_hint`, `lang_trigger`), `titles.*`, `meta.*`, `noscript.*`, `loading.*`, `digital_id.*`, `alternative_id.*`, `footer.*` (incl. `nav_label`), `skip_links.*`
- Loader: `js/eid-cards-loader.js` (`loadPath: locales/eid-{{lng}}.json`)

### IT-Wallet page (`it-wallet.html`)

- `locales/it-wallet-it.json`, `locales/it-wallet-en.json` — stesse convenzioni (`header`, `meta`, `noscript`, `footer`, `skip_links`, `search.clear_label`, …)

### Error page (`error_page.html`)

- `locales/error-en.json`, `locales/error-it.json`
- Keys: `meta.*`, `skip_links.*`, `noscript.*`, `header.*` (incl. `lang_trigger`), `body.*`, `footer.*` (incl. `nav_label`, `new_window_hint`)
- Script: `js/error-i18n.js` + `js/header-lang-dropdown.js` (elementi con `data-i18n`, `data-i18n-aria-label`, `data-i18n-newwindow`)
- Stesse pratiche a11y di disco/it-wallet: skip link, landmark (`main` / `footer`), menu lingua accessibile, link esterni con hint nuova finestra, icona errore decorativa, `noscript` i18n

## Accessibility (WCAG) — test locali e CI

Target: **WCAG 2.2 livello AA** su `disco.html`, `it-wallet.html` e `error_page.html`.

### In locale (da questa directory)

```bash
npm ci
npx playwright install chromium
npm run test:a11y:ci          # suite completa Playwright (axe + best-practice + reflow)
npm run test:a11y:keyboard    # solo contratti tastiera (@keyboard)
npm run test:a11y:reflow      # zoom/reflow 400%
npm run test:a11y:best-practices  # best-practice axe (anche in CI come warning)
```

- **axe** (`tests/a11y.spec.ts`): tag `wcag2a`, `wcag2aa`, `wcag21aa`, `wcag22aa` su entrambe le pagine.
- **best-practice / focus / status** (`tests/a11y.best-practices.spec.ts`): ARIA, focus, live region, form ricerca, menu SPID/ordinamento.
- **reflow** (`tests/a11y.reflow.spec.ts`): assenza overflow orizzontale a 400% (viewport 320px / 256px).

Documentazione: `docs/a11y-review-report.md`, checklist manuale `docs/a11y-manual-checklist.md`.

### GitHub Actions

Workflow [`.github/workflows/static-accessibility.yml`](../../.github/workflows/static-accessibility.yml) (si attiva su modifiche a `iam-proxy-italia-project/static/**`):

| Job | Bloccante | Contenuto |
|-----|-----------|-----------|
| **A11y required checks** | Sì | W3C HTML (`lint:w3c:html`), axe WCAG (`test:a11y:ci`), tastiera, reflow 400% |
| **A11y warning checks** | No | `test:a11y:best-practices` (regole axe best-practice) |
| **A11y manual evidence** | No | Checklist artefatto per verifiche manuali (SR, esperti) |

Lint HTML/CSS/JS separato: workflow **Static Lint** (`static-lint.yml`).

## Templates

- **disco.html** – Identity provider discovery (wallet/SPID/CIE choice). Uses Bootstrap Italia header, `it-card` components for each wallet, and i18n for all user-facing text.
- **error_page.html** – Auth error page with full i18n (EN/IT). Uses Bootstrap Italia layout and `it-card` for the message area; dropdown/collapse use `data-bs-*` (Bootstrap 5).
