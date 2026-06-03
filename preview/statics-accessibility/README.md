# Static assets (discovery page, error page, Bootstrap Italia)

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

Run from the `static` directory. Note: InfoCamere logo is not yet in the official repo; add `img/spid-idp-infocamereid.svg` manually when available.

## i18n

Both the discovery page and the error page use [i18next](https://www.i18next.com/) with locale files in `locales/`.

### Discovery page (`disco.html`)

- `locales/eid-it.json`, `locales/eid-en.json`
- Keys: `header.*`, `titles.*`, `loading.*`, `digital_id.*`, `alternative_id.*`, `footer.*`, `skip_links.*`
- Loader: `js/eid-cards-loader.js` (`loadPath: locales/eid-{{lng}}.json`)

### IT-Wallet page (`it-wallet.html`)

- `locales/it-wallet-it.json`, `locales/it-wallet-en.json`

### Error page (`error_page.html`)

- `locales/error-en.json`, `locales/error-it.json`
- Keys: `meta.*`, `header.organization_name`, `nav.*`, `body.*`, `footer.*`
- Language selector in the header (EN / ITA). Script: `js/error-i18n.js` (applies to elements with `data-i18n` and `data-i18n-title`).

## Accessibility (WCAG) — test locali e CI

Target: **WCAG 2.2 livello AA** su `disco.html` e `it-wallet.html`.

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
