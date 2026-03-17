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

## SPID IdP logos

SPID discovery uses IdP logos from [italia/spid-graphics](https://github.com/italia/spid-graphics) (`idp-logos/`). The list of IdPs and entityIDs is in `spid/spid-idps.js`, aligned with [registry.spid.gov.it/entities-idp](https://registry.spid.gov.it/entities-idp).

To refresh logos from the official repo:

```bash
bash scripts/update-spid-idp-assets.sh
```

Run from the `static` directory. Note: InfoCamere logo is not yet in the official repo; add `spid-idp-infocamereid.svg` manually when available.

## i18n

Both the discovery page and the error page use [i18next](https://www.i18next.com/) with locale files in `locales/`.

### Discovery page (`disco.html`)

- `locales/wallets-en.json`, `locales/wallets-it.json`
- Keys: `header.region_name`, `titles.*`, `footer.*`, `digital_id.*`, `alternative_id.*`

### Error page (`error_page.html`)

- `locales/error-en.json`, `locales/error-it.json`
- Keys: `meta.*`, `header.organization_name`, `nav.*`, `body.*`, `footer.*`
- Language selector in the header (EN / ITA). Script: `js/error-i18n.js` (applies to elements with `data-i18n` and `data-i18n-title`).

## Templates

- **disco.html** – Identity provider discovery (wallet/SPID/CIE choice). Uses Bootstrap Italia header, `it-card` components for each wallet, and i18n for all user-facing text.
- **error_page.html** – Auth error page with full i18n (EN/IT). Uses Bootstrap Italia layout and `it-card` for the message area; dropdown/collapse use `data-bs-*` (Bootstrap 5).
