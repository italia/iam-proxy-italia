/**
 * IT-Wallet selection page: load wallet data, render cards, filter by id or name (LIKE).
 */

function getBasePath() {
  const path = window.location.pathname;
  const lastSlash = path.lastIndexOf('/');
  return lastSlash >= 0 ? path.substring(0, lastSlash + 1) : '/';
}

function loadDocument(resource) {
  const regionEl = document.getElementById('header-region-name');
  if (regionEl) regionEl.textContent = resource?.header?.region_name ?? '';
  const eidTitle = document.getElementById('eid-title');
  if (eidTitle) eidTitle.textContent = resource?.titles?.logo_title ?? '';
  const tabTitle = document.getElementById('tab-title');
  if (tabTitle) tabTitle.textContent = resource?.titles?.page_title ?? '';
  const pageTitle = document.getElementById('page-title');
  if (pageTitle) pageTitle.textContent = resource?.titles?.page_title ?? '';

  const searchInput = document.getElementById('wallet-search');
  if (searchInput) searchInput.placeholder = resource?.search?.placeholder ?? 'Cerca per nome';
  const searchBtn = document.getElementById('search-btn');
  if (searchBtn) searchBtn.textContent = resource?.search?.button ?? 'Cerca';
  const loadMoreBtn = document.getElementById('load-more-btn');
  if (loadMoreBtn) loadMoreBtn.textContent = resource?.wallets?.load_more ?? 'Carica altri';
  const backLink = document.getElementById('back-link');
  if (backLink) backLink.textContent = resource?.nav?.back ?? 'Indietro';

  const infoWhatIs = document.getElementById('info-what-is');
  if (infoWhatIs) infoWhatIs.textContent = resource?.learn_more?.question ?? 'Non sai cos\'è IT-Wallet?';
  const infoLearnMoreText = document.getElementById('info-learn-more-text');
  if (infoLearnMoreText) infoLearnMoreText.textContent = resource?.learn_more?.link ?? 'Scopri di più';

  const footerLegal = document.getElementById('footer-legal');
  if (footerLegal) footerLegal.textContent = resource?.footer?.legal_notice ?? '';
  const footerPrivacy = document.getElementById('footer-privacy');
  if (footerPrivacy) footerPrivacy.textContent = resource?.footer?.privacy_policy ?? '';
  const footerAccess = document.getElementById('footer-accessibility');
  if (footerAccess) footerAccess.textContent = resource?.footer?.accessibility_statement ?? '';
}

/** LIKE-style match: substring, case-insensitive */
function matchesLike(text, query) {
  if (!query || !query.trim()) return true;
  const q = query.trim().toLowerCase();
  const t = (text || '').toLowerCase();
  return t.includes(q);
}

function filterWallets(wallets, query) {
  if (!query || !query.trim()) return wallets;
  const q = query.trim().toLowerCase();
  return wallets.filter((w) => {
    const idMatch = matchesLike(w.id, q);
    const nameMatch = matchesLike(w.name, q);
    return idMatch || nameMatch;
  });
}

function buildWalletUri(uri) {
  const params = new URLSearchParams(window.location.search);
  // Default return to proxy's disco callback when missing (e.g. direct access or params lost)
  const returnUrl = params.get('return') || (window.location.origin + '/Saml2/disco');
  // For wallet flow, entityID must be 'wallet' to route to OpenID4VP; do not overwrite with page params
  const entityID = uri.includes('entityID=wallet') ? 'wallet' : (params.get('entityID') || 'wallet');
  try {
    const u = new URL(uri, window.location.origin);
    u.searchParams.set('return', returnUrl);
    u.searchParams.set('entityID', entityID);
    return u.toString();
  } catch {
    return uri + (uri.includes('?') ? '&' : '?') + 'return=' + encodeURIComponent(returnUrl) + '&entityID=' + encodeURIComponent(entityID);
  }
}

function createWalletCard(wallet, resource, basePath) {
  const col = document.createElement('div');
  col.className = 'col';
  const card = document.createElement('article');
  card.className = 'it-card shadow';

  const body = document.createElement('div');
  body.className = 'it-card-body d-flex flex-column';

  const link = document.createElement('a');
  link.href = buildWalletUri(wallet.uri);
  link.className = 'text-decoration-none text-dark d-flex flex-column';
  link.style.minHeight = '80px';

  const logoTitleRow = document.createElement('div');
  logoTitleRow.className = 'd-flex align-items-center mb-2';
  const img = document.createElement('img');
  img.src = (wallet.logo_uri || '').startsWith('/') ? wallet.logo_uri : basePath + (wallet.logo_uri || '');
  img.alt = wallet.name;
  img.className = 'wallet-card-logo me-3 flex-shrink-0';
  img.style.width = '48px';
  img.style.height = '48px';
  img.style.objectFit = 'contain';
  logoTitleRow.appendChild(img);

  const title = document.createElement('h5');
  title.className = 'it-card-title mb-0 flex-grow-1';
  title.textContent = wallet.name;
  title.style.webkitLineClamp = '2';
  title.style.display = '-webkit-box';
  title.style.WebkitBoxOrient = 'vertical';
  title.style.overflow = 'hidden';
  logoTitleRow.appendChild(title);

  link.appendChild(logoTitleRow);
  body.appendChild(link);

  const learnMoreLabel = resource?.learn_more?.link ?? 'Scopri di più';
  const descContainer = document.createElement('div');
  descContainer.className = 'wallet-learn-more';

  const toggle = document.createElement('a');
  toggle.href = '#';
  toggle.className = 'eid-learn-more-toggle';
  toggle.textContent = learnMoreLabel;

  const svgNs = 'http://www.w3.org/2000/svg';
  const arrow = document.createElementNS(svgNs, 'svg');
  arrow.setAttribute('class', 'eid-learn-more-arrow');
  arrow.setAttribute('aria-hidden', 'true');
  arrow.setAttribute('width', '4');
  arrow.setAttribute('height', '3');
  arrow.setAttribute('viewBox', '0 0 16 16');
  const arrowPath = document.createElementNS(svgNs, 'path');
  arrowPath.setAttribute('fill', 'none');
  arrowPath.setAttribute('stroke', '#0066cc');
  arrowPath.setAttribute('stroke-width', '2');
  arrowPath.setAttribute('stroke-linecap', 'round');
  arrowPath.setAttribute('stroke-linejoin', 'round');
  arrowPath.setAttribute('d', 'm2 5 6 6 6-6');
  arrow.appendChild(arrowPath);
  toggle.appendChild(arrow);

  const desc = document.createElement('p');
  desc.className = 'text-muted small mb-0 mt-2';
  desc.textContent = wallet.description || '';

  const howToGetLabel = resource?.learn_more?.how_to_get ?? 'Scopri come ottenerlo';
  const howToGetLink = document.createElement('a');
  howToGetLink.href = wallet.how_to_get_url || '#';
  howToGetLink.className = 'wallet-how-to-get-link text-decoration-none d-inline-flex align-items-center gap-1 mt-2';
  howToGetLink.textContent = howToGetLabel;
  const extIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  extIcon.setAttribute('class', 'icon icon-sm ms-1');
  extIcon.setAttribute('aria-hidden', 'true');
  const useEl = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  useEl.setAttribute('href', basePath + 'svg/sprites.svg#it-external-link');
  extIcon.appendChild(useEl);
  howToGetLink.appendChild(extIcon);

  const contentWrapper = document.createElement('div');
  contentWrapper.className = 'eid-learn-more-content';
  contentWrapper.appendChild(desc);
  contentWrapper.appendChild(howToGetLink);

  toggle.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    const box = toggle.closest('.it-card');
    const isExpanded = toggle.classList.contains('expanded');
    if (!isExpanded) {
      toggle.classList.add('expanded');
      contentWrapper.classList.add('is-open');
      if (box) box.style.height = 'auto';
    } else {
      toggle.classList.remove('expanded');
      contentWrapper.classList.remove('is-open');
      if (box) box.style.height = '';
    }
  });

  descContainer.appendChild(toggle);
  descContainer.appendChild(contentWrapper);
  body.appendChild(descContainer);
  card.appendChild(body);
  col.appendChild(card);
  return col;
}

function renderWallets(wallets, resource, basePath) {
  const grid = document.getElementById('wallet-grid');
  grid.innerHTML = '';
  if (wallets.length === 0) {
    const noResultsLabel = resource?.search?.no_results ?? 'Nessun risultato';
    const emptyDiv = document.createElement('div');
    emptyDiv.className = 'col-12 d-flex flex-column align-items-center justify-content-center py-5';
    const img = document.createElement('img');
    img.src = basePath + 'img/error-icon.svg';
    img.alt = '';
    img.className = 'it-wallet-no-results-icon mb-3';
    img.setAttribute('aria-hidden', 'true');
    const msg = document.createElement('h5');
    msg.className = 'h5 text-muted mb-0';
    msg.textContent = noResultsLabel;
    emptyDiv.appendChild(img);
    emptyDiv.appendChild(msg);
    grid.appendChild(emptyDiv);
  } else {
    wallets.forEach((w) => {
      grid.appendChild(createWalletCard(w, resource, basePath));
    });
  }
}

function setupBackLink() {
  const backLink = document.getElementById('back-link');
  if (backLink) {
    const params = new URLSearchParams(window.location.search);
    const search = params.toString();
    backLink.href = search ? 'disco.html?' + search : 'disco.html';
  }
}

async function loadItWalletPage() {
  const basePath = getBasePath();
  const lang = i18next.language || 'it';

  let resource = i18next.getResourceBundle(lang, 'translation');
  if (!resource) {
    resource = i18next.store?.getDataByLanguage?.(lang)?.translation ?? i18next.store?.data?.[lang]?.translation ?? {};
  }
  loadDocument(resource);

  let wallets = [];
  try {
    const resp = await fetch(basePath + 'data/it-wallets.json');
    if (resp.ok) {
      const data = await resp.json();
      wallets = data.immediate_subordinate_entities || [];
    }
  } catch (err) {
    console.error('Error loading it-wallets.json:', err);
  }

  const searchInput = document.getElementById('wallet-search');
  const searchBtn = document.getElementById('search-btn');

  function applyFilter() {
    const query = (searchInput?.value || '').trim();
    const filtered = filterWallets(wallets, query);
    renderWallets(filtered, resource, basePath);
  }

  searchInput?.addEventListener('input', () => applyFilter());
  searchInput?.addEventListener('keyup', (e) => { if (e.key === 'Enter') applyFilter(); });
  searchBtn?.addEventListener('click', () => applyFilter());

  applyFilter();
  setupBackLink();
}

i18next
  .use(i18nextHttpBackend)
  .init({
    lng: 'it',
    fallbackLng: 'it',
    backend: { loadPath: getBasePath() + 'locales/it-wallet-{{lng}}.json' }
  })
  .then(loadItWalletPage)
  .catch((err) => console.error('Error loading it-wallet page:', err));

document.getElementById('lang-select')?.addEventListener('change', (e) => {
  i18next.changeLanguage(e.target.value).then(loadItWalletPage);
});
