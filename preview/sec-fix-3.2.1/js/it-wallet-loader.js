/**
 * IT-Wallet selection page: load wallets, random default order,
 * optional search/sort controls and card rendering.
 */

const SHOW_CARD_LEARN_MORE = false;
const SEARCH_MIN_WALLETS = 7;

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
  const pageSubtitle = document.getElementById('page-subtitle');
  if (pageSubtitle) pageSubtitle.textContent = resource?.titles?.page_subtitle ?? '';

  const searchInput = document.getElementById('wallet-search');
  if (searchInput) searchInput.placeholder = resource?.search?.placeholder ?? 'Cerca per nome';
  const searchBtn = document.getElementById('search-btn');
  if (searchBtn) searchBtn.textContent = resource?.search?.button ?? 'Cerca';
  const sortSelect = document.getElementById('wallet-sort');
  if (sortSelect) {
    const options = sortSelect.options;
    if (options[0]) options[0].textContent = resource?.sort?.default ?? 'Predefinito';
    if (options[1]) options[1].textContent = resource?.sort?.az ?? 'Alfabetico A-Z';
    if (options[2]) options[2].textContent = resource?.sort?.za ?? 'Alfabetico Z-A';
  }
  const backLink = document.getElementById('back-link');
  if (backLink) backLink.textContent = resource?.nav?.back ?? 'Indietro';

  const footerLegal = document.getElementById('footer-legal');
  if (footerLegal) footerLegal.textContent = resource?.footer?.legal_notice ?? '';
  const footerPrivacy = document.getElementById('footer-privacy');
  if (footerPrivacy) footerPrivacy.textContent = resource?.footer?.privacy_policy ?? '';
  const footerAccess = document.getElementById('footer-accessibility');
  if (footerAccess) footerAccess.textContent = resource?.footer?.accessibility_statement ?? '';
}

function shuffleWallets(wallets) {
  const shuffled = [...wallets];
  for (let i = shuffled.length - 1; i > 0; i -= 1) {
    const j = Math.floor(Math.random() * (i + 1));
    [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
  }
  return shuffled;
}

function sortWallets(wallets, sortValue) {
  if (sortValue === 'az') {
    return [...wallets].sort((a, b) => (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' }));
  }
  if (sortValue === 'za') {
    return [...wallets].sort((a, b) => (b.name || '').localeCompare(a.name || '', undefined, { sensitivity: 'base' }));
  }
  return wallets;
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
  col.className = 'col-12 col-lg-6 it-wallet-grid-col';
  const card = document.createElement('article');
  card.className = 'it-card shadow it-wallet-card';

  const body = document.createElement('div');
  body.className = 'it-card-body d-flex flex-column justify-content-center';

  const logoTitleCol = document.createElement('div');
  logoTitleCol.className = 'd-flex align-items-center justify-content-start w-100 it-wallet-card-main-row';
  const img = document.createElement('img');
  img.src = (wallet.logo_uri || '').startsWith('/') ? wallet.logo_uri : basePath + (wallet.logo_uri || '');
  img.alt = wallet.name;
  img.className = 'wallet-card-logo me-3 flex-shrink-0';
  logoTitleCol.appendChild(img);

  const titleLink = document.createElement('a');
  titleLink.href = buildWalletUri(wallet.uri);
  titleLink.className = 'it-wallet-card-link text-start';
  titleLink.title = wallet.name;
  const title = document.createElement('h5');
  title.className = 'it-card-title mb-0 it-wallet-card-title';
  title.textContent = wallet.name;
  titleLink.appendChild(title);
  logoTitleCol.appendChild(titleLink);
  body.appendChild(logoTitleCol);

  if (SHOW_CARD_LEARN_MORE) {
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
  }

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

  const defaultWalletOrder = shuffleWallets(wallets);
  const searchInput = document.getElementById('wallet-search');
  const searchBtn = document.getElementById('search-btn');
  const searchClearBtn = document.getElementById('search-clear-btn');
  const sortSelect = document.getElementById('wallet-sort');
  const controls = document.getElementById('wallet-controls');
  const showControls = defaultWalletOrder.length >= SEARCH_MIN_WALLETS;
  controls?.classList.toggle('d-none', !showControls);
  let appliedQuery = '';

  function applyFiltersAndSort() {
    const query = showControls ? appliedQuery : '';
    const sortValue = showControls ? (sortSelect?.value || 'default') : 'default';
    const filtered = filterWallets(defaultWalletOrder, query);
    const sorted = sortWallets(filtered, sortValue);
    renderWallets(sorted, resource, basePath);
    searchClearBtn?.classList.toggle('d-none', !(searchInput?.value || '').trim());
  }

  searchInput?.addEventListener('input', () => {
    searchClearBtn?.classList.toggle('d-none', !(searchInput?.value || '').trim());
  });
  searchBtn?.addEventListener('click', () => {
    appliedQuery = (searchInput?.value || '').trim();
    applyFiltersAndSort();
  });
  sortSelect?.addEventListener('change', () => applyFiltersAndSort());
  searchClearBtn?.addEventListener('click', () => {
    if (searchInput) {
      searchInput.value = '';
      searchInput.focus();
    }
    appliedQuery = '';
    applyFiltersAndSort();
  });

  applyFiltersAndSort();
  setupBackLink();
}

i18next
  .use(i18nextHttpBackend)
  .init({
    lng: 'it',
    fallbackLng: 'it',
    backend: { loadPath: getBasePath() + 'locales/it-wallet-{{lng}}.json' }
  })
  .then(() => {
    if (typeof window.initHeaderLangDropdown === 'function') {
      window.initHeaderLangDropdown(i18next, { afterLanguageChange: () => loadItWalletPage() });
    }
    return loadItWalletPage();
  })
  .catch((err) => console.error('Error loading it-wallet page:', err));
