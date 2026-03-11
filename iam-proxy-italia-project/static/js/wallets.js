// ----------------------- i18next -----------------------
function loadWalletsi18next() {
  const lang = i18next.language;
  console.debug("i18next initialized, language:", lang);
  const wallets = i18next.getResourceBundle(lang, "translation");
  loadDocument(wallets);
  loadWallets(wallets);
  uniformWalletsAfterImages();
  if (typeof Ita !== "undefined") {
    new Ita();
  }
//  if (typeof Cie !== "undefined") {
//    new Cie();
//  }
}

// Inizializza i18next
i18next
.use(i18nextHttpBackend)
.init({
  lng: 'en',
  fallbackLng: 'en',
  backend: {
    loadPath: 'locales/wallets-{{lng}}.json'
  }
})
.then(loadWalletsi18next)
.catch(err => console.error('Error loading wallets.json:', err));

// Change language
document.getElementById("lang-select")?.addEventListener('change', (e) => {
  const selectedLang = e.target.value;
  i18next.changeLanguage(selectedLang).then(loadWalletsi18next);
});

// ----------------------- Document Loader -----------------------
function loadDocument(resource) {
  // header (use bundle or i18next.t so it works regardless of bundle structure)
  const regionEl = document.getElementById('header-region-name');
  if (regionEl) {
    const regionName = resource?.header?.region_name ?? i18next.t('header.region_name');
    regionEl.textContent = regionName || '';
  }
  document.getElementById('wallet-title').textContent = resource.titles.login_logo;
  // footer
  document.getElementById('footer-legal').textContent = resource.footer.legal_notice;
  document.getElementById('footer-privacy').textContent = resource.footer.privacy_policy;
  document.getElementById('footer-accessibility').textContent = resource.footer.accessibility_statement;
  // meta
  document.getElementById("tab-title").textContent = resource.titles.page_title;
  const metaDesc = document.querySelector('meta[name="description"]');
  if (metaDesc) metaDesc.setAttribute('content', resource.titles.page_title);
}

// ----------------------- Wallets Loader -----------------------
function loadWallets(resource) {
  const container = document.getElementById('wallets-container');
  container.innerHTML = '';

  if (checkId(resource.digital_id)) {
    const digitalSection = document.createElement('div');
    digitalSection.className = 'mb-4';
    const title = document.createElement('h3');
    title.textContent = resource.titles.login_digital_identity;
    title.className = 'text-center mb-3';
    digitalSection.appendChild(title);

    createWallet(resource, "digital_id", digitalSection);
    container.appendChild(digitalSection);

    const infoDiv = document.createElement('div');
    infoDiv.className = 'd-flex flex-column align-items-center mb-4';
    const havenDigitalId = resource.titles.havent_digital_identy;
    if (havenDigitalId) {
      const infoTitle = document.createElement('h4');
      infoTitle.textContent = havenDigitalId;

      const infoLink = document.createElement('a');
      infoLink.textContent = resource.titles.find_how_to_get_digital_id;
      const findUrl = resource.titles.find_how_to_get_digital_id_url;
      if (findUrl) {
        infoLink.href = findUrl;
        infoLink.target = '_blank';
      }
      infoDiv.appendChild(infoTitle);
      infoDiv.appendChild(infoLink);
      container.appendChild(infoDiv);
    }
  }

  if (checkId(resource.alternative_id)) {
    const altSection = document.createElement('div');
    altSection.className = 'mb-4';
    const title = document.createElement('h3');
    title.textContent = resource.titles.login_alternative_method;
    title.className = 'text-center mb-3';
    altSection.appendChild(title);

    createWallet(resource, "alternative_id", altSection);
    container.appendChild(altSection);
  }
}

// ----------------------- Create Wallet -----------------------
function createWallet(resource, id_key, container) {
  const row = document.createElement('div');
  row.className = 'row';
  Object.entries(resource[id_key]).forEach(([key, wallet]) => {
    const col = document.createElement('div');
    col.className = 'col-12 col-md-6 mb-3 mb-md-4';
    col.appendChild(createWalletBox(resource, wallet));
    row.appendChild(col);
  });
  container.appendChild(row);
}

// ----------------------- Wallet Box (Bootstrap Italia it-card) -----------------------
function createWalletBox(resource, wallet) {
  // Bootstrap Italia card: https://italia.github.io/bootstrap-italia/docs/componenti/card/
  const card = document.createElement('article');
  card.className = 'it-card rounded shadow-sm border h-100';

  const title = document.createElement('h3');
  title.className = 'it-card-title';
  title.textContent = wallet.name;

  const body = document.createElement('div');
  body.className = 'it-card-body d-flex flex-column';
  const bodyRow = document.createElement('div');
  bodyRow.className = 'd-flex justify-content-between align-items-center flex-wrap gap-2';

  const withLearnMore = !!wallet.learn_more_link || !!wallet.learn_more_descr;
  bodyRow.appendChild(createLogoButton(wallet, withLearnMore));
  body.appendChild(bodyRow);

  if (withLearnMore) {
    const learnMoreElem = createLearnMore(resource, wallet);
    if (learnMoreElem) {
      learnMoreElem.classList.add('mt-2');
      body.appendChild(learnMoreElem);
    }
  }

  card.appendChild(title);
  card.appendChild(body);
  return card;
}

// ----------------------- Logo Button -----------------------
function createLogoButton(wallet, hasLearnMore = false) {
  const createLogoImg = () => {
    const img = document.createElement('img');
    img.src = wallet.logo;
    img.alt = wallet.name;
    img.style.width = '24px';
    img.style.height = '24px';
    img.style.objectFit = 'contain';
    return img;
  };

  const createTextSpan = () => {
    const span = document.createElement('span');
    span.textContent = wallet.logo_text;
    return span;
  };

// Support for multy-provider for CIE OIDC
//if (wallet.login_url?.includes("#cie-idp-button")) {
//    const wrapper = document.createElement('div');
//    wrapper.className = 'ita ita-dropdown ita-l ita-fixed mb-3';
//
//    const btn = document.createElement('a');
//    btn.href = "#";
//    btn.className = 'btn btn-primary d-flex align-items-center';
//    btn.style.gap = '0.5rem';
//    btn.setAttribute('spid-idp-button', '#spid-idp-button-xlarge-post');
//    btn.setAttribute('aria-haspopup', 'true');
//    btn.setAttribute('aria-expanded', 'false');
//
//    btn.appendChild(createLogoImg());
//    btn.appendChild(createTextSpan());
//
//    const menu = document.createElement('div');
//    menu.className = 'ita-menu';
//    menu.setAttribute('role', 'menu');
//    menu.setAttribute('data-cie-remote', '');
//
//    wrapper.appendChild(btn);
//    wrapper.appendChild(menu);
//
//    return wrapper;
//  }

if (wallet.login_url?.includes("#spid-idp-button")) {
    const wrapper = document.createElement('div');
    wrapper.className = 'ita ita-dropdown ita-l ita-fixed mb-3';

    const btn = document.createElement('a');
    btn.href = "#";
    btn.className = 'btn btn-primary d-flex align-items-center';
    btn.style.gap = '0.5rem';
    btn.setAttribute('spid-idp-button', '#spid-idp-button-xlarge-post');
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');

    btn.appendChild(createLogoImg());
    btn.appendChild(createTextSpan());

    const menu = document.createElement('div');
    menu.className = 'ita-menu';
    menu.setAttribute('role', 'menu');
    menu.setAttribute('data-spid-remote', '');

    wrapper.appendChild(btn);
    wrapper.appendChild(menu);

    return wrapper;
  }

  const btn = document.createElement('a');
  btn.href = wallet.login_url;
  btn.className = 'btn btn-primary d-flex align-items-center';
  btn.style.gap = '0.5rem';
  btn.style.whiteSpace = 'nowrap';
  btn.style.flexShrink = '0';
  btn.style.width = 'auto';
  btn.style.display = 'inline-flex';
  if (hasLearnMore) {
    btn.style.alignSelf = 'center';
  }

  btn.appendChild(createLogoImg());
  btn.appendChild(createTextSpan());

  return btn;
}

// ----------------------- Learn More -----------------------
function createLearnMore(resource, wallet) {
  if (!wallet.learn_more_link && wallet.learn_more_descr) {
    const container = document.createElement('div');
    container.className = 'mt-2';

    const toggle = document.createElement('a');
    toggle.href = '#';
    toggle.textContent = resource.titles.learn_more;
    toggle.style.cursor = 'pointer';

    const text = document.createElement('p');
    text.innerHTML = wallet.learn_more_descr;
    text.style.display = 'none';
    text.className = 'mt-2';

    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      const box = toggle.closest('.it-card');
      if (text.style.display === 'none') {
        text.style.display = 'block';
        if (box) box.style.height = 'auto';
      } else {
        text.style.display = 'none';
        if (box) box.style.height = '';
        uniformAll();
      }
    });

    container.appendChild(toggle);
    container.appendChild(text);
    return container;
  } else if (wallet.learn_more_link) {
    const link = document.createElement('a');
    link.href = wallet.learn_more_link;
    link.target = '_blank';
    link.className = 'd-block mt-2';
    link.textContent = resource.titles.learn_more;
    return link;
  }
  return null;
}

// ----------------------- Helpers -----------------------
function setUniformSize(selector, dimension = "height") {
  const elements = document.querySelectorAll(selector);
  let max = 0;

  elements.forEach(el => el.style[dimension] = "");

  elements.forEach(el => {
    const value = (dimension === "width") ? el.offsetWidth : el.offsetHeight;
    if (value > max) max = value;
  });

  elements.forEach(el => el.style[dimension] = max + "px");
}

function checkId(id) {
  return id && typeof id === 'object' && Object.keys(id).length > 0;
}

function uniformAll() {
  setUniformSize(".it-card", "height");
  setUniformSize(".it-card .btn", "height");
  setUniformSize(".it-card .btn", "width");
}

function uniformWalletsAfterImages() {
  const imgs = document.querySelectorAll(".it-card img");
  let loaded = 0;

  if (!imgs.length) {
    uniformAll();
    return;
  }

  imgs.forEach(img => {
    if (img.complete) {
      loaded++;
    } else {
      img.addEventListener("load", () => {
        loaded++;
        if (loaded === imgs.length) uniformAll();
      });
    }
  });

  if (loaded === imgs.length) uniformAll();
}

window.addEventListener('resize', uniformAll);
