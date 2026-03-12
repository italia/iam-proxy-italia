// ----------------------- i18next -----------------------
function loadEidCardsi18next() {
  const lang = i18next.language;
  console.debug("i18next initialized, language:", lang);
  let eidBundle = i18next.getResourceBundle(lang, "translation");
  if (!eidBundle) {
    eidBundle = i18next.store?.getDataByLanguage?.(lang)?.translation ?? i18next.store?.data?.[lang]?.translation;
  }
  if (!eidBundle) {
    console.error("eid-cards: locale bundle not loaded for", lang);
    return;
  }
  loadDocument(eidBundle);
  loadEidCards(eidBundle);
  uniformEidCardsAfterImages();
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
    loadPath: 'locales/eid-{{lng}}.json'
  }
})
.then(loadEidCardsi18next)
.catch(err => console.error('Error loading eid-cards:', err));

// Change language
document.getElementById("lang-select")?.addEventListener('change', (e) => {
  const selectedLang = e.target.value;
  i18next.changeLanguage(selectedLang).then(loadEidCardsi18next);
});

// ----------------------- Document Loader -----------------------
function loadDocument(resource) {
  // header (use bundle or i18next.t so it works regardless of bundle structure)
  const regionEl = document.getElementById('header-region-name');
  if (regionEl) {
    const regionName = resource?.header?.region_name ?? i18next.t('header.region_name');
    regionEl.textContent = regionName || '';
  }
  const eidTitle = document.getElementById('eid-title');
  if (eidTitle) eidTitle.textContent = resource?.titles?.login_logo ?? '';
  const footerLegal = document.getElementById('footer-legal');
  if (footerLegal) footerLegal.textContent = resource?.footer?.legal_notice ?? '';
  const footerPrivacy = document.getElementById('footer-privacy');
  if (footerPrivacy) footerPrivacy.textContent = resource?.footer?.privacy_policy ?? '';
  const footerAccess = document.getElementById('footer-accessibility');
  if (footerAccess) footerAccess.textContent = resource?.footer?.accessibility_statement ?? '';
  const tabTitle = document.getElementById("tab-title");
  if (tabTitle) tabTitle.textContent = resource?.titles?.page_title ?? '';
  const metaDesc = document.querySelector('meta[name="description"]');
  if (metaDesc) metaDesc.setAttribute('content', resource?.titles?.page_title ?? '');
}

// ----------------------- Eid Cards Loader -----------------------
function loadEidCards(resource) {
  const container = document.getElementById('eid-cards-container');
  container.innerHTML = '';
  // Remove existing alt section (lives outside container) to prevent duplication on language change
  document.getElementById('eid-alternative-section')?.remove();

  if (checkId(resource.digital_id)) {
    const digitalSection = document.createElement('div');
    digitalSection.className = 'mb-4';
    const title = document.createElement('h3');
    title.textContent = resource.titles.login_digital_identity;
    title.className = 'text-center mb-4';
    digitalSection.appendChild(title);

    createEidCardsRow(resource, "digital_id", digitalSection);
    container.appendChild(digitalSection);

    const infoDiv = document.createElement('div');
    infoDiv.className = 'd-flex flex-column align-items-center mb-4';
    const havenDigitalId = resource.titles.havent_digital_identy;
    if (havenDigitalId) {
      const infoTitle = document.createElement('h4');
      infoTitle.textContent = havenDigitalId;

      const infoLink = document.createElement('a');
      infoLink.className = 'eid-find-how-link';
      infoLink.appendChild(document.createTextNode(resource.titles.find_how_to_get_digital_id));
      const findUrl = (resource.titles.find_how_to_get_digital_id_url || '').toString().trim();
      if (findUrl) {
        infoLink.href = findUrl;
        infoLink.target = '_blank';
        infoLink.rel = 'noopener noreferrer';
      } else {
        infoLink.href = 'javascript:void(0)';
        infoLink.addEventListener('click', (e) => e.preventDefault());
      }
      const svgNs = 'http://www.w3.org/2000/svg';
      const linkIcon = document.createElementNS(svgNs, 'svg');
      linkIcon.setAttribute('aria-hidden', 'true');
      linkIcon.setAttribute('width', '16');
      linkIcon.setAttribute('height', '16');
      linkIcon.setAttribute('viewBox', '0 0 24 24');
      linkIcon.setAttribute('fill', '#0066cc');
      linkIcon.style.cssText = 'flex-shrink:0;vertical-align:middle;display:inline-block';
      const path = document.createElementNS(svgNs, 'path');
      path.setAttribute('d', 'M21 3v6h-1V4.7l-7.6 7.7-.8-.8L19.3 4H15V3h6zm-4 16.5c0 .3-.2.5-.5.5h-12c-.3 0-.5-.2-.5-.5v-12c0-.3.2-.5.5-.5H12V6H4.5C3.7 6 3 6.7 3 7.5v12c0 .8.7 1.5 1.5 1.5h12c.8 0 1.5-.7 1.5-1.5V12h-1v7.5z');
      linkIcon.appendChild(path);
      infoLink.appendChild(linkIcon);
      infoDiv.appendChild(infoTitle);
      infoDiv.appendChild(infoLink);
      container.appendChild(infoDiv);
    }
  }

  if (checkId(resource.alternative_id)) {
    const altWrapper = document.createElement('div');
    altWrapper.id = 'eid-alternative-section';
    altWrapper.className = 'py-4';
    altWrapper.style.backgroundColor = '#F5F5F0';
    altWrapper.style.width = '100vw';
    altWrapper.style.marginLeft = 'calc(50% - 50vw)';

    const altSection = document.createElement('div');
    altSection.className = 'container mb-0';
    const title = document.createElement('h3');
    title.textContent = resource.titles.login_alternative_method;
    title.className = 'text-center mb-3 pb-4';
    altSection.appendChild(title);

    createEidCardsRow(resource, "alternative_id", altSection);
    altWrapper.appendChild(altSection);
    // Insert after main so altWrapper spans full viewport (full-width row)
    const main = container.closest('main');
    main.insertAdjacentElement('afterend', altWrapper);
  }
}

// ----------------------- Create Eid Cards Row -----------------------
function createEidCardsRow(resource, id_key, container) {
  const row = document.createElement('div');
  row.className = 'row justify-content-center';
  const entries = getEidEntriesForRow(resource[id_key]);
  entries.forEach((eid) => {
    const col = document.createElement('div');
    col.className = 'col-12 col-md-3 mb-3 mb-md-4';
    col.appendChild(createEidCardBox(resource, eid));
    row.appendChild(col);
  });
  container.appendChild(row);
}

// Merge CIE SAML2 and CIE OIDC into single card with dropdown when both present
function getEidEntriesForRow(entriesObj) {
  if (!entriesObj || typeof entriesObj !== 'object') return [];
  const entries = Object.entries(entriesObj);
  const hasCie = entries.some(([k]) => k === 'cie');
  const hasCieOidc = entries.some(([k]) => k === 'cie_oidc');
  if (hasCie && hasCieOidc) {
    const cie = entriesObj.cie;
    const cieOidc = entriesObj.cie_oidc;
    const mergedCie = {
      name: 'CIE',
      logo_text: cie.logo_text || 'Login with CIE',
      logo: cie.logo,
      login_url: '#cie-idp-button',
      _cieOptions: [cie, cieOidc],
      learn_more_descr: cie.learn_more_descr,
      learn_more_link: cie.learn_more_link
    };
    const result = [];
    let mergedCieInserted = false;
    for (const [k, v] of entries) {
      if (k === 'cie' || k === 'cie_oidc') {
        if (!mergedCieInserted) {
          result.push(mergedCie);
          mergedCieInserted = true;
        }
      } else {
        result.push(v);
      }
    }
    return result;
  }
  return entries.map(([, v]) => v);
}

// ----------------------- Eid Card Box (Bootstrap Italia it-card) -----------------------
function createEidCardBox(resource, eid) {
  // Bootstrap Italia card: https://italia.github.io/bootstrap-italia/docs/componenti/card/
  const card = document.createElement('article');
  card.className = 'it-card shadow h-100';

  const title = document.createElement('h4');
  title.className = 'it-card-title mb-3';
  title.textContent = eid.name;

  const body = document.createElement('div');
  body.className = 'it-card-body d-flex flex-column';
  const bodyRow = document.createElement('div');
  bodyRow.className = 'd-flex justify-content-between align-items-center flex-wrap gap-2';

  const withLearnMore = !!eid.learn_more_link || !!eid.learn_more_descr;
  bodyRow.appendChild(createLogoButton(eid, withLearnMore));
  body.appendChild(bodyRow);

  if (withLearnMore) {
    const learnMoreElem = createLearnMore(resource, eid);
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
function createLogoButton(eid, hasLearnMore = false) {
  const createLogoImg = () => {
    const img = document.createElement('img');
    img.src = eid.logo;
    img.alt = eid.name;
    img.style.width = '24px';
    img.style.height = '24px';
    img.style.objectFit = 'contain';
    return img;
  };

  const createTextSpan = () => {
    const span = document.createElement('span');
    span.textContent = eid.logo_text;
    return span;
  };

  // CIE multiprovider: dropdown when both CIE SAML2 and CIE OIDC are present
  if (eid._cieOptions && eid._cieOptions.length > 0) {
    const wrapper = document.createElement('div');
    wrapper.className = 'ita ita-dropdown ita-l ita-fixed';
    wrapper.style.position = 'relative';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-primary d-flex align-items-center';
    btn.style.gap = '0.5rem';
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');

    btn.appendChild(createLogoImg());
    btn.appendChild(createTextSpan());

    const menu = document.createElement('ul');
    menu.className = 'cie-dropdown-menu spid-idp-button-link';
    menu.setAttribute('role', 'menu');
    menu.style.cssText = 'display:none; position:absolute; top:100%; left:0; margin-top:4px; min-width:270px; z-index:1040;';

    eid._cieOptions.forEach((opt) => {
      const li = document.createElement('li');
      li.className = 'spid-idp-button-link';
      const link = document.createElement('a');
      link.href = opt.login_url;
      link.innerHTML = `<img src="${opt.logo}" alt=""> <span class="cie-option-label">${opt.name}</span>`;
      li.appendChild(link);
      menu.appendChild(li);
    });

    const closeMenu = () => {
      menu.style.display = 'none';
      btn.setAttribute('aria-expanded', 'false');
      document.removeEventListener('click', outsideClick);
    };
    const outsideClick = (e) => {
      if (!wrapper.contains(e.target)) closeMenu();
    };

    const toggleMenu = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const isOpen = menu.style.display === 'block';
      if (isOpen) {
        closeMenu();
      } else {
        menu.style.display = 'block';
        btn.setAttribute('aria-expanded', 'true');
        requestAnimationFrame(() => {
          requestAnimationFrame(() => document.addEventListener('click', outsideClick));
        });
      }
    };
    btn.addEventListener('pointerdown', toggleMenu, { capture: true });

    wrapper.appendChild(btn);
    wrapper.appendChild(menu);

    return wrapper;
  }

  if (eid.login_url?.includes("#spid-idp-button")) {
    const wrapper = document.createElement('div');
    wrapper.className = 'ita ita-dropdown ita-l ita-fixed';

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
  btn.href = eid.login_url;
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
function createLearnMore(resource, eid) {
  if (!eid.learn_more_link && eid.learn_more_descr) {
    const container = document.createElement('div');
    container.className = 'mt-2';

    const toggle = document.createElement('a');
    toggle.href = '#';
    toggle.textContent = resource.titles.learn_more;
    toggle.style.cursor = 'pointer';

    const text = document.createElement('p');
    text.innerHTML = eid.learn_more_descr;
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
  } else if (eid.learn_more_link) {
    const link = document.createElement('a');
    link.href = eid.learn_more_link;
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

function uniformEidCardsAfterImages() {
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
