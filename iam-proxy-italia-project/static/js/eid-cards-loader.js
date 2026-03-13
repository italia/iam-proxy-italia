// ----------------------- i18next -----------------------
function loadEidCardsi18next() {
  const lang = i18next.language;
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
    lng: 'it',
    fallbackLng: 'it',
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
    altWrapper.className = 'py-4 eid-alternative-section';

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
  row.className = 'row justify-content-center align-items-start';
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
    img.className = 'eid-card-logo';
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
    wrapper.className = 'ita ita-dropdown ita-l ita-fixed eid-cie-dropdown-wrapper';

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-primary d-flex align-items-center eid-card-btn';
    btn.setAttribute('aria-haspopup', 'true');
    btn.setAttribute('aria-expanded', 'false');

    btn.appendChild(createLogoImg());
    btn.appendChild(createTextSpan());

    const menu = document.createElement('ul');
    menu.className = 'cie-dropdown-menu spid-idp-button-link';
    menu.setAttribute('role', 'menu');

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
      menu.classList.remove('is-open');
      btn.setAttribute('aria-expanded', 'false');
      document.removeEventListener('click', outsideClick);
    };
    const outsideClick = (e) => {
      if (!wrapper.contains(e.target)) closeMenu();
    };

    const toggleMenu = (e) => {
      e.preventDefault();
      e.stopPropagation();
      const isOpen = menu.classList.contains('is-open');
      if (isOpen) {
        closeMenu();
      } else {
        menu.classList.add('is-open');
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
    wrapper.className = 'ita ita-dropdown ita-l ita-fixed eid-cie-dropdown-wrapper';

    const btn = document.createElement('a');
    btn.href = "#";
    btn.className = 'btn btn-primary d-flex align-items-center eid-card-btn';
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
  btn.className = 'btn btn-primary d-flex align-items-center eid-card-btn';

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
    toggle.className = 'eid-learn-more-toggle';
    toggle.textContent = resource.titles.learn_more;

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

    const text = document.createElement('p');
    text.innerHTML = eid.learn_more_descr;
    text.className = 'mt-2 eid-learn-more-content';

    toggle.addEventListener('click', (e) => {
      e.preventDefault();
      const box = toggle.closest('.it-card');
      const isExpanded = toggle.classList.contains('expanded');
      if (!isExpanded) {
        toggle.classList.add('expanded');
        text.classList.add('is-open');
        if (box) box.style.height = 'auto';
      } else {
        toggle.classList.remove('expanded');
        text.classList.remove('is-open');
        if (box) box.style.height = '';
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
function checkId(id) {
  return id && typeof id === 'object' && Object.keys(id).length > 0;
}
