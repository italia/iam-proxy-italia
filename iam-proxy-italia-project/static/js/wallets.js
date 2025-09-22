function loadWalletsi18next() {
  const lang = i18next.language
  console.debug("i18next initialized, language:", lang);
  const wallets = i18next.getResourceBundle(lang, "translation")
  loadWallets(wallets)
}

i18next
.use(i18nextHttpBackend)
.init({
  lng: 'en',
  fallbackLng: 'en',
  debug: true,
  backend: {
    loadPath: 'locales/{{lng}}.json'
  }
})
.then(loadWalletsi18next)
.catch(err => console.error('Error during wallets.json:', err));

document.getElementById("lang-select")?.addEventListener('change', (e) => {
  const selectedLang = e.target.value;
  i18next.changeLanguage(selectedLang).then(loadWalletsi18next);
});

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
    }
    if (checkId(resource.alternative_id)) {
      const altSection = document.createElement('div');
      altSection.className = 'mb-4';
      const title = document.createElement('h3');
      title.textContent  = resource.titles.login_alternative_method;
      title.className = 'text-center mb-3';
      altSection.appendChild(title);
      createWallet(resource, "alternative_id", altSection);
      container.appendChild(altSection);
    }
}

function createWallet(resource, id_key, container) {
  const row = document.createElement('div');
  row.className = 'row'; // Bootstrap row for grid layout
  Object.entries(resource[id_key]).forEach(([key, wallet]) => {
    const col = document.createElement('div');
    col.className = 'col-12 col-md-6 mb-3';
    col.appendChild(createWalletBox(resource, wallet));
    row.appendChild(col);
  });
  container.appendChild(row);
  setUniformElement('.wallet-box');
  setUniformElement('.wallet-box .btn');
}

function createWalletName(name) {
  const nameElem = document.createElement('h5');
  nameElem.textContent = name;
  return nameElem;
}

function createLogoButton(wallet) {
  const btn = document.createElement('a');
  btn.href = wallet.login_url;
  btn.className = 'btn btn-primary d-flex align-items-center';
  btn.style.gap = "0.5rem";

  const logoImg = document.createElement('img');
  logoImg.src = wallet.logo;
  logoImg.alt = wallet.name;
  logoImg.style.width = "24px";
  logoImg.style.height = "24px";

  const textSpan = document.createElement('span');
  textSpan.textContent = wallet.logo_text;

  btn.appendChild(logoImg);
  btn.appendChild(textSpan);
  return btn;
}

function createLearnMore(resource, wallet) {
  if (!wallet.learn_more_link && wallet.learn_more) {
    const container = document.createElement('div');
    container.className = 'mt-2';

    const toggle = document.createElement('a');
    toggle.href = "#";
    toggle.textContent = resource.titles.learn_more;
    toggle.style.cursor = "pointer";

    const text = document.createElement('p');
    text.innerHTML = wallet.learn_more;
    text.style.display = "none";
    text.className = "mt-2";

    toggle.addEventListener("click", (e) => {
      e.preventDefault();
      const box = toggle.closest('.wallet-box');
      if (text.style.display === "none") {
        box.style.height = 'auto'; // Allow box to expand
        text.style.display = "block";
      } else {
        text.style.display = "none";
        setUniformElement('.wallet-box');
      }
    });

    container.appendChild(toggle);
    container.appendChild(text);
    return container;
  } else if (wallet.learn_more_link) {
    const link = document.createElement('a');
    link.href = wallet.learn_more_link;
    link.target = "_blank";
    toggle.textContent = resource.titles.learn_more;
    link.className = "d-block mt-2";
    return link;
  }
  return null;
}

function createWalletBox(resource, wallet) {
  const box = document.createElement('div');
  box.className = 'wallet-box border rounded p-3 shadow-sm bg-white';

  const row = document.createElement('div');
  row.className = 'd-flex justify-content-between align-items-center';

  const left = document.createElement('div');
  left.className = 'wallet-info';
  left.appendChild(createWalletName(wallet.name));

  row.appendChild(left);
  row.appendChild(createLogoButton(wallet));
  box.appendChild(row);

  const learnMoreElem = createLearnMore(resource, wallet);
  if (learnMoreElem) {
    box.appendChild(learnMoreElem);
  }

  return box;
}

function setUniformElement(selector) {
  const nodeElement = document.querySelectorAll(selector);
  let maxWidth = 0;
  nodeElement.forEach(btn => {
    btn.style.width = ''; // Reset any previous width
    const btnWidth = btn.offsetWidth;
    if (btnWidth > maxWidth) maxWidth = btnWidth;
  });
  nodeElement.forEach(btn => {
    btn.style.width = maxWidth + 'px';
  });
}

function checkId(id) {
  return id &&
      typeof id === 'object'
      && Object.keys(id).length > 0
}
