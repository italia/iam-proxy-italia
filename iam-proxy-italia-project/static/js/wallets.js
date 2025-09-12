const LEARN_MORE_ELEMENT = {
  "ita": "Scopri di più",
  "en": "Learn more"
};

const LOGIN_LOGO_PREFIX_ELEMENT = {
  "ita": "Entra con ",
  "en": "Login with "
};

document.addEventListener("DOMContentLoaded", () => {
  const langSelect = document.getElementById('lang-select');
  let selectedLang = langSelect.value;
  // load wallets
  loadWallets(selectedLang);
  // reload wallets on language change
  langSelect.addEventListener('change', (e) => {
    selectedLang = e.target.value;
    loadWallets(selectedLang);
  });
});

function loadWallets(lang) {
  fetch(`/static/model/wallets-${lang}.json`)
  .then(res => res.json())
  .then(wallets => {
    const container = document.getElementById('wallets-container');
    container.innerHTML = '';
    wallets.forEach(wallet => {
      const col = document.createElement('div');
      col.className = 'col-12 col-md-6 mb-3';
      col.appendChild(createWalletBox(wallet, lang));
      container.appendChild(col);
      setUniformWalletBoxHeight();
    });
  })
  .catch(err => console.error('Error during wallets.json:', err));
}

function createWalletName(name) {
  const nameElem = document.createElement('h5');
  nameElem.textContent = name;
  return nameElem;
}

function createLogoButton(wallet, lang) {
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
  textSpan.textContent = (LOGIN_LOGO_PREFIX_ELEMENT[lang] || "Login with ")
      + wallet.name;

  btn.appendChild(logoImg);
  btn.appendChild(textSpan);
  return btn;
}

function createLearnMore(wallet, lang) {
  if (!wallet.learn_more_link && wallet.learn_more) {
    const container = document.createElement('div');
    container.className = 'mt-2';

    const toggle = document.createElement('a');
    toggle.href = "#";
    toggle.textContent = LEARN_MORE_ELEMENT[lang] || "Learn more";
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
        setUniformWalletBoxHeight(); // Reset heights if needed
      }
    });

    container.appendChild(toggle);
    container.appendChild(text);
    return container;
  } else if (wallet.learn_more_link) {
    const link = document.createElement('a');
    link.href = wallet.learn_more_link;
    link.target = "_blank";
    link.textContent = LEARN_MORE_ELEMENT[lang] || "Learn more";
    link.className = "d-block mt-2";
    return link;
  }
  return null;
}

function createWalletBox(wallet, lang) {
  const box = document.createElement('div');
  box.className = 'wallet-box border rounded p-3 shadow-sm bg-white';

  const row = document.createElement('div');
  row.className = 'd-flex justify-content-between align-items-center';

  const left = document.createElement('div');
  left.className = 'wallet-info';
  left.appendChild(createWalletName(wallet.name));

  row.appendChild(left);
  row.appendChild(createLogoButton(wallet, lang));
  box.appendChild(row);

  const learnMoreElem = createLearnMore(wallet, lang);
  if (learnMoreElem) {
    box.appendChild(learnMoreElem);
  }

  return box;
}

function setUniformWalletBoxHeight() {
  const boxes = document.querySelectorAll('.wallet-box');
  let maxHeight = 0;
  boxes.forEach(box => {
    box.style.height = ''; // Reset any previous height
    const boxHeight = box.offsetHeight;
    if (boxHeight > maxHeight) {
      maxHeight = boxHeight;
    }
  });
  boxes.forEach(box => {
    box.style.height = maxHeight + 'px';
  });
}