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

      const box = document.createElement('div');
      box.className = 'wallet-box border rounded p-3 shadow-sm bg-white';

      // init wallet row
      const row = document.createElement('div');
      row.className = 'd-flex justify-content-between align-items-center';

      // wallet name
      const left = document.createElement('div');
      left.className = 'wallet-info';
      const name = document.createElement('h5');
      name.textContent = wallet.name;
      left.appendChild(name);

      row.appendChild(left);

      // logo button
      const btn = document.createElement('a');
      btn.href = wallet.login_url;
      btn.className = 'btn btn-primary d-flex align-items-center';
      btn.style.gap = "0.5rem";

      // logo image in button
      const logoImg = document.createElement('img');
      logoImg.src = wallet.logo;
      logoImg.alt = wallet.name;
      logoImg.style.width = "24px";
      logoImg.style.height = "24px";

      // text in logo button "Login with {wallet.name}"
      const textSpan = document.createElement('span');
      textSpan.textContent = (LOGIN_LOGO_PREFIX_ELEMENT[lang] || "Login with ") + wallet.name;

      btn.appendChild(logoImg);
      btn.appendChild(textSpan);
      row.appendChild(btn);
      box.appendChild(row);

      // Learn more as text
      if (!wallet.learn_more_link && wallet.learn_more) {
        const learnMoreContainer = document.createElement('div');
        learnMoreContainer.className = 'mt-2'; // margine sopra

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
          text.style.display = text.style.display === "none" ? "block" : "none";
        });

        learnMoreContainer.appendChild(toggle);
        learnMoreContainer.appendChild(text);

        box.appendChild(learnMoreContainer);
      } else if (wallet.learn_more_link) { // Learn more as external link
        const link = document.createElement('a');
        link.href = wallet.learn_more_link;
        link.target = "_blank";
        link.textContent = LEARN_MORE_ELEMENT[lang] || "Learn more";
        link.className = "d-block mt-2";
        box.appendChild(link);
      }

      col.appendChild(box);
      container.appendChild(col);
    });
  })
  .catch(err => console.error('Error during wallets.json:', err));
}