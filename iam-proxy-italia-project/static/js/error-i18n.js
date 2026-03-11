/**
 * i18n for error_page.html: load locale and apply to data-i18n / data-i18n-title elements.
 */

function applyErrorTranslations() {
  // Meta
  document.title = i18next.t('meta.title');
  var metaDesc = document.querySelector('meta[name="description"]');
  if (metaDesc) metaDesc.setAttribute('content', i18next.t('meta.description'));

  // data-i18n: set textContent
  document.querySelectorAll('[data-i18n]').forEach(function (el) {
    var key = el.getAttribute('data-i18n');
    if (key) el.textContent = i18next.t(key);
  });

  // data-i18n-title: set title attribute (for links)
  document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
    var key = el.getAttribute('data-i18n-title');
    if (key) el.setAttribute('title', i18next.t(key));
  });

  // Update html lang
  document.documentElement.lang = i18next.language === 'it' ? 'it' : 'en';
}

function initErrorI18n() {
  applyErrorTranslations();
  var langSelect = document.getElementById('error-lang-select');
  if (langSelect) {
    var lng = (i18next.language || '').split('-')[0];
    if (lng === 'it' || lng === 'en') langSelect.value = lng;
    else langSelect.value = 'en';
    langSelect.addEventListener('change', function (e) {
      i18next.changeLanguage(e.target.value).then(applyErrorTranslations);
    });
  }
}

if (typeof i18next !== 'undefined' && typeof i18nextHttpBackend !== 'undefined') {
  i18next
    .use(i18nextHttpBackend)
    .init({
      lng: document.documentElement.lang || 'it',
      fallbackLng: 'en',
      backend: {
        loadPath: 'locales/error-{{lng}}.json'
      }
    })
    .then(initErrorI18n)
    .catch(function (err) {
      console.error('Error loading error page translations:', err);
    });
} else {
  console.warn('i18next not loaded: error page translations skipped');
}
