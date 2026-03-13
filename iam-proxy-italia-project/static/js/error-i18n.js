/**
 * i18n for error_page.html: load locale and apply to data-i18n / data-i18n-title elements.
 */

function applyErrorTranslations() {
  // Meta
  document.title = i18next.t('meta.title');
  var metaDesc = document.querySelector('meta[name="description"]');
  if (metaDesc) metaDesc.setAttribute('content', i18next.t('meta.description'));

  // data-i18n: set textContent (with fallback for header.region_name -> header.organization_name)
  document.querySelectorAll('[data-i18n]').forEach(function (el) {
    var key = el.getAttribute('data-i18n');
    if (!key) return;
    var val = i18next.t(key);
    if (val === key && key === 'header.region_name') {
      val = i18next.t('header.organization_name');
    }
    el.textContent = val;
  });

  // data-i18n-title: set title attribute (for links)
  document.querySelectorAll('[data-i18n-title]').forEach(function (el) {
    var key = el.getAttribute('data-i18n-title');
    if (key) el.setAttribute('title', i18next.t(key));
  });

  // Update html lang
  document.documentElement.lang = (i18next.language || '').split('-')[0] || 'en';
}

function initErrorI18n(supported) {
  applyErrorTranslations();
  var langSelect = document.getElementById('error-lang-select');
  if (langSelect) {
    var lng = (i18next.language || '').split('-')[0];
    if (supported && supported.indexOf(lng) !== -1) langSelect.value = lng;
    else langSelect.value = supported && supported[0] ? supported[0] : 'en';
    langSelect.addEventListener('change', function (e) {
      var selectedLang = e.target.value;
      var currentBase = (i18next.language || '').split('-')[0];
      if (selectedLang && selectedLang !== currentBase) {
        i18next.changeLanguage(selectedLang).then(applyErrorTranslations).catch(function (err) {
          console.error('Language change failed:', err);
        });
      }
    });
  }
}

if (typeof i18next !== 'undefined' && typeof i18nextHttpBackend !== 'undefined' && typeof window.LocaleUtils !== 'undefined') {
  var LocaleUtils = window.LocaleUtils;
  var basePath = ((typeof window.__LOCALES_BASE__ !== 'undefined' && window.__LOCALES_BASE__) || (LocaleUtils.getBasePath && LocaleUtils.getBasePath())) || '/';
  basePath = basePath.replace(/\/?$/, '/');
  LocaleUtils.fetchLocalesManifest(basePath)
    .then(function (manifest) {
      var supported = manifest.error || ['en'];
      var initialLng = LocaleUtils.getPreferredLanguage(supported);
      return i18next
        .use(i18nextHttpBackend)
        .init({
          lng: initialLng,
          fallbackLng: supported[0] || 'en',
          load: 'languageOnly',
          preload: supported,
          backend: {
            loadPath: basePath + 'locales/error-{{lng}}.json',
            requestOptions: { cache: 'no-store' }
          }
        })
        .then(function () {
          LocaleUtils.populateLangSelect(document.getElementById('error-lang-select'), supported, initialLng);
          initErrorI18n(supported);
        });
    })
    .catch(function (err) {
      console.error('Error loading error page translations:', err);
    });
} else {
  console.warn('i18next not loaded: error page translations skipped');
}
