/**
 * Shared locale/language utilities for i18n pages (error, disco/eid, qr).
 * Resolves preferred language from: URL param > server-injected > [localStorage] > navigator > first supported.
 * Attaches to window.LocaleUtils for use by classic scripts and inline code.
 */
(function (global) {
  'use strict';

  function getBasePath() {
    var path = typeof global.location !== 'undefined' && global.location ? global.location.pathname : '';
    var lastSlash = path.lastIndexOf('/');
    return lastSlash >= 0 ? path.substring(0, lastSlash + 1) : '/';
  }

  /**
   * @param {string[]} supported - List of supported lang codes (e.g. ['en','it'])
   * @param {Object} [opts] - Options
   * @param {boolean} [opts.checkLocalStorage] - If true, check localStorage.getItem('lang') after server (for qr page)
   * @returns {string} Preferred language code
   */
  function getPreferredLanguage(supported, opts) {
    opts = opts || {};
    var def = supported && supported.length ? supported[0] : 'en';
    if (!supported || !supported.length) return def;

    var p = new URLSearchParams(typeof global.location !== 'undefined' && global.location ? global.location.search : '');
    var urlLang = p.get('lang') || p.get('lng');
    if (urlLang && supported.indexOf(urlLang.toLowerCase()) !== -1) return urlLang.toLowerCase();

    var serverLang = typeof global.__PREFERRED_LANG__ !== 'undefined' ? global.__PREFERRED_LANG__ : undefined;
    if (serverLang && serverLang !== '__LANG_PLACEHOLDER__' && supported.indexOf(serverLang) !== -1) return serverLang;

    if (opts.checkLocalStorage && typeof global.localStorage !== 'undefined') {
      var saved = global.localStorage.getItem('lang');
      if (saved && supported.indexOf(saved) !== -1) return saved;
    }

    var nav = global.navigator && ((global.navigator.languages && global.navigator.languages.length) ? global.navigator.languages : [global.navigator.language]);
    for (var i = 0; i < nav.length; i++) {
      var base = (nav[i] || '').split('-')[0].toLowerCase();
      if (supported.indexOf(base) !== -1) return base;
    }
    return def;
  }

  /**
   * @param {string} basePath - Base URL path for locales (e.g. '/static/' or '/')
   * @returns {Promise<Object>} Manifest with error, eid, qr (and other) language arrays
   */
  function fetchLocalesManifest(basePath) {
    basePath = (basePath || getBasePath()).replace(/\/?$/, '/');
    var url = basePath + 'locales/languages.json';
    return fetch(url).then(function (r) {
      return r.ok ? r.json() : Promise.resolve({ error: ['en'], eid: ['en'], qr: ['en'] });
    });
  }

  /**
   * @param {string} lang - Lang code (e.g. 'it', 'en')
   * @returns {string} Display label (e.g. 'ITA', 'EN')
   */
  function formatLangLabel(lang) {
    if (!lang) return '';
    return lang === 'it' ? 'ITA' : String(lang).toUpperCase();
  }

  /**
   * Populate a select element with language options from supported list.
   * @param {HTMLSelectElement} selectEl
   * @param {string[]} supported
   * @param {string} selectedValue
   */
  function populateLangSelect(selectEl, supported, selectedValue) {
    if (!selectEl || !supported || !supported.length) return;
    selectEl.innerHTML = supported.map(function (l) {
      return '<option value="' + l + '">' + formatLangLabel(l) + '</option>';
    }).join('');
    selectEl.value = selectedValue;
  }

  var api = {
    getBasePath: getBasePath,
    getPreferredLanguage: getPreferredLanguage,
    fetchLocalesManifest: fetchLocalesManifest,
    formatLangLabel: formatLangLabel,
    populateLangSelect: populateLangSelect
  };

  if (typeof global !== 'undefined') {
    global.LocaleUtils = api;
  }
  /* global module */
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
