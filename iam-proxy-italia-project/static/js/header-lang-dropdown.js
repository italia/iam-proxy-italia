/**
 * Language switcher aligned with developers.italia.it (slim header dropdown + link-list).
 */
(function (global) {
  /** Spazio tra trigger e menu: il margin sul .dropdown-menu è ignorato da Popper (usa transform). */
  // var MENU_OFFSET_PX = 24;

  function bindLangMenuPopper(toggle) {
    if (!global.bootstrap || !global.bootstrap.Dropdown || !toggle) return;
    var existing = bootstrap.Dropdown.getInstance(toggle);
    if (existing) existing.dispose();
    new bootstrap.Dropdown(toggle, {
      popperConfig: function (defaultConfig) {
        var base = defaultConfig || {};
        var mods = Array.isArray(base.modifiers) ? base.modifiers.slice() : [];
        var found = false;
        mods = mods.map(function (m) {
          if (m.name !== 'offset') return m;
          found = true;
          var opt = Object.assign({}, m.options || {});
          opt.offset = [0, MENU_OFFSET_PX];
          return Object.assign({}, m, { options: opt });
        });
        if (!found) {
          mods.push({
            name: 'offset',
            options: { offset: [0, MENU_OFFSET_PX] },
          });
        }
        return Object.assign({}, base, { modifiers: mods });
      },
    });
  }

  function syncRoot(root, lng) {
    var code = (lng || 'it').split('-')[0] === 'en' ? 'en' : 'it';
    var label = root.querySelector('.it-header-lang-label');
    if (label) label.textContent = code === 'en' ? 'EN' : 'ITA';
    root.querySelectorAll('.it-lang-option').forEach(function (a) {
      a.classList.toggle('active', a.getAttribute('data-lang') === code);
    });
  }

  global.initHeaderLangDropdown = function (i18next, options) {
    if (!i18next || typeof i18next.changeLanguage !== 'function') return;
    options = options || {};
    var afterChange = options.afterLanguageChange;

    document.querySelectorAll('.it-header-lang-dropdown').forEach(function (root) {
      if (root.dataset.langDropdownBound === '1') return;
      root.dataset.langDropdownBound = '1';

      var toggle = root.querySelector('[data-bs-toggle="dropdown"]');
      if (!toggle) return;

      bindLangMenuPopper(toggle);

      root.querySelectorAll('.it-lang-option').forEach(function (a) {
        a.addEventListener('click', function (e) {
          e.preventDefault();
          var lng = a.getAttribute('data-lang');
          if (!lng) return;
          if (global.bootstrap && toggle) {
            var dd = bootstrap.Dropdown.getInstance(toggle);
            if (dd) dd.hide();
          }
          i18next.changeLanguage(lng).then(function () {
            if (typeof afterChange === 'function') afterChange(lng);
          });
        });
      });

      i18next.on('languageChanged', function (lng) {
        syncRoot(root, lng);
      });
      syncRoot(root, i18next.language);
    });
  };
})(typeof window !== 'undefined' ? window : this);
