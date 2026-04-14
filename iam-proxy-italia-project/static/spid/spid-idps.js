// * spid-idps.js *
// Legacy discovery: populates ul#spid-idp-list-medium-root-get from js/spid-idps-default.json
var SPID_IDPS_JSON_URL = 'js/spid-idps-default.json';

const urlParams = new URLSearchParams(window.location.search);
const servicePath = urlParams.get("return");
const entityID = urlParams.get('entityID');

function addIdpEntry(data, element) {
  let li = document.createElement('li');
  li.className = 'spid-idp-button-link'
  const logoHtml = data['logo'] ? `<img src="${data['logo']}" alt="${data['entityName']}">` : `<span class="spid-idp-name">${data['entityName']}</span>`;
  li.innerHTML = `<a href="${servicePath}?entityID=${encodeURIComponent(data['entityID'])}&return=${encodeURIComponent(servicePath)}"><span class="spid-sr-only">${data['entityName']}</span>${logoHtml}</a>`
  element.prepend(li)
}

function runLegacyDiscovery(raw) {
  var idps = raw.map(function (x) {
    return {
      entityName: x.organization_name,
      entityID: x.entity_id,
      logo: x.logo_uri || ""
    };
  }).sort(() => Math.random() - 0.5);
  if (!entityID) { alert('To use a Discovery Service you must come from a Service Provider') }
  var ul = document.querySelector('ul#spid-idp-list-medium-root-get');
  if (!ul) return;
  for (var i = 0; i < idps.length; i++) { addIdpEntry(idps[i], ul); }
}

function whenDomReady(fn) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', fn);
  } else {
    fn();
  }
}

fetch(SPID_IDPS_JSON_URL)
  .then(function (r) { return r.ok ? r.json() : Promise.reject(new Error(String(r.status))); })
  .then(function (data) {
    whenDomReady(function () { runLegacyDiscovery(data); });
  })
  .catch(function (err) { console.error('spid-idps: failed to load IdP list', err); });
