// Cookieless Cloudflare Web Analytics on the canonical site, skipped under Do Not Track or Global Privacy Control.
if (location.hostname === 'glarion.app' && navigator.doNotTrack !== '1' && !navigator.globalPrivacyControl) {
  const s = document.createElement('script');
  s.defer = true;
  s.src = 'https://static.cloudflareinsights.com/beacon.min.js';
  s.dataset.cfBeacon = '{"token": "59a21b799a154059b0e50071e09ceec2"}';
  document.head.append(s);
}
