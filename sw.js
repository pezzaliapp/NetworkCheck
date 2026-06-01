/* NetworkCheck — service worker.
   Cache versionata, strategia cache-first con fallback offline, pulizia delle
   cache vecchie all'attivazione. Nessuna chiamata di rete in uscita verso terzi. */

const CACHE = 'networkcheck-v1';

/* Risorse del guscio applicativo, tutte con percorsi relativi. */
const ASSETS = [
  './',
  './index.html',
  './css/style.css',
  './js/app.js',
  './js/parser.js',
  './js/i18n.js',
  './manifest.webmanifest',
  './icons/favicon.svg',
  './icons/favicon.png',
  './icons/apple-touch-icon.png',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/icon-512-maskable.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  event.respondWith(
    caches.match(request).then((cached) => {
      if (cached) return cached;
      return fetch(request)
        .then((response) => {
          /* Memorizza solo risposte valide della stessa origine. */
          if (
            response &&
            response.status === 200 &&
            response.type === 'basic'
          ) {
            const copy = response.clone();
            caches.open(CACHE).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => {
          /* Offline: per le navigazioni restituisci la pagina principale. */
          if (request.mode === 'navigate') {
            return caches.match('./index.html');
          }
          return undefined;
        });
    })
  );
});
