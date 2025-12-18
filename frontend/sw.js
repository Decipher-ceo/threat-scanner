const CACHE_NAME = 'threat-scanner-v1';
const ASSETS = [
    '/',
    '/dashboard.html',
    '/testing.html',
    '/reports.html',
    '/login.html',
    '/assets/styles.css',
    '/assets/auth.js',
    '/js/dashboard.js',
    '/manifest.json'
];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then((cache) => cache.addAll(ASSETS))
    );
});

self.addEventListener('fetch', (event) => {
    // For API requests, always go to network (don't cache)
    if (event.request.url.includes('/api/') || event.request.url.includes('127.0.0.1:5000')) {
        return;
    }

    event.respondWith(
        caches.match(event.request)
            .then((response) => response || fetch(event.request))
    );
});
