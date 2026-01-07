/**
 * Environment-aware link rewriting
 * Rewrites production URLs to staging equivalents when on staging/dev environments
 */
(function() {
  // Detect if we're on staging:
  // - CloudFront dev domain (before custom domain setup)
  // - ?staging query parameter (for testing)
  // - localhost/127.0.0.1 (local development)
  const hostname = window.location.hostname;
  const params = new URLSearchParams(window.location.search);
  const isStaging = hostname.includes('cloudfront.net') ||
                    hostname.includes('staging') ||
                    params.has('staging') ||
                    hostname === 'localhost' ||
                    hostname === '127.0.0.1';

  if (isStaging) {
    // Rewrite production URLs to staging equivalents
    const mappings = {
      'https://app.a13e.com': 'https://staging.a13e.com',
      'https://docs.a13e.com': 'https://docs.staging.a13e.com'
    };

    document.querySelectorAll('a[href]').forEach(link => {
      let href = link.getAttribute('href');
      for (const [prod, staging] of Object.entries(mappings)) {
        if (href.startsWith(prod)) {
          link.setAttribute('href', href.replace(prod, staging));
          break;
        }
      }
    });
  }
})();
