/**
 * CloudFront Function — viewer-request handler for VitePress cleanUrls.
 *
 * VitePress builds extension-less URLs (e.g. /security, /backends/aws-ssm).
 * S3 needs the full filename to serve. This function rewrites the URI:
 *   /                       → /index.html
 *   /security               → /security.html
 *   /backends/              → /backends/index.html
 *   /backends/aws-ssm       → /backends/aws-ssm.html
 *   /assets/foo.abc123.js   → unchanged (has extension)
 *
 * Deployment:
 * 1. AWS Console → CloudFront → Functions → Create function
 *    - Name:    secretenv-docs-url-rewrite
 *    - Runtime: cloudfront-js-2.0
 * 2. Paste this code, Save & Test
 * 3. Publish the function
 * 4. CloudFront → Distributions → <your distribution> → Behaviors
 *    - Edit the default behavior
 *    - Function associations → Viewer request → Function type CloudFront
 *      Functions → choose secretenv-docs-url-rewrite
 *    - Save changes
 *
 * 404 handling: under Distribution → Error pages, map status code 404 to
 * /404.html with response code 404 and a short cache TTL (e.g. 60s).
 */
function handler(event) {
  var request = event.request;
  var uri = request.uri;

  // Directory paths -> /<dir>/index.html
  if (uri.endsWith('/')) {
    request.uri = uri + 'index.html';
    return request;
  }

  // Already has an extension -> serve as-is
  // (matches files with a dot in the last path segment)
  var lastSegment = uri.substring(uri.lastIndexOf('/') + 1);
  if (lastSegment.indexOf('.') !== -1) {
    return request;
  }

  // Extension-less -> append .html
  request.uri = uri + '.html';
  return request;
}
