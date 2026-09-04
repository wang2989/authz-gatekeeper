/**
 * Target Service Readiness Probe
 * 
 * Verifies network reachability to the local or remote target backend before test suite execution.
 * Implements a smart fallback strategy:
 * 1. Checks primary health endpoint (default: /health)
 * 2. If 404 Not Found, probes fallback endpoint (e.g., / or spec URL)
 * 3. Retries until server is responsive or timeout is reached.
 */

/**
 * Polls target server until it is ready to receive requests or timeout expires.
 * 
 * @param {object} options
 * @param {string} options.targetUrl - Base target URL (e.g., http://localhost:8000)
 * @param {string} [options.healthPath='/health'] - Health check path
 * @param {number} [options.timeoutMs=30000] - Total time to wait before failing
 * @param {number} [options.intervalMs=1000] - Wait duration between polling attempts
 * @param {string} [options.specUrl] - Optional HTTP URL to OpenAPI spec
 * @param {function} [options.log] - Optional logger function
 * @returns {Promise<{ ready: boolean, endpoint: string, status: number, attempts: number, durationMs: number }>}
 */
export async function checkTargetReadiness({
  targetUrl,
  healthPath = '/health',
  timeoutMs = 30000,
  intervalMs = 1000,
  specUrl,
  log = () => {},
}) {
  const normalizedTarget = targetUrl.replace(/\/+$/, '');
  const normalizedHealthPath = healthPath.startsWith('/') ? healthPath : `/${healthPath}`;
  const primaryUrl = `${normalizedTarget}${normalizedHealthPath}`;
  const rootUrl = `${normalizedTarget}/`;

  const startTime = Date.now();
  let attempts = 0;
  let lastError = null;

  while (Date.now() - startTime < timeoutMs) {
    attempts++;
    try {
      // 1. Probe primary health endpoint
      const res = await fetch(primaryUrl, {
        method: 'GET',
        signal: AbortSignal.timeout(Math.min(3000, timeoutMs)),
      });

      if (res.status >= 200 && res.status < 400) {
        return {
          ready: true,
          endpoint: primaryUrl,
          status: res.status,
          attempts,
          durationMs: Date.now() - startTime,
        };
      }

      // If health endpoint returns 404, try smart fallback to root '/' or specUrl
      if (res.status === 404) {
        const fallbackUrls = [rootUrl];
        if (specUrl && specUrl.startsWith('http')) {
          fallbackUrls.push(specUrl);
        }

        for (const fallbackUrl of fallbackUrls) {
          try {
            const fallbackRes = await fetch(fallbackUrl, {
              method: 'GET',
              signal: AbortSignal.timeout(Math.min(3000, timeoutMs)),
            });

            // If the server responds to HTTP requests (even 401/403/404), the server process is listening
            if (fallbackRes.status < 500) {
              return {
                ready: true,
                endpoint: fallbackUrl,
                status: fallbackRes.status,
                fallback: true,
                attempts,
                durationMs: Date.now() - startTime,
              };
            }
          } catch {
            // Ignore fallback errors and continue loop
          }
        }
      }

      lastError = new Error(`Server at ${primaryUrl} responded with HTTP ${res.status}`);
    } catch (err) {
      lastError = err;
      log(`[probe] Attempt ${attempts}: Waiting for ${primaryUrl}... (${err.message})`);
    }

    // Check if remaining time allows another interval
    const remainingTime = timeoutMs - (Date.now() - startTime);
    if (remainingTime > 0) {
      const waitTime = Math.min(intervalMs, remainingTime);
      await new Promise((resolve) => setTimeout(resolve, waitTime));
    }
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
  const configuredTimeoutSec = (timeoutMs / 1000).toFixed(2);
  const error = new Error(
    `Target service at ${targetUrl} was unreachable after ${durationSec}s ` +
    `(configured timeout: ${configuredTimeoutSec}s, ${attempts} attempts).\n` +
    `Last error: ${lastError ? lastError.message : 'Unknown error'}\n\n` +
    `Troubleshooting:\n` +
    `  • Verify that your local application server is running and listening on ${targetUrl}\n` +
    `  • If your server uses a custom health route, specify --health-path <path>\n` +
    `  • If readiness was already validated in a prior CI step, bypass with --no-probe`
  );
  error.code = 'ERR_TARGET_UNREACHABLE';
  error.exitCode = 2;
  throw error;
}

