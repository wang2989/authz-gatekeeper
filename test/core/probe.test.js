import { describe, it, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { checkTargetReadiness } from '../../src/core/probe.js';

describe('Target Readiness Probe (src/core/probe.js)', () => {
  let activeServers = [];

  afterEach(async () => {
    await Promise.all(
      activeServers.map(
        (server) =>
          new Promise((resolve) => {
            if (typeof server.closeAllConnections === 'function') {
              server.closeAllConnections();
            }
            server.close(() => resolve());
          })
      )
    );
    activeServers = [];
  });

  function startMockServer(handler) {
    return new Promise((resolve) => {
      const server = http.createServer(handler);
      server.listen(0, '127.0.0.1', () => {
        activeServers.push(server);
        const port = server.address().port;
        resolve({ server, port, url: `http://127.0.0.1:${port}` });
      });
    });
  }

  function getUnusedPort() {
    return new Promise((resolve, reject) => {
      const server = http.createServer();
      server.listen(0, '127.0.0.1', () => {
        const port = server.address().port;
        server.close(() => resolve(port));
      });
      server.on('error', reject);
    });
  }

  it('resolves immediately when /health returns 200 OK', async () => {
    const { url } = await startMockServer((req, res) => {
      if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    const result = await checkTargetReadiness({
      targetUrl: url,
      timeoutMs: 3000,
      intervalMs: 100,
    });

    assert.equal(result.ready, true);
    assert.equal(result.status, 200);
    assert.equal(result.attempts, 1);
  });

  it('falls back to root endpoint when /health returns 404', async () => {
    const { url } = await startMockServer((req, res) => {
      if (req.url === '/') {
        res.writeHead(200);
        res.end('Welcome API');
      } else {
        res.writeHead(404);
        res.end('Not Found');
      }
    });

    const result = await checkTargetReadiness({
      targetUrl: url,
      timeoutMs: 3000,
      intervalMs: 100,
    });

    assert.equal(result.ready, true);
    assert.equal(result.fallback, true);
    assert.equal(result.endpoint, `${url}/`);
  });

  it('retries until server becomes ready', async () => {
    let callCount = 0;
    const { url } = await startMockServer((req, res) => {
      callCount++;
      if (callCount >= 3) {
        res.writeHead(200);
        res.end('ready now');
      } else {
        res.writeHead(503);
        res.end('starting up...');
      }
    });

    const result = await checkTargetReadiness({
      targetUrl: url,
      timeoutMs: 4000,
      intervalMs: 100,
    });

    assert.equal(result.ready, true);
    assert.equal(result.status, 200);
    assert.equal(result.attempts, 3);
  });

  it('throws ERR_TARGET_UNREACHABLE with exitCode 2 when service does not respond in time', async () => {
    const unusedPort = await getUnusedPort();
    const unreachableUrl = `http://127.0.0.1:${unusedPort}`;

    await assert.rejects(
      () =>
        checkTargetReadiness({
          targetUrl: unreachableUrl,
          timeoutMs: 600,
          intervalMs: 150,
        }),
      (err) => {
        assert.equal(err.code, 'ERR_TARGET_UNREACHABLE');
        assert.equal(err.exitCode, 2);
        assert.match(err.message, new RegExp(`Target service at http:\\/\\/127\\.0\\.0\\.1:${unusedPort} was unreachable`));
        assert.match(err.message, /was unreachable after \d+\.\d{2}s \(configured timeout: 0\.60s, \d+ attempts\)/);
        return true;
      }
    );
  });
});

