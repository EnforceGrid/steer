#!/usr/bin/env node
/**
 * Lightweight mock OpenAI-compatible upstream for throughput benchmarking.
 *
 * Returns a canned chat completion after a configurable delay (default 60ms)
 * to simulate upstream latency without hitting a real LLM.
 *
 * Default 60ms matches Bifrost's benchmark methodology for apples-to-apples
 * gateway comparison. Use MOCK_DELAY_MS=200 for realistic LLM latency profiles.
 *
 * Usage:
 *   node k6/mock-upstream.js                  # port 9999, 60ms delay
 *   MOCK_PORT=8888 MOCK_DELAY_MS=200 node k6/mock-upstream.js
 */

const http = require('http');
const cluster = require('cluster');
const os = require('os');

const PORT = parseInt(process.env.MOCK_PORT || '9999', 10);
const DELAY_MS = parseInt(process.env.MOCK_DELAY_MS || '60', 10);
const WORKERS = parseInt(process.env.MOCK_WORKERS || String(os.cpus().length), 10);

const RESPONSE = JSON.stringify({
  id: 'chatcmpl-bench',
  object: 'chat.completion',
  model: 'mock-model',
  choices: [{
    index: 0,
    message: { role: 'assistant', content: 'OK' },
    finish_reason: 'stop',
  }],
  usage: { prompt_tokens: 5, completion_tokens: 1, total_tokens: 6 },
});

const HEADERS = {
  'Content-Type': 'application/json',
  'Content-Length': Buffer.byteLength(RESPONSE),
};

if (cluster.isPrimary) {
  console.log(`mock-upstream primary: spawning ${WORKERS} workers (delay=${DELAY_MS}ms)`);
  for (let i = 0; i < WORKERS; i++) {
    cluster.fork();
  }
  cluster.on('exit', (worker) => {
    console.log(`worker ${worker.process.pid} exited, respawning`);
    cluster.fork();
  });
  process.on('SIGINT', () => {
    console.log('\nmock-upstream shutting down');
    process.exit(0);
  });
} else {
  let reqCount = 0;

  const server = http.createServer((req, res) => {
    reqCount++;

    // Health check for readiness detection
    if (req.url === '/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('ok');
      return;
    }

    // Simulate upstream latency then respond
    if (DELAY_MS > 0) {
      setTimeout(() => {
        res.writeHead(200, HEADERS);
        res.end(RESPONSE);
      }, DELAY_MS);
    } else {
      res.writeHead(200, HEADERS);
      res.end(RESPONSE);
    }
  });

  server.listen(PORT, '127.0.0.1', () => {
    console.log(`  worker ${process.pid} listening on http://127.0.0.1:${PORT}`);
  });
}
