#!/usr/bin/env node
// Artifact Keeper release-gate MCP echo server.
//
// A dependency-free MCP server over stdio: newline-delimited JSON-RPC 2.0 on
// stdin/stdout, diagnostics on stderr. It implements the lifecycle
// (initialize, notifications/initialized, ping), tools/list and tools/call
// with one tool, `echo`, which returns its `text` argument unchanged. The
// release gate installs it from an Artifact Keeper npm repository and drives
// it with tests/lib/mcp-stdio-client.py, so nothing here may require a
// package from the public registry.
//
// AK_E2E_ECHO_MARKER, when set, is appended to the server's instructions so a
// test can prove which installed copy answered.

'use strict';

const readline = require('readline');

function packageVersion() {
  try {
    return require('../package.json').version;
  } catch (e) {
    return '0.0.0-fixture';
  }
}

const SERVER_INFO = { name: 'ak-e2e-echo', version: packageVersion() };
const SUPPORTED = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
const TOOLS = [
  {
    name: 'echo',
    title: 'Echo',
    description: 'Return the text argument unchanged.',
    inputSchema: {
      type: 'object',
      properties: { text: { type: 'string', description: 'Text to echo back' } },
      required: ['text'],
      additionalProperties: false,
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  },
];

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + '\n');
}

function result(id, value) {
  send({ jsonrpc: '2.0', id, result: value });
}

function error(id, code, message) {
  send({ jsonrpc: '2.0', id, error: { code, message } });
}

function handle(msg) {
  if (!msg || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    if (msg && msg.id !== undefined) error(msg.id, -32600, 'Invalid Request');
    return;
  }
  const isRequest = msg.id !== undefined && msg.id !== null;
  const params = msg.params || {};
  switch (msg.method) {
    case 'initialize': {
      const asked = params.protocolVersion;
      const version = SUPPORTED.includes(asked) ? asked : SUPPORTED[0];
      let instructions = 'Echo server for the Artifact Keeper release gate.';
      if (process.env.AK_E2E_ECHO_MARKER) instructions += ' marker=' + process.env.AK_E2E_ECHO_MARKER;
      result(msg.id, {
        protocolVersion: version,
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER_INFO,
        instructions,
      });
      return;
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      return;
    case 'ping':
      if (isRequest) result(msg.id, {});
      return;
    case 'tools/list':
      result(msg.id, { tools: TOOLS });
      return;
    case 'tools/call': {
      if (params.name !== 'echo') {
        error(msg.id, -32602, 'Unknown tool: ' + String(params.name));
        return;
      }
      const args = params.arguments || {};
      if (typeof args.text !== 'string') {
        result(msg.id, { content: [{ type: 'text', text: 'text must be a string' }], isError: true });
        return;
      }
      result(msg.id, { content: [{ type: 'text', text: args.text }], isError: false });
      return;
    }
    default:
      if (isRequest) error(msg.id, -32601, 'Method not found: ' + msg.method);
  }
}

const rl = readline.createInterface({ input: process.stdin, terminal: false });
rl.on('line', (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;
  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch (e) {
    send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
    return;
  }
  if (Array.isArray(msg)) {
    msg.forEach(handle);
  } else {
    handle(msg);
  }
});
rl.on('close', () => process.exit(0));
process.stderr.write('ak-e2e-echo MCP server ready on stdio\n');
