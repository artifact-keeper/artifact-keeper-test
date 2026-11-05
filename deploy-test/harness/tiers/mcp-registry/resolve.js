#!/usr/bin/env node
// tiers/mcp-registry/resolve.js - resolve an MCP server the way an agent host
// does, from inside the client container (node >= 18, global fetch).
//
// Env: REG (registry root as a client is configured with it,
// <ak>/mcp/<repo>), NAME (server name), VER (exact version or "latest").
// Reads GET $REG/v0.1/servers/<enc NAME>/versions/<enc VER> anonymously and
// prints one JSON line:
//   {"status":200,"registryType":"npm","identifier":"...","version":"...",
//    "advertised":"<registryBaseUrl as served>","use":"<base to install from>"}
// "use" is the advertised registryBaseUrl verbatim when its origin is the
// origin the client reached the registry on, otherwise the same path on the
// registry's origin (AK_EXTERNAL_URL may name a host this network cannot
// reach; the path is the part the registry decides).
// Exit 0 when a document was read (any status), 1 on a transport error.
'use strict';

async function main() {
  const reg = process.env.REG;
  const name = process.env.NAME;
  const ver = process.env.VER || 'latest';
  const url = `${reg}/v0.1/servers/${encodeURIComponent(name)}/versions/${encodeURIComponent(ver)}`;
  const res = await fetch(url, { headers: { Accept: 'application/json' } });
  const text = await res.text();
  const out = { status: res.status, url };
  if (res.status === 200) {
    const doc = JSON.parse(text);
    const pkg = ((doc.server || {}).packages || [])[0] || {};
    out.registryType = pkg.registryType || '';
    out.identifier = pkg.identifier || '';
    out.version = pkg.version || '';
    out.advertised = pkg.registryBaseUrl || '';
    if (out.advertised) {
      const adv = new URL(out.advertised);
      const origin = new URL(reg).origin;
      out.use = adv.origin === origin ? out.advertised.replace(/\/+$/, '') : origin + adv.pathname.replace(/\/+$/, '');
    }
  } else {
    out.body = text.slice(0, 400);
  }
  process.stdout.write(JSON.stringify(out) + '\n');
}

main().catch((err) => {
  process.stderr.write(`resolve failed: ${err && err.stack ? err.stack : err}\n`);
  process.exit(1);
});
