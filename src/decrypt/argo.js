import { emptyResult } from "./format.js";
import { b64decode, b64encode, inflate, utf8, utf8Encode } from "../crypto/util.js";

export async function tryArgo(text) {
  const m = text.match(/-----BEGIN ARGO VPN BRIDGE BLOCK-----([\s\S]*?)-----END ARGO VPN BRIDGE BLOCK-----/i);
  if (!m) return null;
  try {
    const raw = b64decode(m[1].replace(/\s+/g, ""));
    const outer = JSON.parse(utf8(await inflate(raw)));
    const inner = JSON.parse(atob(outer.payload));
    const r = emptyResult("ArgoVPN Bridge");
    r.server.protocol = inner.protocol || "A";
    r.server.host = inner.server;
    r.server.port = inner.port;
    r.server.remark = inner.name || inner.remark || null;
    r.note = "فقط آدرس پل.";
    r._argoOuter = outer;
    r._argoInner = inner;
    r._argoRawBlock = m[0];
    return r;
  } catch {
    return null;
  }
}

/** Rebuild importable ARGO block from inner fields (keeps signature when possible). */
export async function buildArgoBlock(server, extra = {}) {
  const inner = {
    protocol: server.protocol || "A",
    server: server.host,
    port: Number(server.port) || 443,
  };
  if (extra.remark) inner.name = String(extra.remark);
  else if (server.remark) inner.name = String(server.remark);

  const outer = {
    version: extra.version || 1,
    payload: btoa(JSON.stringify(inner)),
    signature: extra.signature || "",
  };

  const json = utf8Encode(JSON.stringify(outer));
  const compressed = await deflate(json);
  const b64 = b64encode(compressed);
  // wrap lines ~60 like original samples
  const lines = b64.match(/.{1,60}/g)?.join("\n") || b64;
  return (
    "-----BEGIN ARGO VPN BRIDGE BLOCK-----\n" +
    lines +
    "\n-----END ARGO VPN BRIDGE BLOCK-----"
  );
}

async function deflate(data) {
  const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
