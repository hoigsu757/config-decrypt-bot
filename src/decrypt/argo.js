import { emptyResult } from "./format.js";
import { b64decode, inflate, utf8 } from "../crypto/util.js";
export async function tryArgo(text) {
  const m = text.match(/-----BEGIN ARGO VPN BRIDGE BLOCK-----([\s\S]*?)-----END ARGO VPN BRIDGE BLOCK-----/i);
  if (!m) return null;
  try {
    const raw = b64decode(m[1]);
    const outer = JSON.parse(utf8(await inflate(raw)));
    const inner = JSON.parse(atob(outer.payload));
    const r = emptyResult("ArgoVPN Bridge");
    r.server.protocol = inner.protocol || "A";
    r.server.host = inner.server;
    r.server.port = inner.port;
    r.note = "فقط آدرس پل.";
    return r;
  } catch { return null; }
}
