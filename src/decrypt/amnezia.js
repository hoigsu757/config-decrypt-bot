import { emptyResult } from "./format.js";
export function tryAmnezia(text) {
  if (!/\[Interface\]/i.test(text) || !/\[Peer\]/i.test(text) || !/PrivateKey\s*=/i.test(text)) return null;
  const r = emptyResult(/Jc\s*=|Jmin\s*=|H1\s*=/i.test(text) ? "AmneziaWG" : "WireGuard");
  r.server.protocol = r.format.toLowerCase();
  const endpoint = text.match(/Endpoint\s*=\s*(\S+):(\d+)/i);
  if (endpoint) { r.server.host = endpoint[1]; r.server.port = endpoint[2]; }
  const addr = text.match(/Address\s*=\s*([^\n]+)/i);
  if (addr) r.server.user = addr[1].trim();
  const pub = text.match(/\[Peer\][\s\S]*?PublicKey\s*=\s*(\S+)/i);
  if (pub) r.server.password = pub[1];
  const priv = text.match(/PrivateKey\s*=\s*(\S+)/i);
  if (priv) r.server.uuid = priv[1];
  r.note = "WireGuard/Amnezia به VLESS تبدیل نمی‌شود.";
  return r;
}
