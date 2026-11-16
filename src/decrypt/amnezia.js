import { emptyResult } from "./format.js";

export function tryAmnezia(text) {
  if (!/\[Interface\]/i.test(text) || !/\[Peer\]/i.test(text) || !/PrivateKey\s*=/i.test(text)) return null;
  const isAmnezia = /Jc\s*=|Jmin\s*=|H1\s*=|I1\s*=/i.test(text);
  const r = emptyResult(isAmnezia ? "AmneziaWG" : "WireGuard");
  r.server.protocol = isAmnezia ? "amneziawg" : "wireguard";
  const endpoint = text.match(/Endpoint\s*=\s*(\S+):(\d+)/i);
  if (endpoint) {
    r.server.host = endpoint[1];
    r.server.port = endpoint[2];
  }
  const addr = text.match(/Address\s*=\s*([^\n]+)/i);
  if (addr) r.server.user = addr[1].trim();
  const pub = text.match(/\[Peer\][\s\S]*?PublicKey\s*=\s*(\S+)/i);
  if (pub) r.server.password = pub[1]; // peer public key (not a password; shown as key)
  // never put PrivateKey into uuid — rebrand would invent fake vless
  const priv = text.match(/PrivateKey\s*=\s*(\S+)/i);
  if (priv) r.server.privateKey = priv[1];
  r.server.remark = null;
  r.note = isAmnezia
    ? "AmneziaWG — به VLESS تبدیل نمی‌شود؛ فایل .conf بده."
    : "WireGuard — به VLESS تبدیل نمی‌شود؛ فایل .conf بده.";
  r._rawConf = text;
  return r;
}
