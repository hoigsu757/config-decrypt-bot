import { emptyResult } from "./format.js";
import { b64decode, inflate, utf8 } from "../crypto/util.js";

export async function tryRocket(name, text) {
  let b64 = null;
  const url = text.match(/rcktnl\.site\/i\/([A-Za-z0-9_%>+\/=-]+)/i);
  if (url) b64 = decodeURIComponent(url[1]);
  else if (/^[\sA-Za-z0-9+/=]+$/.test(text.trim()) && text.trim().length > 60) b64 = text.trim();
  if (!b64) return null;
  try {
    const raw = b64decode(b64);
    const body = raw[0] < 16 ? raw.slice(1) : raw;
    let inflated;
    try { inflated = await inflate(body); } catch { inflated = body; }
    const map = decodeMsgpackMap(inflated);
    if (!map) return null;
    const r = emptyResult("Rocket Tunnel");
    r.server.protocol = String(map["0"] ?? "ssh");
    r.server.remark = map["1"];
    r.server.host = map["2"];
    r.server.port = map["3"];
    r.server.user = map["4"];
    r.server.password = map["5"];
    r.note = "SSH/Direct — به VLESS تبدیل نمی‌شود.";
    return r;
  } catch { return null; }
}

function decodeMsgpackMap(buf) {
  let i = 0; const b = buf;
  if (i >= b.length) return null;
  const head = b[i++];
  let n;
  if (head >= 0x80 && head <= 0x8f) n = head - 0x80;
  else if (head === 0xde) { n = (b[i]<<8)|b[i+1]; i+=2; }
  else return null;
  const out = {};
  for (let k = 0; k < n; k++) { const key = readVal(); out[String(key)] = readVal(); }
  return out;
  function readVal() {
    const h = b[i++];
    if (h === 0xc0) return null;
    if (h <= 0x7f) return h;
    if (h >= 0xe0) return h - 256;
    if (h === 0xcc) return b[i++];
    if (h === 0xcd) { const v=(b[i]<<8)|b[i+1]; i+=2; return v; }
    if (h === 0xce) { const v=((b[i]<<24)|(b[i+1]<<16)|(b[i+2]<<8)|b[i+3])>>>0; i+=4; return v; }
    if (h >= 0xa0 && h <= 0xbf) return readStr(h-0xa0);
    if (h === 0xd9) return readStr(b[i++]);
    if (h === 0xda) { const len=(b[i]<<8)|b[i+1]; i+=2; return readStr(len); }
    return null;
  }
  function readStr(len) { const s = utf8(b.slice(i,i+len)); i+=len; return s; }
}
