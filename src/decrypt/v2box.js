import { emptyResult, buildVless } from "./format.js";
import { b64decode, pbkdf2Sha256, aesGcmDecrypt, utf8 } from "../crypto/util.js";

export async function tryV2box(name, text, password) {
  let obj;
  try {
    obj = JSON.parse(text);
  } catch {
    return null;
  }
  if (obj.magic !== "v2box_export" && !/\.v2box$/i.test(name || "")) return null;

  const r = emptyResult("V2Box Export");
  if (!password) {
    r.note = "فایل V2Box رمزدار است. رمز Export را بفرست:\n/pass رمز_اینجا\nسپس دوباره فایل را بفرست.";
    return r;
  }

  try {
    const hdr = JSON.parse(utf8(b64decode(obj.header)));
    const salt = b64decode(hdr.salt);
    const nonce = b64decode(obj.nonce);
    const tag = b64decode(obj.tag);
    const ct = b64decode(obj.ciphertext);
    const ctTag = new Uint8Array(ct.length + tag.length);
    ctTag.set(ct);
    ctTag.set(tag, ct.length);

    const key = await pbkdf2Sha256(password, salt, hdr.iterations || 600000, 32);
    let pt;
    try {
      pt = await aesGcmDecrypt(key, nonce, ctTag);
    } catch {
      // try AAD = header string
      pt = await aesGcmDecrypt(key, nonce, ctTag, new TextEncoder().encode(obj.header));
    }
    const decoded = utf8(pt);
    r.note = null;

    // try parse as JSON config / links
    try {
      const j = JSON.parse(decoded);
      fillFromJson(r, j);
    } catch {
      const link = decoded.match(/vless:\/\/[^\s]+/);
      if (link) {
        r.vless = link[0];
        r.links.push(link[0]);
      } else {
        r.note = "رمز درست بود؛ محتوای خام:\n" + decoded.slice(0, 500);
      }
    }
    return r;
  } catch (e) {
    r.note = "رمز اشتباه یا فایل خراب است.";
    return r;
  }
}

function fillFromJson(r, j) {
  const list = Array.isArray(j) ? j : j.outbounds || j.configs || j.servers || [j];
  const p = list[0] || j;
  if (typeof p === "string" && p.includes("://")) {
    r.links.push(p);
    if (p.startsWith("vless://")) r.vless = p;
    return;
  }
  r.server.protocol = (p.protocol || p.type || "vless").toLowerCase();
  r.server.host = p.server || p.address || p.host;
  r.server.port = p.server_port || p.port;
  r.server.uuid = p.uuid || p.id;
  r.server.password = p.password;
  r.server.sni = p.sni || p.tls?.server_name;
  r.server.transport = p.network || p.transport?.type;
  if (r.server.protocol === "vless") {
    r.vless = buildVless(r.server);
    if (r.vless) r.links.push(r.vless);
  }
}
