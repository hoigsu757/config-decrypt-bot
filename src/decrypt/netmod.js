import { emptyResult, buildVless, buildTrojan } from "./format.js";
import { b64decode, aesEcbDecrypt, pkcs7Unpad, utf8 } from "../crypto/util.js";

const KEYS = ["<n3t5yn4^n3tm0d>", "_netsyna_netmod_", "nicetrybuddygoon"];

export function tryNetmod(name, text) {
  const cleaned = text.replace(/\s+/g, "");
  if (!cleaned || cleaned.length < 32) return null;
  const looksNm = /\.nm$/i.test(name || "") || /^[A-Za-z0-9+/=]+$/.test(cleaned);

  let json = null;
  try {
    if (text.trim().startsWith("{")) json = JSON.parse(text);
  } catch {}

  if (!json) {
    try {
      const ct = b64decode(cleaned);
      if (ct.length % 16 !== 0) {
        if (looksNm) {
          const r = emptyResult("NetMod (.nm)");
          r.note = "طول ciphertext نامعتبر است.";
          return r;
        }
        return null;
      }
      for (const key of KEYS) {
        try {
          const pt = pkcs7Unpad(aesEcbDecrypt(new TextEncoder().encode(key), ct));
          const s = utf8(pt);
          if (s.includes("{")) {
            json = JSON.parse(s);
            break;
          }
        } catch {}
      }
    } catch {
      if (!looksNm) return null;
    }
  }

  if (!json) {
    if (looksNm) {
      const r = emptyResult("NetMod (.nm)");
      r.note = "کلید NetMod جور نشد.";
      return r;
    }
    return null;
  }

  const list = json.Common || json.common || (Array.isArray(json) ? json : [json]);
  const p = list[0] || {};
  const r = emptyResult("NetMod (.nm)");
  r.server.protocol = String(p.Protocol || p.protocol || "vless").toLowerCase();
  r.server.host = p.Hostname || p.Host || p.hostname;
  r.server.port = p.Port || p.port;
  r.server.uuid = p.UserID || p.uuid || p.UUID;
  r.server.password = p.Password || p.password;
  r.server.user = p.User || p.user;
  r.server.transport = String(p.TransferProtocol || p.network || "tcp").toLowerCase();
  r.server.tls = String(p.TLSType || p.tls || "").toLowerCase() || undefined;
  r.server.sni = p.SNI || p.sni;
  r.server.path = p.Path || p.path;
  r.server.hostHeader = p.Host || p.host;
  r.server.alpn = p.Alpn || p.alpn;
  r.server.remark = p.Remark || p.remark;
  r.server.encryption = p.EncryptMethod || p.encryption || "none";
  r.server.flow = p.Flow || p.flow;

  if (r.server.protocol === "vless") {
    r.vless = buildVless(r.server);
    if (r.vless) r.links.push(r.vless);
  } else if (r.server.protocol === "trojan") {
    const t = buildTrojan(r.server);
    if (t) r.links.push(t);
  }
  return r;
}
