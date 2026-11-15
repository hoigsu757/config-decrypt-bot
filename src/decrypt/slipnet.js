import { emptyResult, buildVless } from "./format.js";
import { b64decode, hexToBytes, aesGcmDecrypt, pbkdf2Sha256, utf8 } from "../crypto/util.js";

const KEY = hexToBytes("214F052025B2F949605A5429EC3D5FA80C2022C168AD946E68852D447214DBD3");

export async function trySlipnet(text, password) {
  const enc = text.match(/slipnet-enc:\/\/([A-Za-z0-9+/=]+)/i);
  const bundle = text.match(/slipnet-bundle-enc:\/\/([A-Za-z0-9+/=]+)/i);
  const plain = text.match(/slipnet:\/\/([^\s]+)/i);
  let fields = null;

  if (enc) {
    try {
      const data = b64decode(enc[1]);
      if (data.length < 13) return null;
      const pt = await aesGcmDecrypt(KEY, data.slice(1, 13), data.slice(13));
      fields = utf8(pt).split("|");
    } catch { return null; }
  } else if (bundle) {
    if (!password) {
      const r = emptyResult("SlipNet Bundle");
      r.note = "bundle رمز دارد. بفرست: /pass رمز";
      r.server.protocol = "slipnet-bundle";
      return r;
    }
    try {
      const data = b64decode(bundle[1]);
      if (data[0] !== 1) throw new Error("ver");
      const key = await pbkdf2Sha256(password, data.slice(1, 17), 600000, 32);
      const pt = await aesGcmDecrypt(key, data.slice(17, 29), data.slice(29));
      fields = utf8(pt).split("|");
    } catch {
      const r = emptyResult("SlipNet Bundle");
      r.note = "رمز اشتباه یا داده خراب.";
      return r;
    }
  } else if (plain) {
    fields = decodeURIComponent(plain[1]).split("|");
  } else return null;

  const r = emptyResult("SlipNet");
  // schema v28 positions
  r.server.protocol = fields[1] || "slipnet";
  r.server.remark = fields[2];
  r.server.port = fields[8];
  r.server.host = fields[9];
  // later fields for VLESS if present (schema dependent)
  for (let i = 0; i < fields.length; i++) {
    const v = fields[i];
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v || "")) {
      r.server.uuid = v;
    }
  }
  if (r.server.uuid && r.server.host && r.server.port) {
    r.server.protocol = "vless";
    r.vless = buildVless(r.server);
    if (r.vless) r.links.push(r.vless);
  }
  if (fields[15]) r.server.user = fields[15];
  if (fields[16]) r.server.password = fields[16];
  return r;
}
