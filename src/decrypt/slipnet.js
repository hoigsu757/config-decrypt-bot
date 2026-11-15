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
    } catch {
      return null;
    }
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

  return mapSlipnet(fields);
}

function loopback(host) {
  const h = String(host || "").trim().toLowerCase();
  return !h || h === "127.0.0.1" || h === "localhost" || h === "::1" || h === "0.0.0.0";
}

function mapSlipnet(f) {
  const r = emptyResult("SlipNet");
  const mode = f[1] || "slipnet";
  const domain = f[3] || "";
  const localPort = f[8] || "";
  const localHost = f[9] || "";
  const sshUser = f[15] || "";
  const sshPass = f[16] || "";
  const sshPort = f[17] || "";
  const sshHost = f[19] || "";
  const naivePort = f[28] || "";
  const naiveUser = f[29] || "";
  const sshSni = f[51] || "";
  const wsPath = f[56] || "";
  const wsHost = f[58] || "";
  const vlessUuid = f[62] || "";
  const vlessSec = f[63] || "";
  const vlessTrans = f[64] || "";
  const vlessPath = f[65] || "";
  const cdnIp = f[66] || "";
  const cdnPort = f[67] || "";
  const vlessSni = f[78] || f[71] || "";

  r.server.protocol = mode;
  r.server.remark = f[2] || "";
  r.server.user = sshUser || naiveUser || f[12] || "";
  r.server.password = sshPass || "";

  if (vlessUuid) {
    r.server.protocol = "vless";
    r.server.uuid = vlessUuid;
    r.server.host = !loopback(cdnIp) ? cdnIp : domain;
    r.server.port = cdnPort || "443";
    r.server.sni = vlessSni || domain || undefined;
    r.server.transport = (vlessTrans || "ws").toLowerCase();
    r.server.path = vlessPath || "/";
    r.server.hostHeader = domain || undefined;
    r.server.tls = vlessSec || "tls";
    r.server.security = vlessSec || "tls";
    r.vless = buildVless(r.server);
    if (r.vless) r.links.push(r.vless);
  } else if (mode === "ssh" || f[14] === "1") {
    // domain is the public hop. sshHost 127.0.0.1 is the SSH daemon inside the tunnel.
    r.server.host = !loopback(sshHost) ? sshHost : domain || sshHost;
    r.server.port = !loopback(sshHost) ? sshPort || "22" : sshPort || "22";
    r.server.sni = sshSni || domain || undefined;
    r.server.path = wsPath && wsPath !== "/" ? wsPath : undefined;
    r.server.hostHeader = wsHost || undefined;
    const bits = [];
    if (domain) bits.push(`دامنه: ${domain}`);
    if (sshHost) bits.push(`SSH داخل تونل: ${sshHost}:${sshPort || "22"}`);
    if (localHost || localPort) bits.push(`SOCKS محلی: ${localHost || "127.0.0.1"}:${localPort || "1080"}`);
    r.note = bits.join(" | ");
  } else {
    r.server.host = !loopback(localHost) ? localHost : domain || localHost;
    r.server.port = !loopback(localHost) ? localPort : naivePort || localPort;
    if (domain && loopback(r.server.host)) r.server.host = domain;
    if (domain) r.note = `دامنه: ${domain}`;
  }

  if (f[33] && /^\d{12,}$/.test(f[33])) {
    const when = new Date(Number(f[33])).toISOString().slice(0, 10);
    r.note = [r.note, `انقضا: ${when}`].filter(Boolean).join(" | ");
  }
  return r;
}
