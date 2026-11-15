import { emptyResult } from "./format.js";
import { b64decode, inflate, utf8 } from "../crypto/util.js";

export async function tryRocket(name, text) {
  let b64 = null;
  const url = text.match(/rcktnl\.site\/i\/([A-Za-z0-9_%+.\/=-]+)/i);
  if (url) b64 = decodeURIComponent(url[1]);
  else if (/^[\sA-Za-z0-9+/=]+$/.test(text.trim()) && text.trim().length > 60) b64 = text.trim();
  if (!b64) return null;

  try {
    const raw = b64decode(b64);
    const inflated = await decompressRocket(raw);
    if (!inflated) return null;

    const root = decodeMsgpack(inflated);
    if (root == null) return null;

    const flat = {};
    collect(root, flat);

    const r = emptyResult("Rocket Tunnel");
    r.server.protocol = pick(flat, ["0", "protocol", "type"]) || "ssh";
    r.server.remark = pick(flat, ["remark", "name", "title"]);
    r.server.host =
      pick(flat, ["2", "host", "hostname", "server", "ip"]) ||
      firstHost(flat);
    r.server.port = String(
      pick(flat, ["port", "serverPort", "3"]) || firstPort(flat) || ""
    );
    r.server.user = pick(flat, ["1", "4", "user", "username", "login"]);
    r.server.password = pick(flat, ["5", "9", "password", "pass", "pwd"]);
    if (!r.server.host) return null;
    r.note = "Rocket Tunnel — معمولاً SSH/Direct است.";
    return r;
  } catch {
    return null;
  }
}

async function decompressRocket(raw) {
  // version header then zlib (78 9c)
  for (let off = 0; off <= 4 && off < raw.length - 2; off++) {
    if (raw[off] === 0x78 && (raw[off + 1] === 0x9c || raw[off + 1] === 0xda || raw[off + 1] === 0x01)) {
      try {
        return await inflate(raw.slice(off));
      } catch {}
    }
  }
  try {
    return await inflate(raw[0] < 16 ? raw.slice(1) : raw);
  } catch {}
  try {
    return await inflate(raw.slice(2));
  } catch {}
  return raw;
}

function pick(flat, keys) {
  for (const k of keys) {
    const v = flat[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}

function firstHost(flat) {
  for (const v of Object.values(flat)) {
    if (typeof v === "string" && /^(?:\d{1,3}\.){3}\d{1,3}$|^[a-z0-9.-]+\.[a-z]{2,}$/i.test(v) && v !== "127.0.0.1")
      return v;
  }
  for (const v of Object.values(flat)) {
    if (typeof v === "string" && /^(?:\d{1,3}\.){3}\d{1,3}$/i.test(v)) return v;
  }
  return undefined;
}

function firstPort(flat) {
  for (const [k, v] of Object.entries(flat)) {
    if (/port/i.test(k) && typeof v === "number" && v > 0 && v < 65536) return v;
  }
  return undefined;
}

function collect(node, out, prefix = "") {
  if (node == null) return;
  if (Array.isArray(node)) {
    node.forEach((v, i) => collect(v, out, prefix ? `${prefix}.${i}` : String(i)));
    return;
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      const key = String(k);
      if (v !== null && typeof v === "object") collect(v, out, key);
      else out[key] = v;
    }
    return;
  }
}

function decodeMsgpack(buf) {
  let i = 0;
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  function read() {
    if (i >= b.length) return null;
    const h = b[i++];
    if (h === 0xc0) return null;
    if (h === 0xc2) return false;
    if (h === 0xc3) return true;
    if (h <= 0x7f) return h;
    if (h >= 0xe0) return h - 256;
    if (h === 0xcc) return b[i++];
    if (h === 0xcd) {
      const v = (b[i] << 8) | b[i + 1];
      i += 2;
      return v;
    }
    if (h === 0xce) {
      const v = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
      i += 4;
      return v;
    }
    if (h === 0xd0) {
      const v = b[i++];
      return v > 127 ? v - 256 : v;
    }
    if (h === 0xd1) {
      const v = (b[i] << 8) | b[i + 1];
      i += 2;
      return v > 0x7fff ? v - 0x10000 : v;
    }
    if (h >= 0xa0 && h <= 0xbf) return str(h - 0xa0);
    if (h === 0xd9) return str(b[i++]);
    if (h === 0xda) {
      const len = (b[i] << 8) | b[i + 1];
      i += 2;
      return str(len);
    }
    if (h === 0xdb) {
      const len = ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
      i += 4;
      return str(len);
    }
    if (h >= 0x90 && h <= 0x9f) return arr(h - 0x90);
    if (h === 0xdc) {
      const n = (b[i] << 8) | b[i + 1];
      i += 2;
      return arr(n);
    }
    if (h >= 0x80 && h <= 0x8f) return map(h - 0x80);
    if (h === 0xde) {
      const n = (b[i] << 8) | b[i + 1];
      i += 2;
      return map(n);
    }
    return null;
  }
  function str(len) {
    const s = utf8(b.slice(i, i + len));
    i += len;
    return s;
  }
  function arr(n) {
    const a = [];
    for (let k = 0; k < n; k++) a.push(read());
    return a;
  }
  function map(n) {
    const o = {};
    for (let k = 0; k < n; k++) {
      const key = read();
      o[String(key)] = read();
    }
    return o;
  }
  return read();
}
