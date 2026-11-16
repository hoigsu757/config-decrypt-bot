import { emptyResult } from "./format.js";
import { b64decode, b64encode, inflate, utf8, utf8Encode } from "../crypto/util.js";

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
      pick(flat, ["2", "host", "hostname", "server", "ip"]) || firstHost(flat);
    r.server.port = String(pick(flat, ["port", "serverPort", "3"]) || firstPort(flat) || "");
    r.server.user = pick(flat, ["1", "4", "user", "username", "login"]);
    r.server.password = pick(flat, ["5", "password", "pass", "pwd"]);
    if (!r.server.host) return null;
    r.note = "Rocket Tunnel — معمولاً SSH/Direct است.";
    r._rocketMap = flattenToRocketMap(flat, r.server);
    r._rocketUrl = text.match(/https?:\/\/rcktnl\.site\/i\/[^\s]+/i)?.[0] || null;
    return r;
  } catch {
    return null;
  }
}

/** Build importable https://rcktnl.site/i/... from server fields */
export async function buildRocketUrl(server, extra = {}) {
  const map = {
    "0": server.protocol || "ssh_direct",
    "1": server.user || "",
    "2": server.host || "",
    "3": Number(server.port) || 22,
    "4": server.user || "",
    "5": server.password || "",
    "6": {
      hostname: extra.localHost || "127.0.0.1",
      port: Number(server.port) || 22,
    },
    "9": "password",
    "18": false,
  };
  if (extra.remark) map["remark"] = extra.remark;

  const packed = encodeMsgpack([map]);
  const compressed = await deflate(packed);
  const out = new Uint8Array(2 + compressed.length);
  out[0] = 5;
  out[1] = 0;
  out.set(compressed, 2);
  return `https://rcktnl.site/i/${encodeURIComponent(b64encode(out))}`;
}

function flattenToRocketMap(flat, server) {
  return {
    "0": server.protocol || flat["0"] || "ssh_direct",
    "1": server.user || flat["1"] || "",
    "2": server.host || flat["2"] || "",
    "3": Number(server.port || flat["3"] || 22),
    "4": server.user || flat["4"] || flat["1"] || "",
    "5": server.password || flat["5"] || "",
    "6": {
      hostname: flat.hostname || "127.0.0.1",
      port: Number(flat.port || server.port || 22),
    },
    "9": flat["9"] || "password",
    "18": flat["18"] === true,
  };
}

async function deflate(data) {
  const stream = new Blob([data]).stream().pipeThrough(new CompressionStream("deflate"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function decompressRocket(raw) {
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

function collect(node, out) {
  if (node == null) return;
  if (Array.isArray(node)) {
    node.forEach((v) => collect(v, out));
    return;
  }
  if (typeof node === "object") {
    for (const [k, v] of Object.entries(node)) {
      if (v !== null && typeof v === "object" && !Array.isArray(v)) collect(v, out);
      else out[String(k)] = v;
    }
  }
}

function encodeMsgpack(value) {
  const parts = [];
  write(value);
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;

  function write(v) {
    if (v === null || v === undefined) {
      parts.push(Uint8Array.of(0xc0));
      return;
    }
    if (v === false) {
      parts.push(Uint8Array.of(0xc2));
      return;
    }
    if (v === true) {
      parts.push(Uint8Array.of(0xc3));
      return;
    }
    if (typeof v === "number") {
      if (Number.isInteger(v) && v >= 0 && v <= 0x7f) {
        parts.push(Uint8Array.of(v));
      } else if (Number.isInteger(v) && v >= 0 && v <= 0xff) {
        parts.push(Uint8Array.of(0xcc, v));
      } else if (Number.isInteger(v) && v >= 0 && v <= 0xffff) {
        parts.push(Uint8Array.of(0xcd, (v >> 8) & 0xff, v & 0xff));
      } else if (Number.isInteger(v) && v >= 0) {
        parts.push(
          Uint8Array.of(0xce, (v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff)
        );
      } else {
        parts.push(Uint8Array.of(0xcc, 0));
      }
      return;
    }
    if (typeof v === "string") {
      const bytes = utf8Encode(v);
      if (bytes.length <= 31) {
        parts.push(Uint8Array.of(0xa0 + bytes.length));
      } else if (bytes.length <= 0xff) {
        parts.push(Uint8Array.of(0xd9, bytes.length));
      } else {
        parts.push(Uint8Array.of(0xda, (bytes.length >> 8) & 0xff, bytes.length & 0xff));
      }
      parts.push(bytes);
      return;
    }
    if (Array.isArray(v)) {
      if (v.length <= 15) parts.push(Uint8Array.of(0x90 + v.length));
      else parts.push(Uint8Array.of(0xdc, (v.length >> 8) & 0xff, v.length & 0xff));
      for (const item of v) write(item);
      return;
    }
    if (typeof v === "object") {
      const keys = Object.keys(v);
      if (keys.length <= 15) parts.push(Uint8Array.of(0x80 + keys.length));
      else parts.push(Uint8Array.of(0xde, (keys.length >> 8) & 0xff, keys.length & 0xff));
      for (const k of keys) {
        write(String(k));
        write(v[k]);
      }
    }
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
    if (h >= 0xa0 && h <= 0xbf) return str(h - 0xa0);
    if (h === 0xd9) return str(b[i++]);
    if (h === 0xda) {
      const len = (b[i] << 8) | b[i + 1];
      i += 2;
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
