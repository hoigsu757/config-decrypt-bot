import { emptyResult } from "./format.js";

export function tryTgProxy(text) {
  if (!text) return null;
  // https://t.me/proxy?server=...&port=...&secret=...
  // tg://proxy?server=...&port=...&secret=...
  const m = text.match(
    /(?:https?:\/\/)?(?:t\.me|telegram\.me)\/proxy\?([^\s<>"']+)|tg:\/\/proxy\?([^\s<>"']+)/i
  );
  if (!m) return null;

  const qs = m[1] || m[2];
  let params;
  try {
    params = new URLSearchParams(qs);
  } catch {
    return null;
  }

  const server = params.get("server");
  const port = params.get("port");
  const secret = params.get("secret");
  if (!server || !port || !secret) return null;

  const r = emptyResult("Telegram Proxy");
  r.server.protocol = "mtproto";
  r.server.host = server;
  r.server.port = String(port);
  r.server.password = secret;
  r.server.remark = secretMode(secret);

  const link = `https://t.me/proxy?server=${encodeURIComponent(server)}&port=${encodeURIComponent(port)}&secret=${encodeURIComponent(secret)}`;
  r.links = [link];
  r._tgProxy = { server, port: String(port), secret };
  r.note = secretModeNote(secret);
  return r;
}

export function buildTgProxyLink(server, port, secret) {
  return `https://t.me/proxy?server=${encodeURIComponent(server)}&port=${encodeURIComponent(port)}&secret=${encodeURIComponent(secret)}`;
}

function secretMode(secret) {
  const s = String(secret || "").toLowerCase();
  if (s.startsWith("dd")) return "fake-TLS (dd)";
  if (s.startsWith("ee")) return "secure + domain (ee)";
  return "normal";
}

function secretModeNote(secret) {
  const s = String(secret || "").toLowerCase();
  if (s.startsWith("dd")) return "پروکسی MTProto — حالت fake-TLS";
  if (s.startsWith("ee")) return "پروکسی MTProto — secure با دامنه";
  return "پروکسی MTProto تلگرام";
}
