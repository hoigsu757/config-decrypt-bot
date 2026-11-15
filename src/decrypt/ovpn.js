import { emptyResult } from "./format.js";
export function tryOvpn(name, text) {
  if (!/remote\s+\S+/i.test(text)) return null;
  if (!/client|dev tun|proto |-----BEGIN|<auth-user-pass>/i.test(text) && !/\.ovpn$/i.test(name||"")) return null;
  const r = emptyResult("OpenVPN (.ovpn)");
  const remote = text.match(/remote\s+(\S+)\s+(\d+)/i);
  if (remote) { r.server.host = remote[1]; r.server.port = remote[2]; }
  r.server.protocol = "openvpn";
  const block = text.match(/<auth-user-pass>\s*([\s\S]*?)<\/auth-user-pass>/i);
  if (block) {
    const lines = block[1].split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (lines[0]) r.server.user = lines[0];
    if (lines[1]) r.server.password = lines[1];
  }
  const proto = text.match(/^\s*proto\s+(\S+)/im);
  if (proto) r.server.transport = proto[1];
  r.note = "OpenVPN به VLESS تبدیل نمی‌شود.";
  return r;
}
