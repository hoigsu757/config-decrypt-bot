export function tgApi(token, method, body) {
  return fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body || {}),
  }).then(async (r) => {
    const j = await r.json();
    if (!j.ok) throw new Error(`Telegram ${method}: ${j.description || r.status}`);
    return j.result;
  });
}

export async function sendMessage(token, chatId, text, extra = {}) {
  const chunks = splitMessage(text, 4000);
  let last;
  for (const chunk of chunks) {
    last = await tgApi(token, "sendMessage", {
      chat_id: chatId,
      text: chunk,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      ...extra,
    });
  }
  return last;
}

export async function editMessage(token, chatId, messageId, text, extra = {}) {
  try {
    return await tgApi(token, "editMessageText", {
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: "HTML",
      disable_web_page_preview: true,
      ...extra,
    });
  } catch (e) {
    // message not modified / deleted
    return null;
  }
}

export async function pinMessage(token, chatId, messageId) {
  try {
    await tgApi(token, "pinChatMessage", {
      chat_id: chatId,
      message_id: messageId,
      disable_notification: true,
    });
  } catch {}
}

export async function downloadFile(token, fileId, knownSize) {
  // Telegram Bot API cannot download files larger than 20MB via getFile
  if (knownSize && knownSize > 20 * 1024 * 1024) {
    throw new Error(
      "FILE_TOO_BIG: حجم فایل بیشتر از ۲۰ مگابایت است. تلگرام به ربات اجازه دانلود بالای ۲۰MB را نمی‌دهد. فایل کوچک‌تر بفرست یا APK را فشرده/تقسیم کن."
    );
  }
  let file;
  try {
    file = await tgApi(token, "getFile", { file_id: fileId });
  } catch (e) {
    const msg = String(e.message || e);
    if (/too big|file is too big/i.test(msg)) {
      throw new Error(
        "FILE_TOO_BIG: حجم فایل بیشتر از ۲۰ مگابایت است. تلگرام به ربات اجازه دانلود بالای ۲۰MB را نمی‌دهد. یک APK سبک‌تر بفرست."
      );
    }
    throw e;
  }
  if (file.file_size && file.file_size > 20 * 1024 * 1024) {
    throw new Error(
      "FILE_TOO_BIG: حجم فایل بیشتر از ۲۰ مگابایت است. تلگرام به ربات اجازه دانلود بالای ۲۰MB را نمی‌دهد."
    );
  }
  const url = `https://api.telegram.org/file/bot${token}/${file.file_path}`;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`download failed: ${res.status}`);
  const buf = new Uint8Array(await res.arrayBuffer());
  const name = (file.file_path || "file").split("/").pop() || "file";
  return { name, bytes: buf };
}

function splitMessage(text, max) {
  if (text.length <= max) return [text];
  const parts = [];
  let i = 0;
  while (i < text.length) {
    let end = Math.min(i + max, text.length);
    if (end < text.length) {
      const nl = text.lastIndexOf("\n", end);
      if (nl > i + max * 0.5) end = nl + 1;
    }
    parts.push(text.slice(i, end));
    i = end;
  }
  return parts;
}
