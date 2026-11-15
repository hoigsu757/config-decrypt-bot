import express from "express";
import { sendMessage, editMessage, pinMessage, downloadFile, tgApi } from "./telegram/api.js";
import { openBytes } from "./decrypt/open.js";
import { formatMessages } from "./decrypt/format.js";

const TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const PORT = Number(process.env.PORT || 3000);
const PUBLIC_URL = (process.env.PUBLIC_URL || process.env.RAILWAY_PUBLIC_DOMAIN || "").replace(/\/$/, "");
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || "";
const USE_POLLING = process.env.USE_POLLING === "1" || process.env.USE_POLLING === "true";

/** chatId -> password */
const pendingPass = new Map();
/** chatId -> pinned welcome message_id */
const pinnedMsg = new Map();

const WELCOME = [
  "👋 خوش اومدی",
  "",
  "کانال: @Meowhub2",
  "",
  "فایل یا لینک کانفیگ رو بفرست تا باز بشه.",
  "",
  "<b>فرمت‌هایی که باز می‌کنم:</b>",
  "• NPVS / NPVT",
  "• HTTP Injector (.ehi)",
  "• HTTP Custom (.hc)",
  "• NetMod (.nm)",
  "• SlipNet",
  "• V2Box",
  "• OpenVPN / AmneziaWG",
  "• ArgoVPN / Rocket Tunnel",
  "• لینک vless / trojan / ss",
  "",
  "فایل رمزدار: <code>/pass رمز</code>",
].join("\n");

const START_KEYBOARD = {
  keyboard: [[{ text: "/start" }]],
  resize_keyboard: true,
  is_persistent: true,
};

if (!TOKEN) {
  console.error("TELEGRAM_BOT_TOKEN is required");
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: "25mb" }));

app.get("/", (_req, res) => {
  res.json({
    ok: true,
    service: "config-decrypt-bot",
    platform: "railway",
    version: "2.1",
    pantegnos: true,
  });
});

app.post("/webhook", async (req, res) => {
  if (WEBHOOK_SECRET) {
    const secret = req.get("X-Telegram-Bot-Api-Secret-Token");
    if (secret !== WEBHOOK_SECRET) return res.status(403).send("forbidden");
  }
  res.json({ ok: true });
  try {
    await handleUpdate(req.body);
  } catch (e) {
    console.error("handleUpdate", e);
  }
});

app.listen(PORT, async () => {
  console.log(`listening on :${PORT}`);
  if (USE_POLLING) {
    console.log("mode: long-polling");
    try {
      await tgApi(TOKEN, "deleteWebhook", { drop_pending_updates: false });
    } catch {}
    startPolling();
  } else if (PUBLIC_URL) {
    const hook = PUBLIC_URL.startsWith("http") ? `${PUBLIC_URL}/webhook` : `https://${PUBLIC_URL}/webhook`;
    try {
      const body = { url: hook };
      if (WEBHOOK_SECRET) body.secret_token = WEBHOOK_SECRET;
      const r = await tgApi(TOKEN, "setWebhook", body);
      console.log("webhook set:", hook, r);
    } catch (e) {
      console.error("setWebhook failed:", e.message);
      console.log("falling back to polling");
      startPolling();
    }
  } else {
    console.log("PUBLIC_URL not set — using long-polling");
    startPolling();
  }
});

async function startPolling() {
  let offset = 0;
  for (;;) {
    try {
      const updates = await tgApi(TOKEN, "getUpdates", {
        offset,
        timeout: 30,
        allowed_updates: ["message"],
      });
      for (const u of updates) {
        offset = u.update_id + 1;
        await handleUpdate(u);
      }
    } catch (e) {
      console.error("poll", e.message);
      await sleep(2000);
    }
  }
}

async function sendWelcome(chatId) {
  const sent = await sendMessage(TOKEN, chatId, WELCOME, {
    reply_markup: START_KEYBOARD,
  });
  if (sent?.message_id) {
    pinnedMsg.set(String(chatId), sent.message_id);
    await pinMessage(TOKEN, chatId, sent.message_id);
  }
  return sent;
}

async function setStatus(chatId, text) {
  const mid = pinnedMsg.get(String(chatId));
  if (!mid) return;
  await editMessage(TOKEN, chatId, mid, text, { reply_markup: START_KEYBOARD });
}

async function restoreWelcome(chatId) {
  const mid = pinnedMsg.get(String(chatId));
  if (!mid) return;
  await editMessage(TOKEN, chatId, mid, WELCOME, { reply_markup: START_KEYBOARD });
}

async function sendResult(chatId, result) {
  const parts = formatMessages(result);
  for (const part of parts) {
    await sendMessage(TOKEN, chatId, part);
  }
}

async function handleUpdate(update) {
  const msg = update.message || update.edited_message;
  if (!msg) return;
  const chatId = msg.chat.id;
  const text = (msg.text || msg.caption || "").trim();

  try {
    if (text === "/start" || text === "/help") {
      await sendWelcome(chatId);
      return;
    }

    if (text.startsWith("/pass")) {
      const pw = text.replace(/^\/pass(@\w+)?\s*/, "").trim();
      if (!pw) {
        await sendMessage(TOKEN, chatId, "مثال:\n<code>/pass mySecret</code>");
        return;
      }
      pendingPass.set(String(chatId), pw);
      await sendMessage(TOKEN, chatId, "✅ رمز ذخیره شد. حالا فایل را بفرست.");
      return;
    }

    const password = pendingPass.get(String(chatId)) || null;

    if (msg.document) {
      await setStatus(chatId, "⏳ در حال باز کردن فایل...");
      try {
        const { name, bytes } = await downloadFile(TOKEN, msg.document.file_id);
        const result = await openBytes(name, bytes, null, password);
        await restoreWelcome(chatId);
        await sendResult(chatId, result);
      } catch (err) {
        await restoreWelcome(chatId);
        await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
      }
      return;
    }

    if (text && !text.startsWith("/")) {
      await setStatus(chatId, "⏳ در حال باز کردن متن...");
      try {
        const bytes = new TextEncoder().encode(text);
        const result = await openBytes("message.txt", bytes, text, password);
        await restoreWelcome(chatId);
        await sendResult(chatId, result);
      } catch (err) {
        await restoreWelcome(chatId);
        await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
      }
    }
  } catch (err) {
    console.error(err);
    try {
      await restoreWelcome(chatId);
      await sendMessage(TOKEN, chatId, `❌ خطا: <code>${esc(String(err.message || err))}</code>`);
    } catch {}
  }
}

function esc(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
