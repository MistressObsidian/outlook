const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store",
};

const WEBHOOK_TOLERANCE_SECONDS = 5 * 60;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: JSON_HEADERS,
  });
}

function decodeBase64(value) {
  const decoded = atob(value);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function encodeBase64(value) {
  let binary = "";

  for (const byte of new Uint8Array(value)) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function timingSafeEqual(left, right) {
  if (left.length !== right.length) return false;

  let difference = 0;

  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }

  return difference === 0;
}

async function verifyResendWebhook({
  payload,
  eventId,
  timestamp,
  signature,
  secret,
}) {
  const timestampNumber = Number(timestamp);
  const now = Math.floor(Date.now() / 1000);

  if (
    !Number.isInteger(timestampNumber) ||
    Math.abs(now - timestampNumber) > WEBHOOK_TOLERANCE_SECONDS
  ) {
    throw new Error("Webhook timestamp is invalid");
  }

  const encodedSecret = secret.startsWith("whsec_")
    ? secret.slice("whsec_".length)
    : secret;
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase64(encodedSecret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"],
  );
  const signedContent = new TextEncoder().encode(
    `${eventId}.${timestampNumber}.${payload}`,
  );
  const expectedSignature = encodeBase64(
    await crypto.subtle.sign("HMAC", key, signedContent),
  );
  const suppliedSignatures = signature.split(" ");
  const verified = suppliedSignatures.some((versionedSignature) => {
    const [version, suppliedSignature] = versionedSignature.split(",");

    return (
      version === "v1" &&
      Boolean(suppliedSignature) &&
      timingSafeEqual(suppliedSignature, expectedSignature)
    );
  });

  if (!verified) {
    throw new Error("Webhook signature does not match");
  }

  return JSON.parse(payload);
}

function maskEmail(value) {
  const email = String(value || "").trim();
  const at = email.lastIndexOf("@");

  if (at < 1) return "unknown";

  return `${email.slice(0, 1)}***@${email.slice(at + 1)}`;
}

function safeClickedLink(value) {
  if (!value) return null;

  try {
    const url = new URL(value);

    // Query strings and fragments can contain tokens, codes, or personal data.
    if (url.protocol === "http:" || url.protocol === "https:") {
      return `${url.origin}${url.pathname}`;
    }

    return `[${url.protocol.replace(":", "")} link]`;
  } catch {
    return "[invalid link]";
  }
}

function buildSummary(event, eventId) {
  const data = event?.data || {};
  const recipient = Array.isArray(data.to) ? data.to[0] : data.to;

  return {
    source: "resend",
    event_id: eventId,
    event_type: String(event?.type || "unknown"),
    event_created_at: event?.created_at || null,
    email_id: data.email_id || null,
    recipient: maskEmail(recipient),
    clicked_link:
      event?.type === "email.clicked"
        ? safeClickedLink(data.click?.link)
        : null,
    received_at: new Date().toISOString(),
  };
}

function telegramMessage(summary) {
  const lines = [
    "Resend email event",
    `Type: ${summary.event_type}`,
    `Recipient: ${summary.recipient}`,
    `Email ID: ${summary.email_id || "unknown"}`,
    `Time: ${summary.event_created_at || summary.received_at}`,
  ];

  if (summary.clicked_link) {
    lines.push(`Clicked: ${summary.clicked_link}`);
  }

  return lines.join("\n");
}

async function sendToTelegram(env, summary) {
  if (!env.TELEGRAM_BOT_TOKEN && !env.TELEGRAM_CHAT_ID) return;

  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) {
    throw new Error("Telegram configuration is incomplete");
  }

  const response = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        chat_id: env.TELEGRAM_CHAT_ID,
        text: telegramMessage(summary),
        disable_web_page_preview: true,
      }),
    },
  );

  if (!response.ok) {
    throw new Error(`Telegram returned HTTP ${response.status}`);
  }
}

async function sendToGoogleAppsScript(env, summary) {
  if (!env.GOOGLE_APPS_SCRIPT_URL) return;

  if (!env.APPS_SCRIPT_SHARED_SECRET) {
    throw new Error("Google Apps Script shared secret is missing");
  }

  const response = await fetch(env.GOOGLE_APPS_SCRIPT_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      ...summary,
      shared_secret: env.APPS_SCRIPT_SHARED_SECRET,
    }),
    redirect: "follow",
  });

  if (!response.ok) {
    throw new Error(`Google Apps Script returned HTTP ${response.status}`);
  }
}

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.RESEND_WEBHOOK_SECRET) {
    console.error("Resend webhook secrets are not configured");
    return jsonResponse(
      { success: false, error: "Webhook is not configured" },
      503,
    );
  }

  const eventId = request.headers.get("svix-id");
  const timestamp = request.headers.get("svix-timestamp");
  const signature = request.headers.get("svix-signature");

  if (!eventId || !timestamp || !signature) {
    return jsonResponse(
      { success: false, error: "Missing webhook signature" },
      400,
    );
  }

  const rawPayload = await request.text();
  let event;

  try {
    event = await verifyResendWebhook({
      payload: rawPayload,
      eventId,
      timestamp,
      signature,
      secret: env.RESEND_WEBHOOK_SECRET,
    });
  } catch {
    return jsonResponse(
      { success: false, error: "Invalid webhook signature" },
      400,
    );
  }

  // A KV binding named WEBHOOK_EVENTS is optional. When present, it prevents
  // most duplicate Telegram/Sheet notifications caused by webhook retries.
  const dedupeKey = `resend:${eventId}`;

  if (env.WEBHOOK_EVENTS) {
    const alreadyProcessed = await env.WEBHOOK_EVENTS.get(dedupeKey);

    if (alreadyProcessed) {
      return jsonResponse({ success: true, duplicate: true });
    }
  }

  const hasTelegram = Boolean(
    env.TELEGRAM_BOT_TOKEN || env.TELEGRAM_CHAT_ID,
  );
  const hasGoogleSheet = Boolean(env.GOOGLE_APPS_SCRIPT_URL);

  if (!hasTelegram && !hasGoogleSheet) {
    console.error("No webhook notification destination is configured");
    return jsonResponse(
      { success: false, error: "No notification destination configured" },
      503,
    );
  }

  const summary = buildSummary(event, eventId);

  try {
    await Promise.all([
      sendToTelegram(env, summary),
      sendToGoogleAppsScript(env, summary),
    ]);

    if (env.WEBHOOK_EVENTS) {
      await env.WEBHOOK_EVENTS.put(dedupeKey, "1", {
        expirationTtl: 7 * 24 * 60 * 60,
      });
    }
  } catch (error) {
    console.error("Resend webhook forwarding failed:", error.message);

    // A non-2xx response tells Resend to retry delivery.
    return jsonResponse(
      { success: false, error: "Webhook forwarding failed" },
      502,
    );
  }

  return jsonResponse({ success: true });
}

export function onRequest() {
  return jsonResponse(
    { success: false, error: "Method not allowed" },
    405,
  );
}
