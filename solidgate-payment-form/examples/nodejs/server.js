// Solidgate Payment Form — Node.js example server
//
// Uses the OFFICIAL @solidgate/node-sdk for merchantData generation.
// The SDK computes the correct HMAC-SHA512 signature over the encoded,
// encrypted paymentIntent — getting that right by hand is easy to break.
//
// Endpoints
//   GET  /                     Test page with embedded payment form
//   POST /api/payment-intent   Generate merchantData (signed + encrypted)
//   POST /webhook              Receive and verify webhook notifications
//
// Billing v2 (Subscriptions 2.0 / Invoicing) — optional, see ../../billing-v2.md
//   POST /api/billing-v2/customers  Create a Billing customer (API v2)
//   POST /api/billing-v2/checkout   merchantData with a `checkout` object
//   POST /api/billing-v2/invoice    merchantData that pays an existing invoice
//   POST /webhook/billing           Receive and verify Billing v2 events
//
// Setup (one-time)
//   1. Get keys from https://hub.solidgate.com/  (Settings → API Keys)
//   2. Export env vars:
//        export SOLIDGATE_PUBLIC_KEY="api_pk_..."
//        export SOLIDGATE_SECRET_KEY="api_sk_..."
//        export SOLIDGATE_WEBHOOK_PUBLIC_KEY="wh_pk_..."
//        export SOLIDGATE_WEBHOOK_SECRET_KEY="wh_sk_..."
//      Billing v2 only (API v2 key + Billing webhook endpoint secret):
//        export SOLIDGATE_API_V2_SECRET="asec_..."
//        export SOLIDGATE_BILLING_WEBHOOK_SECRET="wsec_..."
//        export SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS="wsec_..."   # optional, during rotation
//        export SOLIDGATE_PRO_MONTHLY_PRICE_ID="<recurring price id>"
//        export SOLIDGATE_ONE_TIME_PRICE_ID="<one-time price id>"
//        export SOLIDGATE_CHANNEL_ID="chn_..."            # only for multi-channel API v2 keys
//        export SOLIDGATE_DEMO_CUSTOMER_ID="cust_..."     # demo stand-in for your session lookup
//   3. Install dependencies (Node.js 18+ for built-in fetch):
//        npm install express @solidgate/node-sdk
//
// Run
//   node server.js
//
// Then open http://localhost:3000 — fill the form, use test card
// 4067429974719265 (any future expiry, any CVV).

const express = require("express");
const crypto = require("crypto");
const path = require("path");
const solidGate = require("@solidgate/node-sdk");

// ============================================================
// Configuration
// ============================================================
const PUBLIC_KEY = process.env.SOLIDGATE_PUBLIC_KEY || "";
const SECRET_KEY = process.env.SOLIDGATE_SECRET_KEY || "";
const WH_PUBLIC_KEY = process.env.SOLIDGATE_WEBHOOK_PUBLIC_KEY || "";
const WH_SECRET_KEY = process.env.SOLIDGATE_WEBHOOK_SECRET_KEY || "";
// Billing v2 — API v2 secret is a Bearer token (no request signing), and the
// Billing webhook endpoint has its own single signing secret.
const API_V2_SECRET = process.env.SOLIDGATE_API_V2_SECRET || "";
const BILLING_WH_SECRET = process.env.SOLIDGATE_BILLING_WEBHOOK_SECRET || "";
const BILLING_WH_SECRET_PREVIOUS = process.env.SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS || "";
const API_V2_BASE = "https://api.solidgate.com/v2";
const CHANNEL_ID = process.env.SOLIDGATE_CHANNEL_ID || ""; // needed only for multi-channel API v2 keys

// Plans live on the server. The browser sends a plan key; price, mode and trial
// are never taken from the request (a shopper could otherwise grant themselves
// a free year).
const PLANS = {
  pro_monthly: {
    mode: "subscription",
    priceId: process.env.SOLIDGATE_PRO_MONTHLY_PRICE_ID,
    description: "Pro plan (monthly)",
    trial: { type: "free", period: { value: 7, unit: "day" } },
  },
  one_time: {
    mode: "invoice",
    priceId: process.env.SOLIDGATE_ONE_TIME_PRICE_ID,
    description: "One-time purchase",
  },
};

// DEMO ONLY: replace with your session lookup. Must return the logged-in user,
// including the Billing customer id ("cust_…") you stored when you created the
// customer via POST /api/billing-v2/customers. Never take it from the browser.
function currentUser(req) {
  const billingCustomerId = process.env.SOLIDGATE_DEMO_CUSTOMER_ID;
  return billingCustomerId ? { id: "demo-user", billingCustomerId } : null;
}

// DEMO ONLY: the logged-in user's id from your session.
function sessionUserId(req) {
  return "demo-user";
}

// DEMO ONLY: persist merchant_reference → user/plan in your DB. Webhooks are
// matched back to the purchase through it (see billing-v2.md § Events).
const pendingCheckouts = new Map();

// DEMO ONLY: persist subscription id → user id in your DB (use your DB).
const subscriptionUsers = new Map();

const PORT = 3000;

if (!PUBLIC_KEY || !SECRET_KEY) {
  console.error("SOLIDGATE_PUBLIC_KEY and SOLIDGATE_SECRET_KEY must be set.");
  console.error('  export SOLIDGATE_PUBLIC_KEY="api_pk_..."');
  console.error('  export SOLIDGATE_SECRET_KEY="api_sk_..."');
  process.exit(1);
}

// One Api instance — reuse it. Constructor is (publicKey, secretKey).
const api = new solidGate.Api(PUBLIC_KEY, SECRET_KEY);

const app = express();
app.disable("x-powered-by");
// Webhook needs the raw body for HMAC verification — register before json().
// "/webhook" also matches "/webhook/billing", so both get the raw body.
app.use("/webhook", express.raw({ type: "*/*" }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ============================================================
// Webhook signature — no SDK helper exists, so verify manually.
// Formula:  base64(hex(HMAC-SHA512(wh_secret, wh_public + raw_body + wh_public)))
// ============================================================
function verifyWebhookSignature(rawBody, receivedSignature) {
  const data = WH_PUBLIC_KEY + rawBody + WH_PUBLIC_KEY;
  const hmacHex = crypto
    .createHmac("sha512", WH_SECRET_KEY)
    .update(data)
    .digest("hex");
  const expected = Buffer.from(hmacHex).toString("base64");
  // Constant-time compare — guards against signature-leak timing attacks.
  if (expected.length !== receivedSignature.length) return false;
  return crypto.timingSafeEqual(
    Buffer.from(expected),
    Buffer.from(receivedSignature),
  );
}

// ============================================================
// Billing v2 webhook signature — different scheme from the one above.
// Formula:  base64(HMAC-SHA256(endpoint_secret, raw_body))   (no hex step)
// ============================================================
// During secret rotation Solidgate sends TWO `signature` headers (new secret
// first), so `receivedSignatures` is an array; accept the event if ANY of them
// matches the current secret or the optional previous one.
function verifyBillingWebhookSignature(rawBodyBuf, receivedSignatures) {
  const received = receivedSignatures.map((s) => Buffer.from(s, "utf-8"));
  return [BILLING_WH_SECRET, BILLING_WH_SECRET_PREVIOUS].filter(Boolean).some((secret) => {
    const expected = Buffer.from(
      crypto.createHmac("sha256", secret).update(rawBodyBuf).digest("base64"),
      "utf-8",
    );
    // Compare byte lengths (not string lengths) so non-ASCII input can't throw.
    return received.some((r) => expected.length === r.length && crypto.timingSafeEqual(expected, r));
  });
}

// Calls API v2. Returns { status, body }; never throws on a non-JSON error page.
async function callApiV2(path, payload, headers = {}) {
  const resp = await fetch(`${API_V2_BASE}${path}`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${API_V2_SECRET}`,
      "Content-Type": "application/json",
      ...headers,
    },
    body: JSON.stringify(payload),
  });
  const text = await resp.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { error: text.slice(0, 500) };
  }
  return { status: resp.status, body };
}

// ============================================================
// Endpoints
// ============================================================

// Generate merchantData for the frontend SDK.
// The SDK's formMerchantData(intent) returns a FormInitDTO; .toObject()
// produces { merchant, signature, paymentIntent } ready to send to the browser.
app.post("/api/payment-intent", (req, res) => {
  const { amount, currency, order_id, order_description } = req.body;

  if (!amount || !currency || !order_id) {
    return res
      .status(400)
      .json({ error: "amount, currency, and order_id are required" });
  }

  const paymentIntent = {
    amount: parseInt(amount, 10),
    currency,
    order_id,
    order_description: order_description || "Payment",
    platform: "WEB",
  };

  // Carry through optional fields if the caller provided them.
  if (req.body.customer_email)
    paymentIntent.customer_email = req.body.customer_email;
  if (req.body.product_id) paymentIntent.product_id = req.body.product_id;
  if (req.body.payment_type) paymentIntent.payment_type = req.body.payment_type;
  if (req.body.ip_address) paymentIntent.ip_address = req.body.ip_address;

  const merchantData = api.formMerchantData(paymentIntent).toObject();

  console.log("[DEBUG] Generated merchantData for order_id=%s", order_id);
  res.json(merchantData);
});

// Webhook endpoint — verify, then handle.
app.post("/webhook", (req, res) => {
  if (!Buffer.isBuffer(req.body)) return res.status(400).send("Invalid body");
  const rawBody = req.body.toString("utf-8");
  const signature = req.headers["signature"];
  const eventType = req.headers["solidgate-event-type"];
  const eventId = req.headers["solidgate-event-id"];

  if (typeof signature !== "string") return res.status(400).send("Missing signature header");
  if (!verifyWebhookSignature(rawBody, signature)) {
    console.error("Invalid webhook signature");
    return res.status(400).send("Invalid signature");
  }

  const event = JSON.parse(rawBody);
  console.log(`[DEBUG] Webhook [${eventType}] (${eventId})`);

  // Decline info lives at top-level event.error (sibling of order/transactions),
  // NOT inside event.order.
  if (eventType === "card_gate.order.updated") {
    const status = event.order?.status;
    const orderId = event.order?.order_id;

    switch (status) {
      case "settle_ok":
        console.log(`Order ${orderId}: payment captured — fulfill the order`);
        break;
      case "auth_ok":
        console.log(`Order ${orderId}: funds reserved`);
        break;
      case "auth_failed": {
        const code = event.error?.code;
        const userMsg =
          event.error?.recommended_message_for_user ||
          event.error?.messages?.[0] ||
          "";
        console.log(
          `Order ${orderId}: payment failed — code=${code} ${userMsg}`,
        );
        break;
      }
      case "void_ok":
        console.log(`Order ${orderId}: payment voided`);
        break;
      case "refunded":
        // Partial vs full refund: compare event.order.refunded_amount with event.order.amount.
        console.log(
          `Order ${orderId}: refunded ${event.order?.refunded_amount} / ${event.order?.amount}`,
        );
        break;
    }
  }

  if (eventType === "subscription.updated.v2") {
    const sub = event.subscription;
    console.log(`Subscription ${sub?.id}: status = ${sub?.status}`);
  }

  res.status(200).send("OK");
});

// ============================================================
// Billing v2 (Subscriptions 2.0 / Invoicing)
// ============================================================

// Create a Billing customer. Do this once per end user and store the returned
// id ("cust_…") — every checkout references it as checkout.customer_id.
app.post("/api/billing-v2/customers", async (req, res) => {
  if (!API_V2_SECRET) return res.status(500).json({ error: "SOLIDGATE_API_V2_SECRET is not set" });
  // In production, create the customer for the logged-in user (signup) and
  // store the returned id on that user — don't expose this route publicly.
  const { email, first_name, last_name, address } = req.body;
  if (!email) return res.status(400).json({ error: "email is required" });
  // Derived server-side; any merchant_reference sent by the client is ignored.
  const merchant_reference = `user-${sessionUserId(req)}`;

  try {
    const { status, body } = await callApiV2(
      "/customers/create",
      // address.country is ISO 3166-1 alpha-3 (e.g. "USA"); tax is calculated from it.
      { email, first_name, last_name, merchant_reference, address },
      // Safe retries: the same key within 24h returns the first result.
      { "Idempotency-Key": `customer-${merchant_reference}` },
    );
    res.status(status).json(body); // { id: "cust_…", ... } or { code, message, context }
  } catch (err) {
    console.error("Billing API unreachable:", err.message);
    res.status(502).json({ error: "Billing API unreachable" });
  }
});

// merchantData for a Billing v2 checkout. Body: { plan, quantity?, coupon_code? }.
// No amount/currency/product_id/customer_account_id — Billing prices the cart.
app.post("/api/billing-v2/checkout", (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "not logged in / no Billing customer" });
  const plan = PLANS[req.body.plan];
  if (!plan || !plan.priceId) return res.status(400).json({ error: "unknown plan" });

  const quantity = plan.mode === "invoice" ? Math.min(Math.max(parseInt(req.body.quantity, 10) || 1, 1), 10) : 1;
  const merchantReference = `${plan.mode}-${crypto.randomUUID()}`; // unique per purchase; [A-Za-z0-9_-]
  const checkout = {
    mode: plan.mode,
    customer_id: user.billingCustomerId,
    merchant_reference: merchantReference,
    line_items: [{ product_price_id: plan.priceId, quantity }],
  };
  if (req.body.coupon_code) checkout.discounts = [{ coupon_code: String(req.body.coupon_code) }];
  if (plan.mode === "subscription" && plan.trial) checkout.subscription_data = { trial: plan.trial };

  const paymentIntent = {
    order_id: `ord-${crypto.randomUUID()}`,
    order_description: plan.description,
    platform: "WEB",
    checkout,
  };
  // Behind a proxy/load balancer this is the proxy's address — use the client IP
  // from your trusted proxy header instead.
  if (req.ip) paymentIntent.ip_address = req.ip;

  pendingCheckouts.set(merchantReference, { userId: user.id, plan: req.body.plan });

  // Same SDK call as one-time payments — signed with the API v1 keys.
  const merchantData = api.formMerchantData(paymentIntent).toObject();
  console.log("[DEBUG] Billing v2 checkout: plan=%s merchant_reference=%s", req.body.plan, merchantReference);
  res.json(merchantData);
});

// merchantData that collects payment for an invoice already issued via API v2.
// Body: { invoice_id }. Response: { merchantData, amountDue, currency } — show the
// amount yourself: invoice_id intents emit no invoicePreview.
app.post("/api/billing-v2/invoice", async (req, res) => {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: "not logged in / no Billing customer" });
  const { invoice_id } = req.body;
  if (!invoice_id) return res.status(400).json({ error: "invoice_id is required" });
  if (!API_V2_SECRET) return res.status(500).json({ error: "SOLIDGATE_API_V2_SECRET is not set" });

  // The invoice's customer, email and address end up in the form, so only the
  // invoice's own customer may open it.
  let invoice;
  try {
    const { status, body } = await callApiV2("/invoices/get", {
      id: String(invoice_id),
      ...(CHANNEL_ID && { channel_id: CHANNEL_ID }),
    });
    if (status === 404) return res.status(404).json({ error: "invoice not found" });
    if (status !== 200) {
      console.error("Billing API error: /invoices/get returned", status);
      return res.status(502).json({ error: "Billing API error" });
    }
    invoice = body.invoice ?? body;
  } catch (err) {
    console.error("Billing API unreachable:", err.message);
    return res.status(502).json({ error: "Billing API unreachable" });
  }
  const invoiceCustomerId = invoice.customer?.id ?? invoice.customer_id;
  if (invoiceCustomerId !== user.billingCustomerId) return res.status(404).json({ error: "invoice not found" });
  if (!["OPEN", "DUNNING", "UNPAID"].includes(invoice.status)) {
    return res.status(409).json({ error: `invoice is ${invoice.status}, not payable` });
  }

  const paymentIntent = {
    order_id: `ord-${crypto.randomUUID()}`,
    order_description: `Invoice ${invoice.id}`,
    platform: "WEB",
    invoice_id: invoice.id, // never combine with checkout
  };
  // Behind a proxy/load balancer this is the proxy's address — use the client IP
  // from your trusted proxy header instead.
  if (req.ip) paymentIntent.ip_address = req.ip;

  res.json({
    merchantData: api.formMerchantData(paymentIntent).toObject(),
    amountDue: invoice.amount_due, // minor units
    currency: invoice.currency,
  });
});

// Billing v2 events: { event_id, event_type, occurred_at, data }.
// Deliveries can repeat and arrive out of order: deduplicate on event_id, and
// mark an event processed only AFTER the handler succeeded — otherwise a failed
// handler loses the event for good. Non-2xx makes Solidgate redeliver.
const processedBillingEvents = new Set(); // use your DB in production (keep ≥ 1 week)

function handleBillingEvent(event) {
  // Invoice events nest the payload: data.invoice / data.invoice_payment.
  const invoice = event.data?.invoice;
  // Subscription events carry data.subscription: id, status, merchant_reference,
  // customer_id, next_billing_at, cancellation_info.reason, latest_invoice_id, trial_info.
  const sub = event.data?.subscription;
  switch (event.event_type) {
    case "SUBSCRIPTION_ACTIVATED":
    case "SUBSCRIPTION_TRIAL_ACTIVATED": {
      const purchase = pendingCheckouts.get(sub?.merchant_reference);
      if (purchase) {
        subscriptionUsers.set(sub.id, purchase.userId);
        const trial = event.event_type === "SUBSCRIPTION_TRIAL_ACTIVATED" ? " (trial)" : "";
        console.log(`Grant access${trial} to user ${purchase.userId} (subscription ${sub.id})`);
      } else {
        console.log(`Subscription ${sub?.id}: unknown merchant_reference, ignoring`);
      }
      break;
    }
    case "SUBSCRIPTION_RENEWED":
      console.log(`Extend access for user ${subscriptionUsers.get(sub?.id)}`);
      break;
    case "INVOICE_PAID": {
      // billing_reason casing differs across docs — compare case-insensitively.
      const reason = String(invoice?.billing_reason || "").toUpperCase();
      if (invoice?.subscription_id) {
        // Subscription invoice: only renewal cycles matter here — access is granted
        // on SUBSCRIPTION_ACTIVATED / SUBSCRIPTION_TRIAL_ACTIVATED.
        if (reason === "SUBSCRIPTION_CYCLE") {
          console.log(`Extend access for user ${subscriptionUsers.get(invoice.subscription_id)}`);
        }
      } else {
        // One-time invoice (checkout mode "invoice" or invoice_id): match by
        // merchant_reference or invoice id, then fulfil.
        const purchase = pendingCheckouts.get(invoice?.merchant_reference);
        console.log(`Invoice ${invoice?.id} paid (ref=${invoice?.merchant_reference}, user=${purchase?.userId ?? "?"}) — fulfil`);
      }
      // Entitlements come from what was paid, not from what the page asked for:
      // updateCheckout runs in the browser. Check invoice.line_items[].product_price_id.
      break;
    }
    case "INVOICE_PAYMENT_FAILED":
      console.log(`Payment ${event.data?.invoice_payment?.payment_id} failed — ask the customer to update the payment method`);
      break;
    case "INVOICE_UNPAID":
      console.log(
        invoice?.subscription_id
          ? `Invoice ${invoice?.id}: subscription invoice unpaid (SUBSCRIPTION_UNPAID revokes access)`
          : `Mark invoice ${invoice?.id} unpaid`,
      );
      break;
    case "SUBSCRIPTION_UNPAID":
    case "SUBSCRIPTION_EXPIRED":
      console.log(`Revoke access for user ${subscriptionUsers.get(sub?.id)}`);
      break;
    case "SUBSCRIPTION_CANCELLED":
      console.log(`Revoke access for user ${subscriptionUsers.get(sub?.id)}`);
      console.log(`Cancellation reason: ${sub?.cancellation_info?.reason}`);
      break;
  }
}

app.post("/webhook/billing", (req, res) => {
  if (!BILLING_WH_SECRET) return res.status(500).send("Billing webhook secret not set");
  if (!Buffer.isBuffer(req.body)) return res.status(400).send("Invalid body");
  // Two `signature` headers during secret rotation: Node joins them with ",".
  const signatures = String(req.headers["signature"] || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (signatures.length === 0) return res.status(400).send("Missing signature header");
  if (!verifyBillingWebhookSignature(req.body, signatures)) {
    console.error("Invalid Billing webhook signature");
    return res.status(400).send("Invalid signature");
  }

  let event;
  try {
    event = JSON.parse(req.body.toString("utf-8"));
  } catch {
    return res.status(400).send("Invalid JSON");
  }
  if (processedBillingEvents.has(event.event_id)) return res.status(200).send("OK");

  // Kept synchronous for the demo. In production, durably enqueue the event here,
  // return 200, and let the worker apply the same "mark after success" rule.
  try {
    console.log(`[DEBUG] Billing event [${event.event_type}] (${event.event_id})`);
    handleBillingEvent(event);
    processedBillingEvents.add(event.event_id);
    res.status(200).send("OK");
  } catch (err) {
    console.error("Billing event handler failed:", err);
    res.status(500).send("Retry later");
  }
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
