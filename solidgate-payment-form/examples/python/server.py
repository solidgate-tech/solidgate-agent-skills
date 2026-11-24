# Solidgate Payment Form — Python example server
#
# Uses the OFFICIAL `solidgate-sdk` package
# for merchantData generation. The SDK computes the correct HMAC-SHA512
# signature over the encoded, encrypted paymentIntent — getting that right
# by hand is easy to break.
#
# KNOWN ISSUE (checked 2026-11-18): all published `solidgate-sdk` releases
# (0.2.1–0.4.0) fail on `import solidgate` because __init__.py imports a
# missing `MerchantData`. Workaround: delete the line
# `from .api_client import MerchantData` from the installed
# solidgate/__init__.py. See ../../frontend-sdk.md § Backend SDKs.
#
# NOTE: there is also an old `solidgate-card-sdk` package on PyPI (last
# released July 2021, v0.1.0). It is abandoned — DO NOT use it. The
# maintained package built from the official repo is `solidgate-sdk`.
#
# Endpoints
#   GET  /                      Test page with embedded payment form
#   POST /api/payment-intent    Generate merchantData (signed + encrypted)
#   POST /webhook               Receive and verify webhook notifications
#
# Billing v2 (Subscriptions 2.0 / Invoicing) — optional, see ../../billing-v2.md
#   POST /api/billing-v2/customers  Create a Billing customer (API v2)
#   POST /api/billing-v2/checkout   merchantData with a `checkout` object
#   POST /api/billing-v2/invoice    merchantData that pays an existing invoice
#   POST /webhook/billing           Receive and verify Billing v2 events
#
# Setup (one-time)
#   1. Get keys from https://hub.solidgate.com/  (Settings → API Keys)
#   2. Export env vars:
#        export SOLIDGATE_PUBLIC_KEY="api_pk_..."
#        export SOLIDGATE_SECRET_KEY="api_sk_..."
#        export SOLIDGATE_WEBHOOK_PUBLIC_KEY="wh_pk_..."
#        export SOLIDGATE_WEBHOOK_SECRET_KEY="wh_sk_..."
#      Billing v2 only (API v2 key + Billing webhook endpoint secret):
#        export SOLIDGATE_API_V2_SECRET="asec_..."
#        export SOLIDGATE_BILLING_WEBHOOK_SECRET="wsec_..."
#        export SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS="wsec_..."   # optional, during rotation
#        export SOLIDGATE_PRO_MONTHLY_PRICE_ID="<recurring price id>"
#        export SOLIDGATE_ONE_TIME_PRICE_ID="<one-time price id>"
#        export SOLIDGATE_CHANNEL_ID="chn_..."            # only for multi-channel API v2 keys
#        export SOLIDGATE_DEMO_CUSTOMER_ID="cust_..."     # demo stand-in for your session lookup
#   3. Install dependencies:
#        pip install flask solidgate-sdk   (then apply the KNOWN ISSUE fix above)
#
# Run
#   python server.py
#
# Then open http://localhost:3000 — fill the form, use test card
# 4067429974719265 (any future expiry, any CVV).

import base64
import hashlib
import hmac
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

from flask import Flask, request, jsonify, render_template_string
from solidgate import ApiClient

# ============================================================
# Configuration
# ============================================================
PUBLIC_KEY = os.environ.get("SOLIDGATE_PUBLIC_KEY", "")
SECRET_KEY = os.environ.get("SOLIDGATE_SECRET_KEY", "")
WH_PUBLIC_KEY = os.environ.get("SOLIDGATE_WEBHOOK_PUBLIC_KEY", "")
WH_SECRET_KEY = os.environ.get("SOLIDGATE_WEBHOOK_SECRET_KEY", "")
# Billing v2 — API v2 secret is a Bearer token (no request signing), and the
# Billing webhook endpoint has its own single signing secret.
API_V2_SECRET = os.environ.get("SOLIDGATE_API_V2_SECRET", "")
BILLING_WH_SECRET = os.environ.get("SOLIDGATE_BILLING_WEBHOOK_SECRET", "")
BILLING_WH_SECRET_PREVIOUS = os.environ.get("SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS", "")
API_V2_BASE = "https://api.solidgate.com/v2"
CHANNEL_ID = os.environ.get("SOLIDGATE_CHANNEL_ID", "")  # needed only for multi-channel API v2 keys

# Plans live on the server. The browser sends a plan key; price, mode and trial
# are never taken from the request (a shopper could otherwise grant themselves
# a free year).
PLANS = {
    "pro_monthly": {
        "mode": "subscription",
        "price_id": os.environ.get("SOLIDGATE_PRO_MONTHLY_PRICE_ID"),
        "description": "Pro plan (monthly)",
        "trial": {"type": "free", "period": {"value": 7, "unit": "day"}},
    },
    "one_time": {
        "mode": "invoice",
        "price_id": os.environ.get("SOLIDGATE_ONE_TIME_PRICE_ID"),
        "description": "One-time purchase",
    },
}


def current_user(req):
    """DEMO ONLY: replace with your session lookup. Must return the logged-in user,
    including the Billing customer id ("cust_…") you stored when you created the
    customer via POST /api/billing-v2/customers. Never take it from the browser."""
    billing_customer_id = os.environ.get("SOLIDGATE_DEMO_CUSTOMER_ID")
    return {"id": "demo-user", "billing_customer_id": billing_customer_id} if billing_customer_id else None


def session_user_id(req):
    """DEMO ONLY: the logged-in user's id from your session."""
    return "demo-user"


# DEMO ONLY: persist merchant_reference -> user/plan in your DB. Webhooks are
# matched back to the purchase through it (see billing-v2.md § Events).
pending_checkouts = {}

PORT = 3000

if not PUBLIC_KEY or not SECRET_KEY:
    print("SOLIDGATE_PUBLIC_KEY and SOLIDGATE_SECRET_KEY must be set.")
    print('  export SOLIDGATE_PUBLIC_KEY="api_pk_..."')
    print('  export SOLIDGATE_SECRET_KEY="api_sk_..."')
    sys.exit(1)

# One ApiClient instance — reuse it.
# The SDK's __init__ is ApiClient(merchant_id, private_key): pass the public
# key, then the secret key. There are no `public_key=` / `secret_key=` kwargs.
client = ApiClient(PUBLIC_KEY, SECRET_KEY)


def merchant_data_to_dict(md) -> dict:
    """Serialize a `FormInitDTO` into the camelCase shape the
    frontend SDK expects. The SDK exposes `payment_intent` (snake_case)
    and has no `.to_dict()` method — convert manually."""
    return {
        "merchant": md.merchant,
        "signature": md.signature,
        "paymentIntent": md.payment_intent,  # rename: payment_intent → paymentIntent
    }


app = Flask(__name__)


# ============================================================
# Webhook signature — no SDK helper exists, so verify manually.
# Formula:  base64(hex(HMAC-SHA512(wh_secret, wh_public + raw_body + wh_public)))
# ============================================================
def verify_webhook_signature(raw_body: str, received_signature: str) -> bool:
    data = WH_PUBLIC_KEY + raw_body + WH_PUBLIC_KEY
    hmac_hex = hmac.new(
        WH_SECRET_KEY.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()
    expected = base64.b64encode(hmac_hex.encode("utf-8")).decode("utf-8")
    return hmac.compare_digest(expected, received_signature)


# ============================================================
# Billing v2 webhook signature — different scheme from the one above.
# Formula:  base64(HMAC-SHA256(endpoint_secret, raw_body))   (no hex step)
# ============================================================
def verify_billing_webhook_signature(raw_body: bytes, received_signatures: list) -> bool:
    # During secret rotation Solidgate sends TWO `signature` headers (new secret
    # first); accept the event if ANY of them matches the current or previous secret.
    received = [s.encode("utf-8", "replace") for s in received_signatures]
    for secret in (BILLING_WH_SECRET, BILLING_WH_SECRET_PREVIOUS):
        if not secret:
            continue
        expected = base64.b64encode(
            hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).digest()
        )
        # Compare bytes (not str) so a non-ASCII header can't raise TypeError.
        for candidate in received:
            if hmac.compare_digest(expected, candidate):
                return True
    return False


def call_api_v2(path: str, payload: dict, headers: dict = None):
    """Calls API v2. Returns (status, body_dict); never raises on a non-JSON error
    page. Network errors (urllib.error.URLError) propagate to the caller."""
    req = urllib.request.Request(
        f"{API_V2_BASE}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {API_V2_SECRET}",
            "Content-Type": "application/json",
            **(headers or {}),
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    text = raw.decode("utf-8", "replace")
    try:
        body = json.loads(text)
    except ValueError:
        body = {"error": text[:500]}
    return status, body


# ============================================================
# HTML test page
# ============================================================
INDEX_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Solidgate Payment Form Test</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
    h1 { font-size: 24px; }
    label { display: block; margin: 8px 0 4px; font-weight: 500; }
    input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { margin-top: 16px; padding: 10px 24px; background: #0066FF; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
    #payment-form { margin-top: 24px; min-height: 300px; }
    #status { margin-top: 16px; padding: 12px; border-radius: 4px; display: none; }
    .success { background: #d4edda; color: #155724; }
    .error   { background: #f8d7da; color: #721c24; }
    .info    { background: #d1ecf1; color: #0c5460; }
  </style>
</head>
<body>
  <h1>Solidgate Payment Form Test</h1>
  <form id="config-form">
    <label>Amount (cents): <input id="amount" value="1020" type="number"></label>
    <label>Currency: <input id="currency" value="USD"></label>
    <label>Description: <input id="description" value="Test payment"></label>
    <button type="submit">Initialize Payment Form</button>
  </form>
  <div id="status"></div>
  <div id="payment-form"></div>

  <script src="https://cdn.solidgate.com/js/solid-form.js"></script>
  <script>
    const statusEl = document.getElementById("status");
    function showStatus(msg, type) {
      statusEl.textContent = msg;
      statusEl.className = type;
      statusEl.style.display = "block";
    }

    document.getElementById("config-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      showStatus("Initializing...", "info");
      const orderId = "order-" + crypto.randomUUID();
      try {
        const resp = await fetch("/api/payment-intent", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            amount: parseInt(document.getElementById("amount").value, 10),
            currency: document.getElementById("currency").value,
            order_id: orderId,
            order_description: document.getElementById("description").value,
          }),
        });
        if (!resp.ok) {
          showStatus("Error: " + (await resp.json()).error, "error");
          return;
        }
        const merchantData = await resp.json();
        document.getElementById("payment-form").innerHTML = "";
        const form = PaymentFormSdk.init({
          merchantData,
          iframeParams: { containerId: "payment-form" },
        });
        form.on("mounted", () => showStatus("Form loaded. Test card: 4067429974719265", "info"));
        form.on("success", () => showStatus("Payment successful! Order: " + orderId, "success"));
        form.on("fail", (ev) => showStatus("Failed: " + ((ev.data ?? ev).message || "Declined"), "error"));
        form.on("error", (ev) => showStatus("Error: " + ((ev.data ?? ev).value?.message || "Unknown"), "error"));
        form.on("verify", () => showStatus("3DS verification...", "info"));
      } catch (err) {
        showStatus("Network error: " + err.message, "error");
      }
    });
  </script>
</body>
</html>
"""


# ============================================================
# Endpoints
# ============================================================


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/payment-intent", methods=["POST"])
def payment_intent():
    """Generate merchantData using the official SDK.

    `client.form_merchant_data(intent)` returns a `FormInitDTO`
    instance with attributes `payment_intent` (snake_case), `merchant`,
    and `signature`. We rebuild the dict here to send the frontend the
    `paymentIntent` (camelCase) field name `PaymentFormSdk.init` expects.
    """
    data = request.get_json(silent=True) or {}
    if not data.get("amount") or not data.get("currency") or not data.get("order_id"):
        return jsonify({"error": "amount, currency, and order_id are required"}), 400

    intent = {
        "amount": int(data["amount"]),
        "currency": data["currency"],
        "order_id": data["order_id"],
        "order_description": data.get("order_description", "Payment"),
        "platform": "WEB",
    }
    for field in ("customer_email", "product_id", "payment_type", "ip_address"):
        if data.get(field):
            intent[field] = data[field]

    merchant_data = merchant_data_to_dict(client.form_merchant_data(intent))
    print(f"[DEBUG] Generated merchantData for order_id={data['order_id']}")
    return jsonify(merchant_data)


@app.route("/webhook", methods=["POST"])
def webhook():
    raw_body = request.get_data(as_text=True)
    signature = request.headers.get("signature", "")
    event_type = request.headers.get("solidgate-event-type", "")
    event_id = request.headers.get("solidgate-event-id", "")

    if not signature:
        return "Missing signature header", 400
    if not verify_webhook_signature(raw_body, signature):
        print("[ERROR] Invalid webhook signature")
        return "Invalid signature", 400

    event = json.loads(raw_body)
    print(f"[DEBUG] Webhook [{event_type}] ({event_id})")

    # Decline info lives at top-level event["error"] (sibling of order/transactions),
    # NOT inside event["order"].
    if event_type == "card_gate.order.updated":
        order = event.get("order", {})
        status = order.get("status")
        order_id = order.get("order_id")

        if status == "settle_ok":
            print(f"Order {order_id}: payment captured — fulfill the order")
        elif status == "auth_failed":
            err = event.get("error", {})
            user_msg = (
                err.get("recommended_message_for_user")
                or (err.get("messages") or ["unknown"])[0]
            )
            print(
                f"Order {order_id}: payment failed — code={err.get('code')} {user_msg}"
            )

    if event_type == "subscription.updated.v2":
        sub = event.get("subscription", {})
        print(f"Subscription {sub.get('id')}: status = {sub.get('status')}")

    return "OK", 200


# ============================================================
# Billing v2 (Subscriptions 2.0 / Invoicing)
# ============================================================


@app.route("/api/billing-v2/customers", methods=["POST"])
def billing_create_customer():
    """Create a Billing customer once per end user; store the returned id
    ("cust_…") — every checkout references it as checkout.customer_id."""
    if not API_V2_SECRET:
        return jsonify({"error": "SOLIDGATE_API_V2_SECRET is not set"}), 500
    # In production, create the customer for the logged-in user (signup) and
    # store the returned id on that user — don't expose this route publicly.
    data = request.get_json(silent=True) or {}
    if not data.get("email"):
        return jsonify({"error": "email is required"}), 400

    # merchant_reference is derived server-side; any client-sent value is ignored.
    merchant_reference = "user-" + session_user_id(request)
    # address.country is ISO 3166-1 alpha-3 (e.g. "USA"); tax is calculated from it.
    body = {k: data[k] for k in ("email", "first_name", "last_name", "address") if data.get(k)}
    body["merchant_reference"] = merchant_reference
    # Safe retries: the same key within 24h returns the first result.
    headers = {"Idempotency-Key": f"customer-{merchant_reference}"}

    try:
        status, resp_body = call_api_v2("/customers/create", body, headers)
    except urllib.error.URLError as e:
        print(f"[ERROR] Billing API unreachable: {e.reason}")
        return jsonify({"error": "Billing API unreachable"}), 502
    return jsonify(resp_body), status  # { "id": "cust_…", ... } or { code, message, context }


@app.route("/api/billing-v2/checkout", methods=["POST"])
def billing_checkout():
    """merchantData for a Billing v2 checkout. Body: { plan, quantity?, coupon_code? }.
    No amount/currency/product_id/customer_account_id — Billing prices the cart."""
    user = current_user(request)
    if not user:
        return jsonify({"error": "not logged in / no Billing customer"}), 401
    data = request.get_json(silent=True) or {}
    plan_key = data.get("plan")
    plan = PLANS.get(plan_key) if isinstance(plan_key, str) else None
    if not plan or not plan["price_id"]:
        return jsonify({"error": "unknown plan"}), 400

    try:
        requested_quantity = int(data.get("quantity") or 1)
    except (TypeError, ValueError):
        requested_quantity = 1
    quantity = min(max(requested_quantity, 1), 10) if plan["mode"] == "invoice" else 1
    # Unique per purchase within the channel; letters, digits, "_" and "-" only.
    merchant_reference = f"{plan['mode']}-{uuid.uuid4()}"
    checkout = {
        "mode": plan["mode"],
        "customer_id": user["billing_customer_id"],
        "merchant_reference": merchant_reference,
        "line_items": [{"product_price_id": plan["price_id"], "quantity": quantity}],
    }
    if data.get("coupon_code"):
        checkout["discounts"] = [{"coupon_code": str(data["coupon_code"])}]
    if plan["mode"] == "subscription" and plan.get("trial"):
        checkout["subscription_data"] = {"trial": plan["trial"]}

    intent = {
        "order_id": f"ord-{uuid.uuid4()}",
        "order_description": plan["description"],
        "platform": "WEB",
        "checkout": checkout,
    }
    if request.remote_addr:
        # Behind a proxy/load balancer this is the proxy's address — use the client IP
        # from your trusted proxy header instead.
        intent["ip_address"] = request.remote_addr

    pending_checkouts[merchant_reference] = {"user_id": user["id"], "plan": plan_key}

    # Same SDK call as one-time payments — signed with the API v1 keys.
    merchant_data = merchant_data_to_dict(client.form_merchant_data(intent))
    print(f"[DEBUG] Billing v2 checkout: plan={plan_key} merchant_reference={merchant_reference}")
    return jsonify(merchant_data)


@app.route("/api/billing-v2/invoice", methods=["POST"])
def billing_invoice():
    """merchantData that collects payment for an invoice already issued via
    API v2. Body: { invoice_id }. Response: { merchantData, amountDue, currency } —
    show the amount yourself: invoice_id intents emit no invoicePreview."""
    user = current_user(request)
    if not user:
        return jsonify({"error": "not logged in / no Billing customer"}), 401
    data = request.get_json(silent=True) or {}
    invoice_id = data.get("invoice_id")
    if not invoice_id:
        return jsonify({"error": "invoice_id is required"}), 400

    if not API_V2_SECRET:
        return jsonify({"error": "SOLIDGATE_API_V2_SECRET is not set"}), 500

    # The invoice's customer, email and address end up in the form, so only the
    # invoice's own customer may open it.
    lookup = {"id": str(invoice_id)}
    if CHANNEL_ID:
        lookup["channel_id"] = CHANNEL_ID
    try:
        status, body = call_api_v2("/invoices/get", lookup)
    except urllib.error.URLError as e:
        print(f"[ERROR] Billing API unreachable: {e.reason}")
        return jsonify({"error": "Billing API unreachable"}), 502
    if status == 404:
        return jsonify({"error": "invoice not found"}), 404
    if status != 200:
        print(f"[ERROR] Billing API /invoices/get returned HTTP {status}")
        return jsonify({"error": "Billing API error"}), 502
    invoice = body.get("invoice", body)
    owner = (invoice.get("customer") or {}).get("id") or invoice.get("customer_id")
    if owner != user["billing_customer_id"]:
        return jsonify({"error": "invoice not found"}), 404
    if invoice.get("status") not in ("OPEN", "DUNNING", "UNPAID"):
        return jsonify({"error": f"invoice is {invoice.get('status')}, not payable"}), 409

    intent = {
        "order_id": f"ord-{uuid.uuid4()}",
        "order_description": f"Invoice {invoice['id']}",
        "platform": "WEB",
        "invoice_id": invoice["id"],  # never combine with checkout
    }
    if request.remote_addr:
        # Behind a proxy/load balancer this is the proxy's address — use the client IP
        # from your trusted proxy header instead.
        intent["ip_address"] = request.remote_addr

    return jsonify({
        "merchantData": merchant_data_to_dict(client.form_merchant_data(intent)),
        "amountDue": invoice.get("amount_due"),  # minor units
        "currency": invoice.get("currency"),
    })


# Billing v2 events: { event_id, event_type, occurred_at, data }.
# Deliveries can repeat and arrive out of order: deduplicate on event_id, and
# mark an event processed only AFTER the handler succeeded — otherwise a failed
# handler loses the event for good. Non-2xx makes Solidgate redeliver.
processed_billing_events = set()  # use your DB in production (keep >= 1 week)


subscription_users = {}  # DEMO ONLY: subscription id -> user id; use your DB in production


def handle_billing_event(event: dict) -> None:
    data = event.get("data") or {}
    sub = data.get("subscription") or {}  # subscription events: id, status, merchant_reference, customer_id, next_billing_at, cancellation_info.reason, latest_invoice_id, trial_info
    invoice = data.get("invoice") or {}  # invoice events nest the payload: data.invoice / data.invoice_payment
    event_type = event.get("event_type")
    if event_type in ("SUBSCRIPTION_ACTIVATED", "SUBSCRIPTION_TRIAL_ACTIVATED"):
        purchase = pending_checkouts.get(sub.get("merchant_reference"))
        if purchase:
            subscription_users[sub.get("id")] = purchase["user_id"]
            trial = " (trial)" if event_type == "SUBSCRIPTION_TRIAL_ACTIVATED" else ""
            print(f"Grant access{trial} to user {purchase['user_id']} (subscription {sub.get('id')})")
        else:
            print(f"Subscription {sub.get('id')}: unknown merchant_reference, ignoring")
    elif event_type == "SUBSCRIPTION_RENEWED":
        print(f"Extend access for user {subscription_users.get(sub.get('id'))}")
    elif event_type in ("SUBSCRIPTION_UNPAID", "SUBSCRIPTION_EXPIRED"):
        print(f"Revoke access for user {subscription_users.get(sub.get('id'))}")
    elif event_type == "SUBSCRIPTION_CANCELLED":
        print(f"Revoke access for user {subscription_users.get(sub.get('id'))}")
        print(f"Cancellation reason: {(sub.get('cancellation_info') or {}).get('reason')}")
    elif event_type == "INVOICE_PAID":
        if invoice.get("subscription_id"):
            # billing_reason casing differs across docs — compare case-insensitively.
            reason = str(invoice.get("billing_reason") or "").upper()
            # Access is granted on SUBSCRIPTION_ACTIVATED / _TRIAL_ACTIVATED; only renewals matter here.
            if reason == "SUBSCRIPTION_CYCLE":
                print(f"Extend access for user {subscription_users.get(invoice['subscription_id'])}")
        else:
            # One-time invoice (checkout mode "invoice" or invoice_id): match by
            # merchant_reference or invoice id, then fulfil.
            purchase = pending_checkouts.get(invoice.get("merchant_reference")) or {}
            print(
                f"Invoice {invoice.get('id')} paid (ref={invoice.get('merchant_reference')}, "
                f"user={purchase.get('user_id', '?')}) — fulfil"
            )
        # Entitlements come from what was paid, not from what the page asked for:
        # updateCheckout runs in the browser. Check invoice.line_items[].product_price_id.
    elif event_type == "INVOICE_PAYMENT_FAILED":
        payment_id = (data.get("invoice_payment") or {}).get("payment_id")
        print(f"Payment {payment_id} failed — ask the customer to update the payment method")
    elif event_type == "INVOICE_UNPAID":
        if invoice.get("subscription_id"):
            print("Subscription invoice unpaid (SUBSCRIPTION_UNPAID revokes access)")
        else:
            print(f"Mark invoice {invoice.get('id')} unpaid")


@app.route("/webhook/billing", methods=["POST"])
def billing_webhook():
    if not BILLING_WH_SECRET:
        return "Billing webhook secret not set", 500
    raw_body = request.get_data()  # raw bytes — never re-serialize
    # During secret rotation there are two `signature` headers (new secret first).
    signatures = [
        part.strip()
        for value in request.headers.getlist("signature")
        for part in value.split(",")
        if part.strip()
    ]
    if not signatures:
        return "Missing signature header", 400
    if not verify_billing_webhook_signature(raw_body, signatures):
        print("[ERROR] Invalid Billing webhook signature")
        return "Invalid signature", 400

    try:
        event = json.loads(raw_body)
    except ValueError:
        return "Invalid JSON", 400
    if event.get("event_id") in processed_billing_events:
        return "OK", 200

    # Kept synchronous for the demo. In production, durably enqueue the event here,
    # return 200, and let the worker apply the same "mark after success" rule.
    try:
        print(f"[DEBUG] Billing event [{event.get('event_type')}] ({event.get('event_id')})")
        handle_billing_event(event)
        processed_billing_events.add(event.get("event_id"))
        return "OK", 200
    except Exception as e:  # noqa: BLE001 — any failure must trigger redelivery
        print(f"[ERROR] Billing event handler failed: {e}")
        return "Retry later", 500


if __name__ == "__main__":
    print(f"Server running on http://localhost:{PORT}")
    app.run(port=PORT)
