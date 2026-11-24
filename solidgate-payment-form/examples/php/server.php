<?php
// Solidgate Payment Form — PHP example server
//
// Uses the OFFICIAL solidgate/php-sdk package for merchantData generation.
// The SDK computes the correct HMAC-SHA512 signature over the encoded,
// encrypted paymentIntent — getting that right by hand is easy to break.
//
// Endpoints
//   GET  /                      Test page with embedded payment form
//   POST /api/payment-intent    Generate merchantData (signed + encrypted)
//   POST /webhook               Receive and verify webhook notifications
//
// Billing v2 (Subscriptions 2.0 / Invoicing) — optional, see ../../billing-v2.md
//   POST /api/billing-v2/customers  Create a Billing customer (API v2)
//   POST /api/billing-v2/checkout   merchantData with a `checkout` object
//   POST /api/billing-v2/invoice    merchantData that pays an existing invoice
//   POST /webhook/billing           Receive and verify Billing v2 events
//
// Setup (one-time)
//   1. Get keys from https://hub.solidgate.com/  (Settings → API Keys).
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
//   3. Install dependency (in this directory):
//        composer require solidgate/php-sdk
//
// Run
//   php -S localhost:3000 server.php
//
// Then open http://localhost:3000 — fill the form, use test card
// 4067429974719265 (any future expiry, any CVV).

require __DIR__ . '/vendor/autoload.php';

use SolidGate\API\Api;

// ============================================================
// Configuration
// ============================================================
define('PUBLIC_KEY',     getenv('SOLIDGATE_PUBLIC_KEY') ?: '');
define('SECRET_KEY',     getenv('SOLIDGATE_SECRET_KEY') ?: '');
define('WH_PUBLIC_KEY',  getenv('SOLIDGATE_WEBHOOK_PUBLIC_KEY') ?: '');
define('WH_SECRET_KEY',  getenv('SOLIDGATE_WEBHOOK_SECRET_KEY') ?: '');
// Billing v2 — API v2 secret is a Bearer token (no request signing), and the
// Billing webhook endpoint has its own single signing secret.
define('API_V2_SECRET',     getenv('SOLIDGATE_API_V2_SECRET') ?: '');
define('BILLING_WH_SECRET', getenv('SOLIDGATE_BILLING_WEBHOOK_SECRET') ?: '');
define('BILLING_WH_SECRET_PREVIOUS', getenv('SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS') ?: '');
define('API_V2_BASE',       'https://api.solidgate.com/v2');
define('CHANNEL_ID',        getenv('SOLIDGATE_CHANNEL_ID') ?: ''); // needed only for multi-channel API v2 keys

// Plans live on the server. The browser sends a plan key; price, mode and trial
// are never taken from the request (a shopper could otherwise grant themselves
// a free year).
define('PLANS', [
    'pro_monthly' => [
        'mode'        => 'subscription',
        'price_id'    => getenv('SOLIDGATE_PRO_MONTHLY_PRICE_ID') ?: '',
        'description' => 'Pro plan (monthly)',
        'trial'       => ['type' => 'free', 'period' => ['value' => 7, 'unit' => 'day']],
    ],
    'one_time' => [
        'mode'        => 'invoice',
        'price_id'    => getenv('SOLIDGATE_ONE_TIME_PRICE_ID') ?: '',
        'description' => 'One-time purchase',
    ],
]);

// DEMO ONLY: replace with your session lookup. Must return the logged-in user,
// including the Billing customer id ("cust_…") you stored when you created the
// customer via POST /api/billing-v2/customers. Never take it from the browser.
function currentUser(): ?array {
    $billingCustomerId = getenv('SOLIDGATE_DEMO_CUSTOMER_ID') ?: '';
    return $billingCustomerId !== ''
        ? ['id' => 'demo-user', 'billing_customer_id' => $billingCustomerId]
        : null;
}

// DEMO ONLY: persist merchant_reference -> user/plan in your DB. Webhooks are
// matched back to the purchase through it (see billing-v2.md § Events). The PHP
// built-in server has no shared memory between requests, so this is a stub.
function savePendingCheckout(string $merchantReference, string $userId, string $plan): void {
    error_log("[DEBUG] savePendingCheckout: ref=$merchantReference user=$userId plan=$plan");
}

// DEMO ONLY: look up the purchase saved by savePendingCheckout() — use your DB.
// Returns ['user_id' => ..., 'plan' => ...] or null when the reference is unknown.
function findPendingCheckout(string $merchantReference): ?array {
    error_log("[DEBUG] findPendingCheckout: ref=$merchantReference");
    return null;
}

// DEMO ONLY: remember subscription id -> user in your DB.
function linkSubscription(string $subscriptionId, string $userId): void {
    error_log("[DEBUG] linkSubscription: subscription=$subscriptionId user=$userId");
}

// DEMO ONLY: the user a subscription belongs to — use your DB.
function findSubscriptionUser(string $subscriptionId): string {
    error_log("[DEBUG] findSubscriptionUser: subscription=$subscriptionId");
    return 'unknown-user';
}

// DEMO ONLY: the logged-in user's id from your session.
function sessionUserId(): string {
    return 'demo-user';
}

if (PUBLIC_KEY === '' || SECRET_KEY === '') {
    http_response_code(500);
    echo "SOLIDGATE_PUBLIC_KEY and SOLIDGATE_SECRET_KEY must be set.\n";
    echo "  export SOLIDGATE_PUBLIC_KEY=\"api_pk_...\"\n";
    echo "  export SOLIDGATE_SECRET_KEY=\"api_sk_...\"\n";
    exit;
}

// One Api instance — reuse it.
$api = new Api(PUBLIC_KEY, SECRET_KEY);

// ============================================================
// Webhook signature — no SDK helper exists, so verify manually.
// Formula:  base64(hex(HMAC-SHA512(wh_secret, wh_public + raw_body + wh_public)))
// ============================================================
function verifyWebhookSignature(string $rawBody, string $receivedSignature): bool {
    $data = WH_PUBLIC_KEY . $rawBody . WH_PUBLIC_KEY;
    $hmacHex = hash_hmac('sha512', $data, WH_SECRET_KEY);
    $expected = base64_encode($hmacHex);
    return hash_equals($expected, $receivedSignature);
}

// ============================================================
// Billing v2 webhook signature — different scheme from the one above.
// Formula:  base64(HMAC-SHA256(endpoint_secret, raw_body))   (no hex step)
// ============================================================
//
// During secret rotation Solidgate sends TWO signature headers (new secret
// first); PHP exposes them comma-joined in $_SERVER['HTTP_SIGNATURE']. Accept
// the event if ANY received signature matches the current or previous secret.
function verifyBillingWebhookSignature(string $rawBody, string $signatureHeader): bool {
    $received = array_filter(array_map('trim', explode(',', $signatureHeader)), fn($s) => $s !== '');
    $secrets = [BILLING_WH_SECRET];
    if (BILLING_WH_SECRET_PREVIOUS !== '') {
        $secrets[] = BILLING_WH_SECRET_PREVIOUS;
    }
    foreach ($secrets as $secret) {
        $expected = base64_encode(hash_hmac('sha256', $rawBody, $secret, true));
        foreach ($received as $signature) {
            if (hash_equals($expected, $signature)) {
                return true;
            }
        }
    }
    return false;
}

// Calls API v2. Returns [int $status, array $body]; status 0 means the request
// failed (network). Never throws on a non-JSON error page.
function callApiV2(string $path, array $payload, array $headers = []): array {
    $ch = curl_init(API_V2_BASE . $path);
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload),
        CURLOPT_HTTPHEADER     => array_merge(
            ['Authorization: Bearer ' . API_V2_SECRET, 'Content-Type: application/json'],
            $headers
        ),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 30,
    ]);
    $text   = curl_exec($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    if ($text === false) {
        return [0, ['error' => 'Billing API unreachable']];
    }
    $body = json_decode($text, true);
    if (!is_array($body)) {
        $body = ['error' => substr($text, 0, 500)];
    }
    return [$status, $body];
}

function jsonResponse(int $status, $data): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data);
}

// ============================================================
// Routing
// ============================================================
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Test page
if ($path === '/' && $method === 'GET') {
    header('Content-Type: text/html; charset=utf-8');
    echo <<<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Solidgate Payment Form Test</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 600px; margin: 40px auto; padding: 0 20px; }
    label { display: block; margin: 8px 0 4px; }
    input { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
    button { margin-top: 16px; padding: 10px 24px; background: #0066FF; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
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
        form.on("success", () => showStatus("Payment successful!", "success"));
        form.on("fail",    (ev) => showStatus("Failed: " + ((ev.data ?? ev).message || "Declined"), "error"));
        form.on("error",   (ev) => showStatus("Error: "  + ((ev.data ?? ev).value?.message || "Unknown"), "error"));
      } catch (err) {
        showStatus("Network error: " + err.message, "error");
      }
    });
  </script>
</body>
</html>
HTML;
    exit;
}

// Generate merchantData via the official SDK.
// $api->formMerchantData($intent) returns a FormInitDTO; toArray() gives
// an associative array shaped like { merchant, signature, paymentIntent }.
if ($path === '/api/payment-intent' && $method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);

    if (!$input || empty($input['amount']) || empty($input['currency']) || empty($input['order_id'])) {
        jsonResponse(400, ['error' => 'amount, currency, and order_id are required']);
        exit;
    }

    $intent = [
        'amount'            => (int)$input['amount'],
        'currency'          => $input['currency'],
        'order_id'          => $input['order_id'],
        'order_description' => $input['order_description'] ?? 'Payment',
        'platform'          => 'WEB',
    ];
    foreach (['customer_email', 'product_id', 'payment_type', 'ip_address'] as $field) {
        if (!empty($input[$field])) {
            $intent[$field] = $input[$field];
        }
    }

    $merchantData = $api->formMerchantData($intent)->toArray();
    error_log('[DEBUG] Generated merchantData for order_id=' . $input['order_id']);
    jsonResponse(200, $merchantData);
    exit;
}

// Webhook — verify signature, then handle event.
if ($path === '/webhook' && $method === 'POST') {
    $rawBody   = file_get_contents('php://input');
    $signature = $_SERVER['HTTP_SIGNATURE'] ?? '';
    $eventType = $_SERVER['HTTP_SOLIDGATE_EVENT_TYPE'] ?? '';
    $eventId   = $_SERVER['HTTP_SOLIDGATE_EVENT_ID'] ?? '';

    if ($signature === '') {
        http_response_code(400);
        echo 'Missing signature header';
        exit;
    }
    if (!verifyWebhookSignature($rawBody, $signature)) {
        error_log('[ERROR] Invalid webhook signature');
        http_response_code(400);
        echo 'Invalid signature';
        exit;
    }

    $event = json_decode($rawBody, true);
    error_log("[DEBUG] Webhook [$eventType] ($eventId)");

    // Add business logic here. Decline info lives at top-level $event['error']
    // (sibling of order/transactions), NOT inside $event['order'].

    echo 'OK';
    exit;
}

// ============================================================
// Billing v2 (Subscriptions 2.0 / Invoicing)
// ============================================================

// Create a Billing customer once per end user; store the returned id
// ("cust_…") — every checkout references it as checkout.customer_id.
if ($path === '/api/billing-v2/customers' && $method === 'POST') {
    if (API_V2_SECRET === '') {
        jsonResponse(500, ['error' => 'SOLIDGATE_API_V2_SECRET is not set']);
        exit;
    }
    // In production, create the customer for the logged-in user (signup) and
    // store the returned id on that user — don't expose this route publicly.
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    if (empty($input['email'])) {
        jsonResponse(400, ['error' => 'email is required']);
        exit;
    }
    // address.country is ISO 3166-1 alpha-3 (e.g. "USA"); tax is calculated from it.
    $payload = array_intersect_key($input, array_flip(['email', 'first_name', 'last_name', 'address']));
    // Derived server-side; any merchant_reference sent by the client is ignored.
    $payload['merchant_reference'] = 'user-' . sessionUserId();
    // Safe retries: the same key within 24h returns the first result.
    $headers = ['Idempotency-Key: customer-' . $payload['merchant_reference']];

    [$status, $body] = callApiV2('/customers/create', $payload, $headers);
    if ($status === 0) {
        error_log('[ERROR] Billing API unreachable');
        jsonResponse(502, ['error' => 'Billing API unreachable']);
        exit;
    }
    jsonResponse($status, $body); // { "id": "cust_…", ... } or { code, message, context }
    exit;
}

// merchantData for a Billing v2 checkout. Body: { plan, quantity?, coupon_code? }.
// No amount/currency/product_id/customer_account_id — Billing prices the cart.
if ($path === '/api/billing-v2/checkout' && $method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $user = currentUser();
    if ($user === null) {
        jsonResponse(401, ['error' => 'not logged in / no Billing customer']);
        exit;
    }
    $planKey = (string)($input['plan'] ?? '');
    $plan = PLANS[$planKey] ?? null;
    if ($plan === null || $plan['price_id'] === '') {
        jsonResponse(400, ['error' => 'unknown plan']);
        exit;
    }
    $mode = $plan['mode'];

    $quantity = $mode === 'invoice' ? max(1, min(10, (int)($input['quantity'] ?? 1))) : 1;
    // Unique per purchase within the channel; letters, digits, "_" and "-" only.
    $merchantReference = $mode . '-' . bin2hex(random_bytes(16));
    $checkout = [
        'mode'               => $mode,
        'customer_id'        => $user['billing_customer_id'],
        'merchant_reference' => $merchantReference,
        'line_items'         => [[
            'product_price_id' => $plan['price_id'],
            'quantity'         => $quantity,
        ]],
    ];
    if (!empty($input['coupon_code'])) {
        $checkout['discounts'] = [['coupon_code' => (string)$input['coupon_code']]];
    }
    if ($mode === 'subscription' && !empty($plan['trial'])) {
        $checkout['subscription_data'] = ['trial' => $plan['trial']];
    }

    $intent = [
        'order_id'          => 'ord-' . bin2hex(random_bytes(16)),
        'order_description' => $plan['description'],
        'platform'          => 'WEB',
        'checkout'          => $checkout,
    ];
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        // Behind a proxy/load balancer this is the proxy's address — use the client IP from your trusted proxy header instead.
        $intent['ip_address'] = $_SERVER['REMOTE_ADDR'];
    }

    savePendingCheckout($merchantReference, $user['id'], $planKey);

    // Same SDK call as one-time payments — signed with the API v1 keys.
    $merchantData = $api->formMerchantData($intent)->toArray();
    error_log("[DEBUG] Billing v2 checkout: plan=$planKey merchant_reference=$merchantReference");
    jsonResponse(200, $merchantData);
    exit;
}

// merchantData that collects payment for an invoice already issued via API v2.
// Body: { invoice_id }. Response: { merchantData, amountDue, currency } — show the
// amount yourself: invoice_id intents emit no invoicePreview.
if ($path === '/api/billing-v2/invoice' && $method === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $user = currentUser();
    if ($user === null) {
        jsonResponse(401, ['error' => 'not logged in / no Billing customer']);
        exit;
    }
    if (API_V2_SECRET === '') {
        jsonResponse(500, ['error' => 'SOLIDGATE_API_V2_SECRET is not set']);
        exit;
    }
    if (empty($input['invoice_id'])) {
        jsonResponse(400, ['error' => 'invoice_id is required']);
        exit;
    }

    // The invoice's customer, email and address end up in the form, so only the
    // invoice's own customer may open it.
    $payload = ['id' => (string)$input['invoice_id']];
    if (CHANNEL_ID !== '') {
        $payload['channel_id'] = CHANNEL_ID;
    }
    [$status, $body] = callApiV2('/invoices/get', $payload);
    if ($status === 0) {
        error_log('[ERROR] Billing API unreachable');
        jsonResponse(502, ['error' => 'Billing API unreachable']);
        exit;
    }
    if ($status === 404) {
        jsonResponse(404, ['error' => 'invoice not found']);
        exit;
    }
    if ($status !== 200) {
        error_log("[ERROR] Billing API /invoices/get returned $status");
        jsonResponse(502, ['error' => 'Billing API error']);
        exit;
    }
    $invoice = $body['invoice'] ?? $body;
    $invoiceCustomerId = $invoice['customer']['id'] ?? $invoice['customer_id'] ?? null;
    if ($invoiceCustomerId !== $user['billing_customer_id']) {
        jsonResponse(404, ['error' => 'invoice not found']);
        exit;
    }
    $invoiceStatus = $invoice['status'] ?? '';
    if (!in_array($invoiceStatus, ['OPEN', 'DUNNING', 'UNPAID'], true)) {
        jsonResponse(409, ['error' => "invoice is $invoiceStatus, not payable"]);
        exit;
    }

    $intent = [
        'order_id'          => 'ord-' . bin2hex(random_bytes(16)),
        'order_description' => 'Invoice ' . ($invoice['id'] ?? $payload['id']),
        'platform'          => 'WEB',
        'invoice_id'        => $invoice['id'] ?? $payload['id'], // never combine with checkout
    ];
    if (!empty($_SERVER['REMOTE_ADDR'])) {
        // Behind a proxy/load balancer this is the proxy's address — use the client IP from your trusted proxy header instead.
        $intent['ip_address'] = $_SERVER['REMOTE_ADDR'];
    }

    jsonResponse(200, [
        'merchantData' => $api->formMerchantData($intent)->toArray(),
        'amountDue'    => $invoice['amount_due'] ?? null, // minor units
        'currency'     => $invoice['currency'] ?? null,
    ]);
    exit;
}

// Billing v2 events: { event_id, event_type, occurred_at, data }.
// Deliveries can repeat and arrive out of order: deduplicate on event_id in your
// DB (keep >= 1 week), and mark an event processed only AFTER the handler
// succeeded — otherwise a failed handler loses the event for good. Non-2xx
// makes Solidgate redeliver.
function handleBillingEvent(array $event): void {
    $invoice = $event['data']['invoice'] ?? []; // invoice events nest the payload: data.invoice / data.invoice_payment
    // Subscription events carry data.subscription: id, status, merchant_reference,
    // customer_id, next_billing_at, cancellation_info.reason, latest_invoice_id, trial_info.
    $sub = $event['data']['subscription'] ?? [];
    $subId = (string)($sub['id'] ?? '');
    switch ($event['event_type'] ?? '') {
        case 'SUBSCRIPTION_ACTIVATED':
        case 'SUBSCRIPTION_TRIAL_ACTIVATED':
            $purchase = findPendingCheckout((string)($sub['merchant_reference'] ?? ''));
            if ($purchase !== null) {
                linkSubscription($subId, $purchase['user_id']);
                $trial = ($event['event_type'] ?? '') === 'SUBSCRIPTION_TRIAL_ACTIVATED' ? ' (trial)' : '';
                error_log("Grant access$trial to user {$purchase['user_id']}");
            } else {
                error_log('unknown merchant_reference, ignoring');
            }
            break;
        case 'SUBSCRIPTION_RENEWED':
            error_log('Extend access for user ' . findSubscriptionUser($subId));
            break;
        case 'SUBSCRIPTION_UNPAID':
        case 'SUBSCRIPTION_EXPIRED':
            error_log('Revoke access for user ' . findSubscriptionUser($subId));
            break;
        case 'SUBSCRIPTION_CANCELLED':
            error_log('Revoke access for user ' . findSubscriptionUser($subId));
            error_log('Cancellation reason: ' . ($sub['cancellation_info']['reason'] ?? ''));
            break;
        case 'INVOICE_PAID':
            if (!empty($invoice['subscription_id'])) {
                // billing_reason casing differs across docs — compare case-insensitively.
                $reason = strtoupper((string)($invoice['billing_reason'] ?? ''));
                if ($reason === 'SUBSCRIPTION_CYCLE') {
                    error_log('Extend access for user ' . findSubscriptionUser((string)$invoice['subscription_id']));
                }
                // Otherwise nothing to do: access is granted on SUBSCRIPTION_ACTIVATED / _TRIAL_ACTIVATED.
            } else {
                // One-time invoice (checkout mode "invoice" or invoice_id): match by
                // merchant_reference, then fulfil.
                $purchase = findPendingCheckout((string)($invoice['merchant_reference'] ?? ''));
                error_log(sprintf(
                    'Invoice %s paid (ref=%s, user=%s) — fulfil',
                    $invoice['id'] ?? '', $invoice['merchant_reference'] ?? '', $purchase['user_id'] ?? 'unknown'
                ));
            }
            // Entitlements come from what was paid, not from what the page asked for:
            // updateCheckout runs in the browser. Check invoice.line_items[].product_price_id.
            break;
        case 'INVOICE_PAYMENT_FAILED':
            error_log('Payment ' . ($event['data']['invoice_payment']['payment_id'] ?? '') . ' failed — ask the customer to update the payment method');
            break;
        case 'INVOICE_UNPAID':
            error_log(!empty($invoice['subscription_id'])
                ? 'subscription invoice unpaid (SUBSCRIPTION_UNPAID revokes access)'
                : 'Mark invoice ' . ($invoice['id'] ?? '') . ' unpaid');
            break;
    }
}

if ($path === '/webhook/billing' && $method === 'POST') {
    if (BILLING_WH_SECRET === '') {
        http_response_code(500);
        echo 'Billing webhook secret not set';
        exit;
    }
    $rawBody   = file_get_contents('php://input'); // raw bytes — never re-serialize
    $signature = trim($_SERVER['HTTP_SIGNATURE'] ?? ''); // comma-joined during secret rotation
    if ($signature === '') {
        http_response_code(400);
        echo 'Missing signature header';
        exit;
    }
    if (!verifyBillingWebhookSignature($rawBody, $signature)) {
        error_log('[ERROR] Invalid Billing webhook signature');
        http_response_code(400);
        echo 'Invalid signature';
        exit;
    }

    $event = json_decode($rawBody, true);
    if (!is_array($event)) {
        http_response_code(400);
        echo 'Invalid JSON';
        exit;
    }
    // Minimal file-based dedupe stub — use your DB in production (keep >= 1 week).
    $dedupeDir = sys_get_temp_dir() . '/solidgate-billing-events';
    if (!is_dir($dedupeDir)) {
        mkdir($dedupeDir, 0777, true);
    }
    $dedupeFile = $dedupeDir . '/' . sha1((string)($event['event_id'] ?? ''));
    if (file_exists($dedupeFile)) {
        echo 'OK';
        exit;
    }

    // Kept synchronous for the demo. In production, durably enqueue the event here,
    // return 200, and let the worker apply the same "mark after success" rule.
    try {
        error_log('[DEBUG] Billing event [' . ($event['event_type'] ?? '') . '] (' . ($event['event_id'] ?? '') . ')');
        handleBillingEvent($event);
        touch($dedupeFile); // mark processed only after success
        echo 'OK';
    } catch (Throwable $e) {
        error_log('[ERROR] Billing event handler failed: ' . $e->getMessage());
        http_response_code(500);
        echo 'Retry later';
    }
    exit;
}

// 404
http_response_code(404);
echo 'Not found';
