# Billing v2 (Subscriptions 2.0, Invoicing)

Sell **Billing v2** subscriptions and invoices through the Payment Form. The paymentIntent carries a `checkout` object (or an `invoice_id` for an invoice you already issued) instead of the Billing v1 `product_id` + `customer_account_id` pair. The form calculates price, discount and tax, takes the payment, and Billing creates the subscription or invoice.

Upstream docs:
- Payment Form, Billing flow: https://docs.solidgate.com/payments/integrate/payment-form/create-your-payment-form/
- Subscriptions 2.0: https://docs.solidgate.com/billing/subscriptions/subscriptions-2.0/integrate-subscriptions/
- Invoicing: https://docs.solidgate.com/billing/invoicing/integrate-invoicing/
- Updating the form: https://docs.solidgate.com/payments/integrate/payment-form/update-payment-form/
- API v2 reference: https://api-docs.solidgate.com/api/v2/get-started

---

## Billing v1 or Billing v2? Decide first

The two versions use different fields, keys, APIs and webhooks. **Never mix them in one paymentIntent.** Use the merchant's setup to tell which version they run:

| Signal in the merchant's setup / code | Version | Read |
|---|---|---|
| Top-level `product_id` / `product_price_id` in the paymentIntent, `customer_account_id`, calls to `subscriptions.solidgate.com/api/v1`, webhook `subscription.updated.v2` | **Billing v1** (Subscriptions 1.0) | [subscriptions.md](subscriptions.md) |
| API v2 keys (`akey_…` / `asec_…`), webhook secrets `wsec_…`, customers with ids like `cust_…`, calls to `api.solidgate.com/v2/…`, a `checkout` object or `invoice_id` in the paymentIntent, webhook events like `SUBSCRIPTION_ACTIVATED` / `INVOICE_PAID` | **Billing v2** (this file) | — |
| The user asks for "Subscriptions 2.0", "Billing 2.0", invoices, the customers API, line items or quantities | **Billing v2** | — |
| No signal (new integration, version not stated) | **Ask** which Billing version is enabled on their Solidgate account before writing code | — |

> ⚠️ The Billing **v1** webhook is called `subscription.updated.v2`. The `.v2` suffix is the webhook schema version, **not** Billing v2. Do not treat it as a Billing v2 signal.

### What changes from v1 to v2

| Concern | Billing v1 | Billing v2 |
|---|---|---|
| What you sell in the intent | top-level `product_id` / `product_price_id` | `checkout.line_items[].product_price_id` + `quantity` |
| Customer | `customer_account_id` (your own string) | `checkout.customer_id`: a Billing customer, created first via API v2 |
| Coupon | top-level `coupon_id` | `checkout.discounts[]`: `coupon_id` **or** `coupon_code` |
| Trial | configured on the product in Hub | per checkout in `checkout.subscription_data.trial` |
| Collect an invoice you already issued | — | top-level `invoice_id` in the paymentIntent (or a Payment Page / Payment Link created with `invoice_id`) |
| Subscription management API | `https://subscriptions.solidgate.com/api/v1`, HMAC-SHA512 signed with `api_pk_` / `api_sk_` | `https://api.solidgate.com/v2/…`, `Authorization: Bearer asec_…` |
| Webhooks | `subscription.updated.v2`, `wh_pk_` / `wh_sk_` (HMAC-SHA512) | `SUBSCRIPTION_*`, `INVOICE_*`, `CUSTOMER_*` events, one endpoint secret (HMAC-SHA256) |
| Change the cart after init | `form.update(partialIntent)` / `form.applyCoupon()` | `form.updateCheckout(config)` |

**What stays the same:** `merchantData` is still produced by the backend SDK with the API v1 keys `api_pk_` / `api_sk_` (see [frontend-sdk.md § Backend SDKs](frontend-sdk.md#backend-sdks)). Frontend SDK init, styling and card or APM order webhooks don't change. Products and prices are shared between v1 and v2 ([Subscriptions 2.0 guide](https://docs.solidgate.com/billing/subscriptions/subscriptions-2.0/integrate-subscriptions/)).

---

## Prerequisites

1. **Keys.** You need two sets:
   - API v1 keys (`api_pk_…` / `api_sk_…`) to sign `merchantData` for the form and to create products and prices.
   - API v2 keys (`akey_…` / `asec_…`, see [API v2 get started](https://api-docs.solidgate.com/api/v2/get-started)) for customers, invoices, subscriptions and webhook endpoints. Create them in Hub → Developers.
2. **Product + recurring price.** Create them in Hub or via API v1 ([create product](https://api-docs.solidgate.com/api/products-and-prices/create-product), [create price](https://api-docs.solidgate.com/api/products-and-prices/create-product-price)). A subscription needs at least one **recurring** price, which sets the amount, currency and billing period. Keep the price id: it is the `product_price_id`.
3. **Customer.** Create one Billing customer per end user via API v2. Store the returned `id` (e.g. `cust_01KMG2ABYPF6XS5DMJQ817C429`) against your user and reuse it for every later checkout.
4. **Billing webhook endpoint.** Register one via API v2 ([create webhook](https://api-docs.solidgate.com/api/v2/webhooks/create-webhook)) or in Hub, and store its signing secret. See [§ Webhooks](#billing-v2-webhooks).

### API v2 basics

- Host: `https://api.solidgate.com`. Pattern: `POST /v2/{resource}/{action}`. Every operation is `POST`.
- Auth: `Authorization: Bearer asec_…`. API v2 needs **no request signature**, unlike API v1.
- **Multi-channel API v2 keys:** if your key covers several channels, invoice and subscription calls (`/v2/invoices/create`, `…/finalize`, `…/get`, `…/list`, `/v2/subscriptions/get`) need `"channel_id": "chn_…"` in the body. Otherwise they fail with `400 VALIDATION`.
- JSON bodies use snake_case keys and UPPER_CASE enum values.
- Optional `Idempotency-Key` header (1–255 printable ASCII). The result is kept for 24 h. Reusing a key with a different body returns `422 IDEMPOTENCY_KEY_REUSED`.
- Errors are `{ "code", "message", "context" }`, e.g. `400 VALIDATION`, `401 UNAUTHENTICATED`, `404 NOT_FOUND`, `429 RATE_LIMIT` (see `context.next_try_at`).

### Create a customer (server-side)

```bash
curl -X POST https://api.solidgate.com/v2/customers/create \
  -H "Authorization: Bearer $SOLIDGATE_API_V2_SECRET" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: user-42-customer" \
  -d '{
    "email": "john@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "merchant_reference": "user-42",
    "address": { "country": "USA", "state": "CA", "city": "San Francisco", "line1": "123 Main St", "postal_code": "94105" }
  }'
# → { "id": "cust_01KMG2ABYPF6XS5DMJQ817C429", "email": "john@example.com", "status": "ACTIVE", ... }
```

`email` is required. `address.country` is ISO 3166-1 **alpha-3**. Tax is calculated from the customer address. The customer record holds the payer's identity, address and tax data, so **don't repeat those fields in the paymentIntent**.

---

## Payment Form flows

| You want to… | paymentIntent carries | On payment, Billing… |
|---|---|---|
| **Start a subscription** | `checkout` with `mode: "subscription"` | creates the subscription, generates the activation invoice, collects the payment and stores the payment instrument for renewals |
| **Sell a one-time invoice** | `checkout` with `mode: "invoice"` | creates the invoice, collects the customer's address, finalizes the invoice and processes the charge |
| **Collect an invoice you already issued** via API v2 | top-level `invoice_id` | charges the invoice's amount due and marks it paid |

Rules for all three:
- **Send `checkout` or `invoice_id`, never both.** With `checkout`, omit top-level `amount`, `currency`, `product_id` and `invoice_id`: the Payment Form calculates the total from `checkout.line_items`. With `invoice_id`, omit `amount`, `currency` and `checkout`: the total is the invoice's amount due.
- **Don't send `customer_account_id`**, and don't repeat customer fields already stored on the Billing customer. Also leave out the other Billing v1 fields: top-level `product_price_id` and `coupon_id`.
- Keep the usual form fields: `order_id`, `order_description`, `ip_address`, `platform`, `success_url` / `fail_url`, `language`, wallet fields and so on (see [payment-intent.md](payment-intent.md)).
- Generate `merchantData` with the backend SDK exactly as for one-time payments. `checkout` is just a nested object in the JSON intent.

### Flow A: start a subscription (`mode: "subscription"`)

```json
{
  "order_id": "ord-2026-000123",
  "order_description": "Pro plan (monthly)",
  "ip_address": "8.8.8.8",
  "platform": "WEB",
  "checkout": {
    "mode": "subscription",
    "customer_id": "cust_01KMG2ABYPF6XS5DMJQ817C429",
    "merchant_reference": "sub-user42-20261118-01",
    "line_items": [
      { "product_price_id": "3f8b2a8e-6c1d-4f7e-9a51-2b0d6f1c9e44", "quantity": 1 }
    ],
    "discounts": [{ "coupon_code": "WELCOME20" }],
    "subscription_data": {
      "description": "Pro plan for user 42",
      "metadata": { "user_id": "42", "plan": "pro" },
      "trial": { "type": "free", "period": { "value": 7, "unit": "day" } }
    }
  }
}
```

Flow:
1. Your backend builds the intent, the SDK turns it into `merchantData`, and the frontend calls `PaymentFormSdk.init({ merchantData })`.
2. The form previews the first charge (`invoicePreview` event). **No subscription is created yet.**
3. Optional: the customer changes plan, quantity, coupon or trial. Call `form.updateCheckout(...)` (see [§ Frontend](#frontend-invoicepreview-and-formupdatecheckout)).
4. The customer pays. Solidgate creates the subscription, generates the activation invoice and collects the payment.
5. Grant access on the `SUBSCRIPTION_ACTIVATED` (or `SUBSCRIPTION_TRIAL_ACTIVATED`) webhook, never on the frontend `success` event.

Subscription-specific rules:
- **Pass exactly one recurring price in `line_items`.** Multiple recurring prices are not supported. Additional one-time prices are allowed and are collected with the first payment.
- `line_items[].description` is **not** available in subscription mode.
- Trials: the subscription starts in `TRIALING`. A **free** trial charges nothing for the trial itself, but any one-time items are still charged at trial start. With a **paid** trial, the trial amount and any one-time items are collected together in one payment at trial start.
- Cards, Apple Pay, Google Pay and PayPal (`paypalButtonParams`) work on the same intent. A successful PayPal payment stores a payment instrument for renewals.

### Flow B: one-time invoice (`mode: "invoice"`)

```json
{
  "order_id": "ord-2026-000124",
  "order_description": "Workshop ticket",
  "ip_address": "8.8.8.8",
  "checkout": {
    "mode": "invoice",
    "customer_id": "cust_01KMG2ABYPF6XS5DMJQ817C429",
    "merchant_reference": "cart-8812",
    "line_items": [
      { "product_price_id": "9a3c5e1f-2b4d-4c6e-8f0a-1b2c3d4e5f60", "quantity": 2, "description": "Workshop ticket" }
    ]
  }
}
```

You **don't need to create or finalize an invoice through the API first**. The Payment Form creates the invoice, collects the customer's address, finalizes it and processes the charge when the customer pays. `subscription_data` is a subscription-mode field. Don't send it here.

### Flow C: pay an invoice you already issued (`invoice_id`)

Use this when you created and finalized the invoice yourself via API v2 (`/v2/invoices/create` → `/v2/invoices/finalize`), for example B2B billing, a manual charge, or collecting an unpaid renewal.

```json
{
  "order_id": "ord-2026-000125",
  "order_description": "Invoice INV-2026-0042",
  "ip_address": "8.8.8.8",
  "invoice_id": "<invoice id returned by API v2>"
}
```

> Paying an existing invoice through the embedded form is not yet described on the public Payment Form pages. If form init rejects your `invoice_id`, check with Solidgate support that it is enabled for your account, or use a Payment Page / Payment Link (below).

- The invoice must be finalized and unpaid: status `OPEN`, `DUNNING` or `UNPAID`. A `DRAFT`, `PAID` or `VOIDED` invoice can't be paid this way.
- The amount charged is the invoice's **amount due**. The customer, email and billing address come from the invoice and override anything in the intent.
- The invoice is locked: a billing-address change does not reprice it, and no `invoicePreview` event fires (the amount is fixed, so show the invoice total you already know).
- **Do not call `form.updateCheckout`** on an `invoice_id` intent: there is no cart to change, so it rejects ("Not a checkout flow"). If it happens, re-init the form with fresh `merchantData`.
- Fulfil on `INVOICE_PAID`.
- To finalize, an invoice needs the customer's email, first name, last name, IP address and at least a country in the address. Only `DRAFT` invoices can be edited.

Before building the intent, fetch the invoice server-side and check it belongs to the logged-in user. `POST /v2/invoices/get` with `{ "id": "inv_…", "channel_id": "chn_…" }` (`channel_id` only for multi-channel keys) returns the invoice object itself, not wrapped ([API reference](https://api-docs.solidgate.com/api/v2/invoices/get-invoice)). Relevant fields: `id`, `status`, `customer.id`, `amount_due` and `total_amount` (minor units), `currency`, `merchant_reference`, `billing_reason`, `line_items[]`, `pdf_url`, `created_at`, `updated_at`. Compare `customer.id` with the user's Billing customer id, check `status` is `OPEN`, `DUNNING` or `UNPAID`, and show `amount_due` on your page. The form emits no `invoicePreview` for this intent.

Other ways to collect the same invoice, outside the embedded form:
- **Payment Page** ([create page API](https://api-docs.solidgate.com/api/payment-page/create-payment-page)) or **Payment Link** ([create link API](https://api-docs.solidgate.com/api/payment-link/create-payment-link)): these are API v1 endpoints, signed like other v1 calls. Pass `invoice_id` instead of `amount`/`currency`, and don't mix it with `product_id`. The invoice must be finalized (`OPEN`). A payment page link expires in 24 hours. Take the full request body from the linked API reference, because this skill doesn't document it.
- **API** `POST https://api.solidgate.com/v2/invoices/pay` with `{ "id": "<invoice id>", "payment_instrument_id": "<saved instrument>" }`. This charges a saved payment instrument with no customer present. The result arrives asynchronously via `INVOICE_PAID` / `INVOICE_PAYMENT_FAILED`. Error codes: [pay invoice API reference](https://api-docs.solidgate.com/api/v2/invoices/pay-invoice).

---

## `checkout` object reference

| Field | Type | Required | Rules |
|---|---|---|---|
| `mode` | string | Yes | `"subscription"` or `"invoice"` |
| `customer_id` | string | Yes | 6–100 chars. A Billing 2.0 customer id in `cust_…` format. |
| `merchant_reference` | string | Yes | 1–100 chars, letters, digits, `_` or `-` only. Identifies the subscription or invoice in your system. **Unique within the channel and immutable after creation.** |
| `line_items` | array | Yes | Subscription mode: **exactly one recurring price** (plus optional one-time prices). Invoice mode: the products on the invoice. |
| `line_items[].product_price_id` | string | Yes | 1–100 chars. The product price charged on this line. |
| `line_items[].quantity` | integer | Yes | 1–999 999 |
| `line_items[].description` | string | No | 1–255 chars, shown on the invoice. **Invoice mode only.** |
| `discounts` | array | No | 0–1 items. One coupon: `coupon_id` **or** `coupon_code`, not both. |
| `discounts[].coupon_id` | string | One of | 1–100 chars |
| `discounts[].coupon_code` | string | One of | 2–25 chars, alphanumeric only. The code a customer typed. |
| `subscription_data` | object | No | **Subscription mode only.** |
| `subscription_data.description` | string | No | 1–500 chars |
| `subscription_data.metadata` | object | No | String key/value pairs, at most 10 entries |
| `subscription_data.trial` | object | No | Trial period configuration |
| `subscription_data.trial.type` | string | Yes (with `trial`) | `"free"` or `"paid"` |
| `subscription_data.trial.period` | object | Yes (with `trial`) | `{ "value": <int>, "unit": … }` |
| `subscription_data.trial.period.unit` | string | Yes | `minute`, `hour`, `day`, `week`, `month`, `quarter` or `year` |
| `subscription_data.trial.period.value` | integer | Yes | Trial length in `unit`s. Maximums: `day` ≤ 365, `week` ≤ 52, `month` ≤ 12. |
| `subscription_data.trial.amount` | integer | Paid trials | Trial price in minor units, 1–999 999 999. **Send it for `paid`, omit it for `free`.** |
| `subscription_data.trial.settle_interval` | integer | No | Hours before the paid trial charge settles automatically, 0–168. Paid trials only; omit it for `free`. |

> The intent's `checkout.subscription_data.trial` and `form.updateCheckout`'s `subscriptionData.trial` are documented with **different limits**. The intent allows units `minute`…`year` and `settle_interval` 0–168. `updateCheckout` allows `day`/`week`/`month` and `settleInterval` 0–240. To work with both, use `day`/`week`/`month` and keep `settle_interval` ≤ 168.

---

## Frontend: `invoicePreview` and `form.updateCheckout`

Checkout intents add one event and one method to the standard SDK surface ([frontend-sdk.md](frontend-sdk.md)).

> **Subscribing and getting the form instance** ([form events](https://docs.solidgate.com/payments/integrate/payment-form/form-events/)):
> - Vanilla JS: `const form = PaymentFormSdk.init(...)`, then `form.on("invoicePreview", (e) => e.data.invoicePreview)` **in the same synchronous block as `init`**. The first preview fires before `mounted`, so subscribing after an `await` misses it.
> - React: `onInvoicePreview={(event) => event.invoicePreview}`. Vue: `@invoice-preview="(event) => event.invoicePreview"`. Angular: `(invoicePreview)="onInvoicePreview($event)"`.
> - For `form.updateCheckout` you need the instance: React `onReadyPaymentInstance={(form) => …}`, Vue `@ready-payment-instance="(form) => …"`.
> - **TypeScript:** if your installed SDK typings don't list `invoicePreview` or `updateCheckout` yet, declare a small local interface (as the React/Vue examples do) instead of using `any`.

### `invoicePreview` event

Fires at form init (before `mounted`) and again after a billing-address change (country, state, city, ZIP, address) when the recalculated invoice differs. Identical previews are not re-sent. Render your order summary from this event. **Don't compute totals yourself**, because tax depends on the address.

```js
const form = PaymentFormSdk.init({ merchantData, iframeParams: { containerId: "payment-form" } });
form.on("invoicePreview", (e) => {   // same synchronous block as init
  const p = e.data.invoicePreview;
  // Amounts are decimal STRINGS in major units ("40.00"), not cents.
  // p.total          invoice total
  // p.currency       "USD", p.currencyIcon "$"
  // p.amounts?       { subtotal, discount, taxable?, tax? }
  // p.amountDue?     newer SDK releases, not in the public reference yet: amount charged now after any
  //                  customer balance. Use `p.amountDue ?? p.total` as the pay-now figure.
  // p.lineItems[]    { productPriceId, productId, quantity, amount, currency, currencyIcon,
  //                    amounts? { subtotal, discount, unitPrice?, taxable?, tax? },
  //                    tax? { categoryId, mode, rate } }
  renderSummary(p);
});
```

Show `amountDue ?? total` as the "pay now" figure. The form and the Apple Pay / Google Pay buttons charge that amount.

### `form.updateCheckout(config)`

Changes the cart **without** new `merchantData`: plan or quantity switch, coupon entry, trial terms. Keys are **camelCase** here, unlike the snake_case intent.

```js
let lastGoodConfig = null; // the cart the form is known to hold

async function applyCart(config) {
  try {
    const { invoicePreview } = await form.updateCheckout(config);
    lastGoodConfig = config;
    renderSummary(invoicePreview);
  } catch (err) {
    // err.name === "UpdateCheckoutError"; err.details?.code, err.details?.message (string[] | string | field map)
    showCheckoutError(err);
    // The form's cart state is now unknown: put back the last cart that worked,
    // or re-init with fresh merchantData if there is none / that fails too.
    if (lastGoodConfig) {
      await form.updateCheckout(lastGoodConfig).catch(() => reinitWithFreshMerchantData());
    } else {
      reinitWithFreshMerchantData();
    }
  }
}

applyCart({
  lineItems: [{ productPriceId: annualPriceId, quantity: 1 }], // full replacement, at least 1 item
  discounts: [{ couponCode: "SPRING25" }],                     // 0–1; couponId OR couponCode
  subscriptionData: {                                          // subscription mode only; RE-SEND every call (see below)
    trial: { type: "free", period: { value: 14, unit: "day" } },
    metadata: { plan: "annual" },
    description: "Annual plan",
  },
});
```

`UpdateCheckoutConfig`:

| Field | Rules |
|---|---|
| `lineItems` (required) | **Full replacement**, at least one item. `productPriceId` (required), `quantity` (required, 1–999 999), `description` (optional, 1–255) |
| `discounts` | 0–1 items. `couponId` (1–100) or `couponCode` (2–25, letters and digits), not both |
| `subscriptionData` | Only when `checkout.mode` is `subscription`. `trial`: `type` `free` \| `paid`; `period { value, unit: day \| week \| month }` (max 365 days / 52 weeks / 12 months); `amount` (integer, minor units) and `settleInterval` (0–240 h) are **required for `paid` and omitted for `free`**. `metadata` max 10 pairs, `description` 1–500 |

How it behaves:
- Returns a Promise that resolves to `{ invoicePreview }`. It never throws synchronously, so `await` it inside try/catch. It does **not** fire the `invoicePreview` event, so update the UI from the resolved value.
- Rejects with `UpdateCheckoutError` (`details.code`, `details.message`) when the intent has no `checkout` ("Not a checkout flow", which includes `invoice_id` intents), when used in resign mode, or when Billing rejects the change (unknown coupon, invalid trial, …).
- **After a rejected `updateCheckout`, treat the form's cart as unknown.** Before the customer pays or you call `form.update()`, call `updateCheckout` again with the last config that worked, or re-init with fresh `merchantData`.
- **Every field is a full replacement, `subscriptionData` included.** Omitting `subscriptionData` **clears** the trial, metadata and description you sent in the intent. So an "apply coupon" call without it silently drops a free trial. Re-send `subscriptionData` (same trial as your server-side plan) on every call in subscription mode.
- It cannot change `amount`, `currency`, `product_id`, `customer_account_id`, `customer_id` or `merchant_reference`. For those, build a new intent.
- Don't use `form.update(partialIntent)` or `form.applyCoupon()` to change a Billing v2 cart. Those belong to the v1 and one-time paths.

---

## Billing v2 webhooks

Billing v2 events are **separate** from the card / APM order webhooks in [webhooks.md](webhooks.md). The signing scheme, envelope and event names are all different. **Drive subscription and invoice state from the Billing v2 events.**

### Verify the signature

| | Value |
|---|---|
| Header | `signature` |
| Algorithm | `base64( HMAC-SHA256( endpoint_secret, raw_body ) )`. Use the raw bytes and Base64-encode the digest directly (**no** hex step, **no** key wrapping). |
| Secret | One signing secret **per webhook endpoint** (`wsec_…`), not a `wh_pk_` / `wh_sk_` pair |
| Rotation | During rotation each delivery carries **two** `signature` headers (new secret first). Accept the event if any of them matches. The examples also accept an optional previous secret, `SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS`. |
| Other headers | `solidgate-event-id`, `solidgate-event-type`, `solidgate-event-occurred-at` |

The checklist is the same as v1: use the **raw body bytes**, compare in **constant time**, and serve over HTTPS.

```js
// Node.js / Express: app.use("/webhook/billing", express.raw({ type: "*/*" }))
function verifyBillingSignature(rawBodyBuf, header, secret) {
  const expected = crypto.createHmac("sha256", secret).update(rawBodyBuf).digest("base64");
  const a = Buffer.from(expected), b = Buffer.from(header || "");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
```

```python
# Python
expected = base64.b64encode(hmac.new(secret.encode(), raw_body, hashlib.sha256).digest()).decode()
ok = hmac.compare_digest(expected, request.headers.get("signature", ""))
```

```go
// Go
mac := hmac.New(sha256.New, []byte(secret))
mac.Write(rawBody)
expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
ok := hmac.Equal([]byte(expected), []byte(r.Header.Get("signature")))
```

### Envelope and delivery

```json
{ "event_id": "…", "event_type": "INVOICE_PAID", "occurred_at": "2026-11-18T10:30:00Z", "data": { "…": "shape depends on event_type" } }
```

Headers also carry `solidgate-event-id` (same as `event_id`, unchanged across redeliveries), `solidgate-event-type`, `solidgate-event-occurred-at`, and `solidgate-attempt` (`0` on first delivery, `>0` on redelivery).

- Return `200 OK` quickly after signature verification. If you hand the work to a background queue, **persist or enqueue the event durably before returning 200**.
- Deliveries can repeat and arrive **out of order**. Deduplicate on `event_id`, and **mark an event processed only after your handler succeeds**. Marking it "seen" before processing loses the event for good if the handler fails. If processing fails synchronously, return a non-2xx status so the event is redelivered.
- Order events with `solidgate-event-occurred-at` / `occurred_at`. Ignore an event older than the last state you applied for that subscription or invoice.

### `INVOICE_PAID` / invoice event payload

`data` is **nested**: the invoice sits under `data.invoice`, and the payment under `data.invoice_payment`. There is no top-level `data.id`, `data.invoice_id` or `data.customer_id`. Source: [api-docs: InvoicePaid](https://api-docs.solidgate.com/api/v2/invoices/on-invoice-paid).

```json
{
  "event_id": "…",
  "event_type": "INVOICE_PAID",
  "occurred_at": "2026-11-18T10:30:00Z",
  "data": {
    "invoice": {
      "id": "inv_01KPWT0K1PQWEYYRT7J1H3NC85",
      "status": "PAID",
      "merchant_reference": null,
      "subscription_id": "subs_01HYDYBRKN16B8X3BR9WP78ZR7",
      "billing_reason": "SUBSCRIPTION_CREATE",
      "customer": { "id": "cust_01KMG2ABYPF6XS5DMJQ817C429", "email": "john@example.com" },
      "total_amount": 990,
      "amount_due": 900,
      "currency": "USD",
      "line_items": [
        { "product_price_id": "3f8b2a8e-6c1d-4f7e-9a51-2b0d6f1c9e44", "product_id": "…", "quantity": 1, "amount": 990, "currency": "USD", "amount_details": { "…": "…" } }
      ]
    },
    "invoice_payment": {
      "id": "inp_01KQ7FFRGJ5X0CKSHZ0ZJRQ4VW",
      "invoice_id": "inv_01KPWT0K1PQWEYYRT7J1H3NC85",
      "status": "PAID",
      "payment_id": "pay_01KQ7FFRGJ5X0CKSHZ0ZJRQ4VW",
      "payment_method": "CARD",
      "amount": 900,
      "currency": "USD"
    }
  }
}
```

| What you need | Path |
|---|---|
| Invoice id | `data.invoice.id` (also `data.invoice_payment.invoice_id`) |
| Your reference (`checkout.merchant_reference`) | **Invoice mode (Flow B) and Flow C:** `data.invoice.merchant_reference`. **Subscription mode:** the reference is stored on the **subscription** (`data.subscription.merchant_reference` in `SUBSCRIPTION_*` events) and may be empty on its invoices. Use `data.invoice.subscription_id` to link invoices to the subscription. |
| Subscription id (empty for one-time invoices) | `data.invoice.subscription_id` |
| Customer id (`cust_…`) | `data.invoice.customer.id` |
| Why the invoice exists | `data.invoice.billing_reason`: `SUBSCRIPTION_CREATE` (first payment of a subscription), `SUBSCRIPTION_CYCLE` (renewal), `SUBSCRIPTION_UPDATE`, `MANUAL` (invoice-mode checkout, and invoices you created via API). The API returns them uppercase, while some guides show them lowercase, so **compare case-insensitively**. |
| Payment | `data.invoice_payment.payment_id`, `data.invoice_payment.payment_method` |
| What was paid (for entitlements) | `data.invoice.line_items[]`: `product_price_id`, `product_id`, `quantity`, `amount` (minor units), `currency`, `amount_details` |

Amounts in webhook payloads are **integers in minor units**. That differs from `invoicePreview` on the frontend, which uses decimal strings.

### `SUBSCRIPTION_*` event payload

Every subscription event carries the subscription under `data.subscription` ([API reference: SubscriptionActivated](https://api-docs.solidgate.com/api/v2/subscriptions/on-subscription-activated)):

| What you need | Path |
|---|---|
| Subscription id (`subs_…`) | `data.subscription.id` |
| Your reference (`checkout.merchant_reference`) | `data.subscription.merchant_reference` |
| Customer id (`cust_…`) | `data.subscription.customer_id` |
| Status | `data.subscription.status`: `CREATED`, `PENDING`, `TRIALING`, `ACTIVE`, `REDEMPTION`, `UNPAID`, `CANCELLED`, `EXPIRED`, `PAUSED` |
| Trial | `data.subscription.trial_info` `{ type: FREE \| PAID, period { start_at, end_at }, amount }` |
| Next charge | `data.subscription.next_billing_at` |
| Cancellation | `data.subscription.cancellation_info` `{ cancel_at, requested_at, reason, comment? }`. `reason` is one of `DUNNING_EXHAUSTED`, `CANCELLATION_REQUESTED`, `FRAUD_ALERT_RECEIVED`, `DISPUTE_RECEIVED` |
| Latest invoice / payment instrument | `data.subscription.latest_invoice_id`, `data.subscription.payment_instrument_id` |
| Plan | `data.subscription.line_items[]` (`product_price_id`, `quantity`, `billing_type` `RECURRING` \| `ONE_TIME`, …), plus `metadata`, `description`, `discounts` |

**Recommended matching for subscriptions:**
1. When you build the checkout, persist `merchant_reference → your user / plan`.
2. On `SUBSCRIPTION_ACTIVATED` or `SUBSCRIPTION_TRIAL_ACTIVATED`, look up `data.subscription.merchant_reference`, grant access, and store `data.subscription.id → user`.
3. Later events resolve through the subscription id: `SUBSCRIPTION_*` via `data.subscription.id`, renewals (`INVOICE_PAID` with `SUBSCRIPTION_CYCLE`) via `data.invoice.subscription_id`.

### Events and what to do

| Event | Action |
|---|---|
| `SUBSCRIPTION_ACTIVATED` | **Grant access** (match by `data.subscription.merchant_reference`) |
| `SUBSCRIPTION_TRIAL_ACTIVATED` | Grant trial access. A free trial has no paid first invoice, so this event is the only grant signal. |
| `SUBSCRIPTION_RENEWED` | Extend access |
| `INVOICE_PAID` | Fires on every successful charge, first payment or renewal (`data.invoice.billing_reason`). **Fulfill one-time invoices (Flows B and C) here**: find them by `data.invoice.id` or `data.invoice.merchant_reference`. |
| `INVOICE_PAYMENT_FAILED` | A payment attempt failed (`data.invoice_payment.payment_id`). Ask the customer to update their payment method. |
| `SUBSCRIPTION_REDEMPTION_STARTED`, `INVOICE_DUNNING_STARTED` | Retries are in progress. Keep access and notify the customer. |
| `SUBSCRIPTION_UNPAID` | **Revoke access.** You can still collect the unpaid invoice later with Flow C (`invoice_id`). |
| `INVOICE_UNPAID` | For a subscription invoice (`data.invoice.subscription_id` set), revoke access. For a one-time invoice, mark the order unpaid. Collect later with Flow C. |
| `SUBSCRIPTION_CANCELLED` | Revoke access (`data.subscription.cancellation_info.reason`) |
| `SUBSCRIPTION_EXPIRED` | Revoke access |
| `SUBSCRIPTION_SCHEDULED_FOR_PAUSE`, `SUBSCRIPTION_PAUSED`, `SUBSCRIPTION_RESUMED` | Pause or resume access (`data.subscription.pause_info`, `data.subscription.next_billing_at`) |
| `SUBSCRIPTION_CREATED`, `SUBSCRIPTION_UPDATED`, `SUBSCRIPTION_SCHEDULED_FOR_CANCELLATION`, `SUBSCRIPTION_SCHEDULED_FOR_CREATION`, `SUBSCRIPTION_DELETED` | Sync local state (`DELETED`: a subscription scheduled for creation was deleted, so remove your local record) |
| `INVOICE_CREATED`, `INVOICE_UPDATED`, `INVOICE_FINALIZED`, `INVOICE_VOIDED`, `INVOICE_DELETED`, `INVOICE_FINALIZATION_FAILED` | Sync local state |
| `CUSTOMER_CREATED`, `CUSTOMER_UPDATED`, `PAYMENT_INSTRUMENT_CREATED`, `PAYMENT_INSTRUMENT_REVOKED`, `PAYMENT_INSTRUMENT_EXPIRED` | Sync local state. An expired or revoked instrument means the customer must pay again through the form. |

Subscription statuses: `CREATED`, `PENDING`, `TRIALING`, `ACTIVE`, `PAUSED`, `REDEMPTION`, `UNPAID`, `CANCELLED`, `EXPIRED`. Invoice statuses: `DRAFT`, `OPEN`, `DUNNING`, `PAID`, `UNPAID`, `VOIDED`.

Match events to your records with `merchant_reference` (on the invoice for Flows B and C, on the subscription for Flow A), `data.invoice.id` (Flow C), `data.invoice.subscription_id` (renewals) and `data.invoice.customer.id`. The frontend `success` event carries the card `order_id` only. Use it for UX, never for fulfillment.

---

## Backend example (Node.js)

```js
// Plans live on the server. The browser picks a plan key, never a price id, trial or mode.
const PLANS = {
  pro_monthly: { mode: "subscription", priceId: process.env.PRO_MONTHLY_PRICE_ID,
                 trial: { type: "free", period: { value: 7, unit: "day" } } },
};

// POST /api/billing-v2/checkout  { plan, coupon_code? }  → merchantData
app.post("/api/billing-v2/checkout", async (req, res) => {
  const plan = PLANS[req.body.plan];
  if (!plan) return res.status(400).json({ error: "unknown plan" });
  const user = await currentUser(req);                         // your auth
  const customerId = user.solidgateCustomerId                  // created once via /v2/customers/create
    ?? (await createBillingCustomer(user));
  const merchantReference = `sub-${user.id}-${Date.now()}`;    // unique per purchase
  await savePendingCheckout(merchantReference, user.id, req.body.plan); // needed to match webhooks later

  const intent = {
    order_id: `ord-${crypto.randomUUID()}`,
    order_description: "Pro plan",
    ip_address: req.ip,
    platform: "WEB",
    checkout: {
      mode: plan.mode,
      customer_id: customerId,
      merchant_reference: merchantReference,
      line_items: [{ product_price_id: plan.priceId, quantity: 1 }],
      ...(plan.trial && { subscription_data: { trial: plan.trial } }),
      ...(req.body.coupon_code && { discounts: [{ coupon_code: req.body.coupon_code }] }),
    },
  };
  // Same SDK call as one-time payments; signed with api_pk_/api_sk_ (API v1 keys).
  res.json(api.formMerchantData(intent).toObject());
});
```

Full runnable versions (customer creation, the checkout intent and Billing webhook verification) are in every backend example: [Node.js](examples/nodejs/server.js), [Python](examples/python/server.py), [Go](examples/go/main.go), [PHP](examples/php/server.php). Frontend components with an `invoicePreview` summary and a coupon applied via `updateCheckout`: [React](examples/react/BillingCheckout.tsx), [Vue](examples/vue/BillingCheckout.vue).

---

## Pitfalls

1. **Mixing v1 and v2 fields.** `product_id`, top-level `product_price_id`, `coupon_id` or `customer_account_id` next to `checkout` is wrong. Choose one version.
2. **Sending `amount` / `currency` with `checkout` or `invoice_id`, or sending `checkout` and `invoice_id` together.** Billing calculates the total. Send exactly one of `checkout` or `invoice_id`.
3. **Signing `merchantData` with API v2 keys.** The form still uses the API v1 keys (`api_pk_` / `api_sk_`). `asec_…` is only a Bearer token for `api.solidgate.com/v2`. Never ship either secret to the browser.
4. **Making up a `customer_id`, or trusting one from the browser.** It must be a Billing customer (`cust_…`) created via API v2. Look it up server-side from the logged-in user. Never accept `customer_id` (or a raw `product_price_id` / `invoice_id`) from the request body without checking it belongs to that user, or anyone can start a checkout or pay against another customer's record. Your own user id goes in the customer's `merchant_reference`.
5. **Reusing `merchant_reference`.** It is unique within the channel and immutable once created. Generate a fresh one for every new `merchantData`.
6. **Verifying Billing v2 webhooks with the v1 recipe** (HMAC-SHA512, `wh_pk_` wrapping, hex). v2 uses HMAC-SHA256 over the raw body with the endpoint secret, Base64-encoded.
7. **Granting access on the frontend `success` event** or on `card_gate.order.updated` alone. Use `SUBSCRIPTION_ACTIVATED`, `SUBSCRIPTION_TRIAL_ACTIVATED`, `SUBSCRIPTION_RENEWED` and `INVOICE_PAID`.
8. **Computing the order summary client-side.** Tax and discounts are calculated server-side. Render from `invoicePreview` and show `amountDue ?? total` as the pay-now amount.
9. **Trusting the cart the browser ends up with.** `form.updateCheckout` runs client-side, so a shopper can switch to any price or trial on your channel. Grant entitlements from the **paid** invoice in the webhook (`data.invoice.line_items[].product_price_id`, `data.invoice.subscription_id`), not from what your page asked for. Keep server-side plan maps for the initial intent too.
10. **Reading webhook fields from the wrong place.** Invoice events nest the data: use `data.invoice.id`, not `data.id`. See [§ payload](#invoice_paid--invoice-event-payload).
11. **Ignoring a rejected `updateCheckout`.** The cart state is unknown afterwards. Retry with a valid config before letting the customer pay or calling `form.update()`.
12. **Paying a `DRAFT` invoice with `invoice_id`.** Finalize it first (`/v2/invoices/finalize`).
13. **Mode-only fields in the wrong mode:** `line_items[].description` in subscription mode, or `subscription_data` in invoice mode. Also, more than one recurring line item in subscription mode.
