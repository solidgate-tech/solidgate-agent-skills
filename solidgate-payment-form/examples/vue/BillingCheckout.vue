<!--
  Solidgate Payment Form — Vue 3 Billing v2 checkout (Subscriptions 2.0 / Invoicing)

  Renders the Payment Form for a Billing v2 `checkout` intent, shows the order
  summary from the `invoicePreview` event, and applies a coupon with
  `form.updateCheckout()`. See ../../billing-v2.md.

  Setup (one-time)
    1. Run one of the backends in this repo with the Billing v2 env vars set —
       it exposes POST /api/billing-v2/checkout (and /api/billing-v2/customers).
    2. Create a Billing customer once per user at signup and store its id
       ("cust_…") on the user. The backend reads it from the session; the browser
       never sends a customer id.
    3. npm install @solidgate/vue-sdk

  Usage
    <BillingCheckout
      plan="pro_monthly"
      product-price-id="3f8b2a8e-6c1d-4f7e-9a51-2b0d6f1c9e44"
      :subscription-data="{ trial: { type: 'free', period: { value: 7, unit: 'day' } } }"
    />

  `plan` is a key of the backend's server-side PLANS map (price, mode and trial
  are decided there). `productPriceId` is only needed for form.updateCheckout,
  which runs in the browser — so grant entitlements from the paid invoice in the
  webhook, never from what this page asked for.

  Grant access from the SUBSCRIPTION_ACTIVATED / INVOICE_PAID webhooks, not from
  the frontend `success` event.
-->

<template>
  <div>
    <div v-if="!merchantData">
      <button @click="initCheckout" :disabled="loading">
        {{ loading ? "Loading..." : "Subscribe" }}
      </button>
      <p v-if="error" style="color: red">{{ error }}</p>
    </div>

    <div v-else>
      <div v-if="preview">
        <p>Subtotal: {{ preview.currencyIcon }}{{ preview.amounts?.subtotal ?? preview.total }}</p>
        <p v-if="preview.amounts?.discount && preview.amounts.discount !== '0.00'">
          Discount: −{{ preview.currencyIcon }}{{ preview.amounts.discount }}
        </p>
        <p v-if="preview.amounts?.tax">Tax: {{ preview.currencyIcon }}{{ preview.amounts.tax }}</p>
        <p><strong>Pay now: {{ preview.currencyIcon }}{{ preview.amountDue ?? preview.total }}</strong></p>
      </div>

      <input v-model="coupon" placeholder="Coupon code" />
      <button @click="applyCoupon">Apply</button>

      <p v-if="status" style="color: green">{{ status }}</p>
      <p v-if="error" style="color: red">{{ error }}</p>

      <Payment
        :merchant-data="merchantData"
        @ready-payment-instance="onReadyPaymentInstance"
        @invoice-preview="(event: { invoicePreview: InvoicePreview }) => (preview = event.invoicePreview)"
        @success="status = 'Payment received — access is granted once the webhook arrives.'"
        @fail="(e: SdkEvent) => (error = e.data?.message ?? e.message ?? 'Payment declined')"
        @error="(e: SdkEvent) => (error = e.data?.value?.message ?? e.value?.message ?? 'An error occurred')"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import Payment from "@solidgate/vue-sdk";

interface MerchantData {
  merchant: string;
  signature: string;
  paymentIntent: string;
}

// Subset of the invoicePreview payload used here. Amounts are decimal strings
// in major units ("40.00"), not cents.
interface InvoicePreview {
  total: string;
  amountDue?: string; // newer SDK releases; fall back to total
  currency: string;
  currencyIcon: string;
  amounts?: { subtotal: string; discount: string; tax?: string };
  lineItems: { productPriceId: string; quantity: number; amount: string }[];
}

// Minimal shape of the fail / error event payloads used in the template.
interface SdkEvent {
  message?: string;
  value?: { message?: string };
  data?: { message?: string; value?: { message?: string } };
}

interface UpdateCheckoutSubscriptionData {
  trial?: { type: "free" | "paid"; period: { value: number; unit: "day" | "week" | "month" }; amount?: number; settleInterval?: number };
  metadata?: Record<string, string>;
  description?: string;
}

interface UpdateCheckoutConfig {
  lineItems: { productPriceId: string; quantity: number; description?: string }[];
  discounts?: ({ couponId: string } | { couponCode: string })[];
  subscriptionData?: UpdateCheckoutSubscriptionData;
}

// The published typings may not list updateCheckout yet, so describe the bit
// of the form instance this component uses.
interface CheckoutCapableForm {
  updateCheckout(config: UpdateCheckoutConfig): Promise<{ invoicePreview: InvoicePreview }>;
}

// UpdateCheckoutError details.message can be a string, a string[] or a field map.
function describeCheckoutError(err: any): string {
  const m = err?.details?.message;
  if (Array.isArray(m)) return m.join(", ");
  if (m && typeof m === "object") return Object.values(m).join(", ");
  return m ?? err?.message ?? "Could not update the order";
}

const props = withDefaults(
  defineProps<{
    /** Key of the backend's server-side PLANS map, e.g. "pro_monthly" */
    plan: string;
    /** The plan's price id — used only to rebuild the cart in updateCheckout */
    productPriceId: string;
    /**
     * Subscription mode: the same trial/metadata/description as the server-side
     * plan. updateCheckout REPLACES subscriptionData, so it is re-sent on every
     * call — omitting it would silently drop the trial.
     */
    subscriptionData?: UpdateCheckoutSubscriptionData;
    quantity?: number;
    apiUrl?: string;
  }>(),
  { quantity: 1, apiUrl: "/api/billing-v2/checkout" },
);

const merchantData = ref<MerchantData | null>(null);
const preview = ref<InvoicePreview | null>(null);
const coupon = ref("");
const status = ref("");
const error = ref("");
const loading = ref(false);
let form: CheckoutCapableForm | null = null;

async function initCheckout() {
  loading.value = true;
  error.value = "";
  try {
    const resp = await fetch(props.apiUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ plan: props.plan, quantity: props.quantity }),
    });
    if (!resp.ok) throw new Error((await resp.json()).error || `HTTP ${resp.status}`);
    merchantData.value = await resp.json();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

// The form instance is only needed for updateCheckout.
function onReadyPaymentInstance(instance: unknown) {
  form = instance as CheckoutCapableForm;
}

// Full cart for updateCheckout: every field is replaced, so always send all of it,
// subscriptionData included (omitting it would drop the trial).
function cartWith(couponCode: string | null): UpdateCheckoutConfig {
  return {
    lineItems: [{ productPriceId: props.productPriceId, quantity: props.quantity }],
    discounts: couponCode ? [{ couponCode }] : [],
    ...(props.subscriptionData ? { subscriptionData: props.subscriptionData } : {}),
  };
}
// The cart the form is known to hold (starts as the server-side intent).
let lastGood: UpdateCheckoutConfig | null = null;

async function applyCoupon() {
  if (!form) return;
  error.value = "";
  const next = cartWith(coupon.value || null);
  try {
    const res = await form.updateCheckout(next);
    lastGood = next;
    // updateCheckout does not fire invoicePreview — use the resolved value.
    preview.value = res.invoicePreview;
  } catch (err: any) {
    error.value = describeCheckoutError(err);
    // The cart state is now unknown — put back the last cart that worked
    // (including a coupon applied earlier), or the initial one.
    try {
      preview.value = (await form.updateCheckout(lastGood ?? cartWith(null))).invoicePreview;
    } catch {
      error.value = "Could not update the order — please reload the page.";
    }
  }
}
</script>
