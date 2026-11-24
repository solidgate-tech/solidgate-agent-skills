// Solidgate Payment Form — React Billing v2 checkout (Subscriptions 2.0 / Invoicing)
//
// Renders the Payment Form for a Billing v2 `checkout` intent, shows the order
// summary from the `invoicePreview` event, and applies a coupon with
// `form.updateCheckout()`. See ../../billing-v2.md.
//
// Setup (one-time)
//   1. Run one of the backends in this repo with the Billing v2 env vars set —
//      it exposes POST /api/billing-v2/checkout (and /api/billing-v2/customers).
//   2. Create a Billing customer once per user at signup and store its id
//      ("cust_…") on the user. The backend reads it from the session; the browser
//      never sends a customer id.
//   3. npm install @solidgate/react-sdk
//
// Usage
//   <BillingCheckout
//     plan="pro_monthly"
//     productPriceId="3f8b2a8e-6c1d-4f7e-9a51-2b0d6f1c9e44"
//     subscriptionData={{ trial: { type: "free", period: { value: 7, unit: "day" } } }}
//   />
//
// `plan` is a key of the backend's server-side PLANS map (price, mode and trial
// are decided there). `productPriceId` is only needed for form.updateCheckout,
// which runs in the browser — so grant entitlements from the paid invoice in the
// webhook, never from what this page asked for.
//
// Grant access from the SUBSCRIPTION_ACTIVATED / INVOICE_PAID webhooks, not from
// the frontend `success` event.

import { useCallback, useRef, useState } from "react";
import Payment from "@solidgate/react-sdk";

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

// Minimal shape of the fail / error event payloads used below.
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

interface BillingCheckoutProps {
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
}

export default function BillingCheckout({
  plan,
  productPriceId,
  subscriptionData,
  quantity = 1,
  apiUrl = "/api/billing-v2/checkout",
}: BillingCheckoutProps) {
  const [merchantData, setMerchantData] = useState<MerchantData | null>(null);
  const [preview, setPreview] = useState<InvoicePreview | null>(null);
  const [coupon, setCoupon] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const formRef = useRef<CheckoutCapableForm | null>(null);

  const initCheckout = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const resp = await fetch(apiUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan, quantity }),
      });
      if (!resp.ok) throw new Error((await resp.json()).error || `HTTP ${resp.status}`);
      setMerchantData(await resp.json());
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [apiUrl, plan, quantity]);

  // The form instance is only needed for updateCheckout.
  const handleReady = useCallback((form: unknown) => {
    formRef.current = form as CheckoutCapableForm;
  }, []);

  // Full cart for updateCheckout: every field is replaced, so always send all of it,
  // subscriptionData included (omitting it would drop the trial).
  const cartWith = useCallback(
    (couponCode: string | null): UpdateCheckoutConfig => ({
      lineItems: [{ productPriceId, quantity }],
      discounts: couponCode ? [{ couponCode }] : [],
      ...(subscriptionData && { subscriptionData }),
    }),
    [productPriceId, quantity, subscriptionData],
  );
  // The cart the form is known to hold (starts as the server-side intent).
  const lastGoodRef = useRef<UpdateCheckoutConfig | null>(null);

  const applyCoupon = useCallback(async () => {
    const form = formRef.current;
    if (!form) return;
    setError("");
    const next = cartWith(coupon || null);
    try {
      const { invoicePreview } = await form.updateCheckout(next);
      lastGoodRef.current = next;
      // updateCheckout does not fire invoicePreview — use the resolved value.
      setPreview(invoicePreview);
    } catch (err: any) {
      setError(describeCheckoutError(err));
      // The cart state is now unknown — put back the last cart that worked
      // (including a coupon applied earlier), or the initial one.
      try {
        const { invoicePreview } = await form.updateCheckout(lastGoodRef.current ?? cartWith(null));
        setPreview(invoicePreview);
      } catch {
        setError("Could not update the order — please reload the page.");
      }
    }
  }, [coupon, cartWith]);

  if (!merchantData) {
    return (
      <div>
        <button onClick={initCheckout} disabled={loading}>
          {loading ? "Loading..." : "Subscribe"}
        </button>
        {error && <p style={{ color: "red" }}>{error}</p>}
      </div>
    );
  }

  return (
    <div>
      {preview && (
        <div>
          <p>
            Subtotal: {preview.currencyIcon}
            {preview.amounts?.subtotal ?? preview.total}
          </p>
          {preview.amounts?.discount && preview.amounts.discount !== "0.00" && (
            <p>
              Discount: −{preview.currencyIcon}
              {preview.amounts.discount}
            </p>
          )}
          {preview.amounts?.tax && (
            <p>
              Tax: {preview.currencyIcon}
              {preview.amounts.tax}
            </p>
          )}
          <p>
            <strong>
              Pay now: {preview.currencyIcon}
              {preview.amountDue ?? preview.total}
            </strong>
          </p>
        </div>
      )}

      <input value={coupon} onChange={(e) => setCoupon(e.target.value)} placeholder="Coupon code" />
      <button onClick={applyCoupon}>Apply</button>

      {status && <p style={{ color: "green" }}>{status}</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}

      <Payment
        merchantData={merchantData}
        onReadyPaymentInstance={handleReady}
        onInvoicePreview={(event: { invoicePreview: InvoicePreview }) => setPreview(event.invoicePreview)}
        onSuccess={() => setStatus("Payment received — access is granted once the webhook arrives.")}
        onFail={(e: SdkEvent) => setError(e.data?.message ?? e.message ?? "Payment declined")} // fail: { code, message }
        onError={(e: SdkEvent) => setError(e.data?.value?.message ?? e.value?.message ?? "An error occurred")}
      />
    </div>
  );
}
