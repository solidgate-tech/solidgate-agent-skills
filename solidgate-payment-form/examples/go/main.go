// Solidgate Payment Form — Go example server
//
// Uses the OFFICIAL github.com/solidgate-tech/go-sdk for merchantData
// generation. The SDK computes the correct HMAC-SHA512 signature over
// the encoded, encrypted paymentIntent — getting that right by hand is
// easy to break.
//
// Endpoints
//
//	GET  /                      Test page with embedded payment form
//	POST /api/payment-intent    Generate merchantData (signed + encrypted)
//	POST /webhook               Receive and verify webhook notifications
//
// Billing v2 (Subscriptions 2.0 / Invoicing) — optional, see ../../billing-v2.md
//
//	POST /api/billing-v2/customers  Create a Billing customer (API v2)
//	POST /api/billing-v2/checkout   merchantData with a `checkout` object
//	POST /api/billing-v2/invoice    merchantData that pays an existing invoice
//	POST /webhook/billing           Receive and verify Billing v2 events
//
// Setup (one-time)
//  1. Get keys from https://hub.solidgate.com/  (Settings → API Keys).
//  2. Export env vars:
//     export SOLIDGATE_PUBLIC_KEY="api_pk_..."
//     export SOLIDGATE_SECRET_KEY="api_sk_..."
//     export SOLIDGATE_WEBHOOK_PUBLIC_KEY="wh_pk_..."
//     export SOLIDGATE_WEBHOOK_SECRET_KEY="wh_sk_..."
//     Billing v2 only (API v2 key + Billing webhook endpoint secret):
//     export SOLIDGATE_API_V2_SECRET="asec_..."
//     export SOLIDGATE_BILLING_WEBHOOK_SECRET="wsec_..."
//     export SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS="wsec_..."   # optional, during rotation
//     export SOLIDGATE_PRO_MONTHLY_PRICE_ID="<recurring price id>"
//     export SOLIDGATE_ONE_TIME_PRICE_ID="<one-time price id>"
//     export SOLIDGATE_CHANNEL_ID="chn_..."            # only for multi-channel API v2 keys
//     export SOLIDGATE_DEMO_CUSTOMER_ID="cust_..."     # demo stand-in for your session lookup
//  3. Initialise a module and add the SDK:
//     go mod init solidgate-form-example
//     go get github.com/solidgate-tech/go-sdk
//
// Run
//
//	go run main.go
//
// Then open http://localhost:3000 — fill the form, use test card
// 4067429974719265 (any future expiry, any CVV).
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	solidgate "github.com/solidgate-tech/go-sdk"
)

var (
	publicKey   = os.Getenv("SOLIDGATE_PUBLIC_KEY")
	secretKey   = os.Getenv("SOLIDGATE_SECRET_KEY")
	whPublicKey = os.Getenv("SOLIDGATE_WEBHOOK_PUBLIC_KEY")
	whSecretKey = os.Getenv("SOLIDGATE_WEBHOOK_SECRET_KEY")

	// Billing v2 — API v2 secret is a Bearer token (no request signing), and
	// the Billing webhook endpoint has its own single signing secret.
	apiV2Secret             = os.Getenv("SOLIDGATE_API_V2_SECRET")
	billingWHSecret         = os.Getenv("SOLIDGATE_BILLING_WEBHOOK_SECRET")
	billingWHSecretPrevious = os.Getenv("SOLIDGATE_BILLING_WEBHOOK_SECRET_PREVIOUS")
	channelID               = os.Getenv("SOLIDGATE_CHANNEL_ID") // needed only for multi-channel API v2 keys
)

const apiV2Base = "https://api.solidgate.com/v2"

// Plans live on the server. The browser sends a plan key; price, mode and trial
// are never taken from the request (a shopper could otherwise grant themselves
// a free year).
type plan struct {
	Mode        string
	PriceID     string
	Description string
	Trial       map[string]any
}

var plans = map[string]plan{
	"pro_monthly": {
		Mode:        "subscription",
		PriceID:     os.Getenv("SOLIDGATE_PRO_MONTHLY_PRICE_ID"),
		Description: "Pro plan (monthly)",
		Trial:       map[string]any{"type": "free", "period": map[string]any{"value": 7, "unit": "day"}},
	},
	"one_time": {
		Mode:        "invoice",
		PriceID:     os.Getenv("SOLIDGATE_ONE_TIME_PRICE_ID"),
		Description: "One-time purchase",
	},
}

type user struct {
	ID                string
	BillingCustomerID string
}

// currentUser is DEMO ONLY: replace with your session lookup. Must return the
// logged-in user, including the Billing customer id ("cust_…") you stored when
// you created the customer via POST /api/billing-v2/customers. Never take it
// from the browser.
func currentUser(_ *http.Request) *user {
	id := os.Getenv("SOLIDGATE_DEMO_CUSTOMER_ID")
	if id == "" {
		return nil
	}
	return &user{ID: "demo-user", BillingCustomerID: id}
}

// sessionUserID is DEMO ONLY: the logged-in user's id from your session.
func sessionUserID(_ *http.Request) string {
	return "demo-user"
}

type pendingCheckout struct {
	UserID string
	Plan   string
}

// DEMO ONLY: persist merchant_reference → user/plan in your DB. Webhooks are
// matched back to the purchase through it (see billing-v2.md § Events).
var (
	pendingCheckoutsMu sync.Mutex
	pendingCheckouts   = map[string]pendingCheckout{}
)

// DEMO ONLY: persist subscription id → user id in your DB (filled on
// SUBSCRIPTION_ACTIVATED / SUBSCRIPTION_TRIAL_ACTIVATED).
var (
	subscriptionUsersMu sync.Mutex
	subscriptionUsers   = map[string]string{}
)

const port = ":3000"

// api is the Solidgate SDK client. The constructor accepts an optional
// base URL pointer; nil falls back to the production endpoint.
var api *solidgate.API

func mustInitAPI() {
	a, err := solidgate.NewAPI(publicKey, secretKey, nil)
	if err != nil {
		log.Fatalf("init Solidgate SDK: %v", err)
	}
	api = a
}

// ============================================================
// Webhook signature — no SDK helper exists, so verify manually.
// Formula:  base64(hex(HMAC-SHA512(wh_secret, wh_public + raw_body + wh_public)))
// ============================================================

func verifyWebhookSignature(rawBody, receivedSignature string) bool {
	data := whPublicKey + rawBody + whPublicKey
	mac := hmac.New(sha512.New, []byte(whSecretKey))
	mac.Write([]byte(data))
	hmacHex := hex.EncodeToString(mac.Sum(nil))
	expected := base64.StdEncoding.EncodeToString([]byte(hmacHex))
	return hmac.Equal([]byte(expected), []byte(receivedSignature))
}

// ============================================================
// Billing v2 webhook signature — different scheme from the one above.
// Formula:  base64(HMAC-SHA256(endpoint_secret, raw_body))   (no hex step)
// ============================================================

// During secret rotation Solidgate sends TWO `signature` headers (new secret
// first), so accept the event if ANY received signature matches the current
// secret or the optional previous one.
func verifyBillingWebhookSignature(rawBody []byte, receivedSignatures []string) bool {
	secrets := []string{billingWHSecret}
	if billingWHSecretPrevious != "" {
		secrets = append(secrets, billingWHSecretPrevious)
	}
	for _, secret := range secrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(rawBody)
		expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		for _, received := range receivedSignatures {
			if hmac.Equal([]byte(expected), []byte(received)) {
				return true
			}
		}
	}
	return false
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// ============================================================
// Endpoints
// ============================================================

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

// handlePaymentIntent uses the official SDK's FormMerchantData to build
// the merchantData object. We marshal our intent to bytes, hand it to
// the SDK, and the SDK returns a FormInitDTO whose fields map straight
// to the {merchant, signature, paymentIntent} object the frontend expects.
func handlePaymentIntent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Amount           int    `json:"amount"`
		Currency         string `json:"currency"`
		OrderID          string `json:"order_id"`
		OrderDescription string `json:"order_description"`
		CustomerEmail    string `json:"customer_email,omitempty"`
		ProductID        string `json:"product_id,omitempty"`
		PaymentType      string `json:"payment_type,omitempty"`
		IPAddress        string `json:"ip_address,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Amount == 0 || req.Currency == "" || req.OrderID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "amount, currency, and order_id are required"})
		return
	}

	// Build the intent map. The SDK accepts JSON bytes — preserve any
	// optional fields the caller passed.
	intent := map[string]interface{}{
		"amount":            req.Amount,
		"currency":          req.Currency,
		"order_id":          req.OrderID,
		"order_description": req.OrderDescription,
		"platform":          "WEB",
	}
	if req.CustomerEmail != "" {
		intent["customer_email"] = req.CustomerEmail
	}
	if req.ProductID != "" {
		intent["product_id"] = req.ProductID
	}
	if req.PaymentType != "" {
		intent["payment_type"] = req.PaymentType
	}
	if req.IPAddress != "" {
		intent["ip_address"] = req.IPAddress
	}

	jsonBytes, err := json.Marshal(intent)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal intent"})
		return
	}
	dto, err := api.FormMerchantData(jsonBytes)
	if err != nil {
		log.Printf("[ERROR] FormMerchantData: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merchantData generation failed"})
		return
	}

	log.Printf("[DEBUG] Generated merchantData for order_id=%s", req.OrderID)
	writeJSON(w, http.StatusOK, map[string]string{
		"merchant":      dto.Merchant,
		"signature":     dto.Signature,
		"paymentIntent": dto.PaymentIntent,
	})
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	signature := r.Header.Get("signature")
	if signature == "" {
		http.Error(w, "Missing signature header", http.StatusBadRequest)
		return
	}
	if !verifyWebhookSignature(string(body), signature) {
		log.Println("[ERROR] Invalid webhook signature")
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	eventType := r.Header.Get("solidgate-event-type")
	eventID := r.Header.Get("solidgate-event-id")
	log.Printf("[DEBUG] Webhook [%s] (%s)", eventType, eventID)

	var event map[string]interface{}
	_ = json.Unmarshal(body, &event)
	// Add business logic here. Decline info is at top-level event["error"]
	// (sibling of order/transactions), NOT inside event["order"].

	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "OK")
}

// ============================================================
// Billing v2 (Subscriptions 2.0 / Invoicing)
// ============================================================

var billingHTTP = &http.Client{Timeout: 30 * time.Second}

// callAPIV2 calls API v2. It returns the HTTP status and the decoded JSON body;
// a non-JSON error page becomes {"error": "<first 500 chars>"}. A network
// failure is returned as an error (the routes answer 502).
func callAPIV2(ctx context.Context, path string, payload any, headers map[string]string) (int, map[string]any, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiV2Base+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiV2Secret)
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := billingHTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	text, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(text, &body); err != nil || body == nil {
		s := []rune(string(text))
		if len(s) > 500 {
			s = s[:500]
		}
		body = map[string]any{"error": string(s)}
	}
	return resp.StatusCode, body, nil
}

// formMerchantData signs the intent with the SDK (API v1 keys) and returns the
// {merchant, signature, paymentIntent} object the frontend expects.
func formMerchantData(intent map[string]any) (map[string]string, error) {
	jsonBytes, err := json.Marshal(intent)
	if err != nil {
		return nil, err
	}
	dto, err := api.FormMerchantData(jsonBytes)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"merchant":      dto.Merchant,
		"signature":     dto.Signature,
		"paymentIntent": dto.PaymentIntent,
	}, nil
}

// clientIP returns the caller's socket address. Behind a proxy/load balancer
// this is the proxy's address — use the client IP from your trusted proxy
// header instead.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	return host
}

// handleBillingCreateCustomer creates a Billing customer once per end user.
// Store the returned id ("cust_…"): every checkout references it as
// checkout.customer_id.
func handleBillingCreateCustomer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if apiV2Secret == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "SOLIDGATE_API_V2_SECRET is not set"})
		return
	}
	// In production, create the customer for the logged-in user (signup) and
	// store the returned id on that user — don't expose this route publicly.
	var req struct {
		Email             string          `json:"email"`
		FirstName         string          `json:"first_name,omitempty"`
		LastName          string          `json:"last_name,omitempty"`
		MerchantReference string          `json:"merchant_reference,omitempty"`
		Address           json.RawMessage `json:"address,omitempty"` // country: ISO 3166-1 alpha-3
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}

	// Derived server-side from the session; any client-sent value is ignored.
	req.MerchantReference = "user-" + sessionUserID(r)
	headers := map[string]string{
		// Safe retries: the same key within 24h returns the first result.
		"Idempotency-Key": "customer-" + req.MerchantReference,
	}
	status, body, err := callAPIV2(r.Context(), "/customers/create", req, headers)
	if err != nil {
		log.Printf("[ERROR] Billing API unreachable: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Billing API unreachable"})
		return
	}
	writeJSON(w, status, body) // { "id": "cust_…", ... } or { code, message, context }
}

// handleBillingCheckout returns merchantData for a Billing v2 checkout.
// Body: { plan, quantity?, coupon_code? }. No amount/currency/product_id/
// customer_account_id: Billing prices the cart.
func handleBillingCheckout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in / no Billing customer"})
		return
	}
	var req struct {
		Plan       string `json:"plan"`
		Quantity   int    `json:"quantity"`
		CouponCode string `json:"coupon_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	p, ok := plans[req.Plan]
	if !ok || p.PriceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown plan"})
		return
	}

	quantity := 1
	if p.Mode == "invoice" && req.Quantity > 1 {
		quantity = req.Quantity
		if quantity > 10 {
			quantity = 10
		}
	}
	// Unique per purchase within the channel; letters, digits, "_" and "-" only.
	merchantReference := p.Mode + "-" + newID()
	checkout := map[string]any{
		"mode":               p.Mode,
		"customer_id":        u.BillingCustomerID,
		"merchant_reference": merchantReference,
		"line_items": []map[string]any{
			{"product_price_id": p.PriceID, "quantity": quantity},
		},
	}
	if req.CouponCode != "" {
		checkout["discounts"] = []map[string]string{{"coupon_code": req.CouponCode}}
	}
	if p.Mode == "subscription" && p.Trial != nil {
		checkout["subscription_data"] = map[string]any{"trial": p.Trial}
	}

	intent := map[string]any{
		"order_id":          "ord-" + newID(),
		"order_description": p.Description,
		"platform":          "WEB",
		"checkout":          checkout,
	}
	if ip := clientIP(r); ip != "" {
		intent["ip_address"] = ip
	}

	pendingCheckoutsMu.Lock()
	pendingCheckouts[merchantReference] = pendingCheckout{UserID: u.ID, Plan: req.Plan}
	pendingCheckoutsMu.Unlock()

	// Same SDK call as one-time payments — signed with the API v1 keys.
	merchantData, err := formMerchantData(intent)
	if err != nil {
		log.Printf("[ERROR] FormMerchantData: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merchantData generation failed"})
		return
	}
	log.Printf("[DEBUG] Billing v2 checkout: plan=%s merchant_reference=%s", req.Plan, merchantReference)
	writeJSON(w, http.StatusOK, merchantData)
}

// handleBillingInvoice returns merchantData that collects payment for an
// invoice already issued via API v2 (finalized; status OPEN / DUNNING /
// UNPAID). Body: { invoice_id }. Response: { merchantData, amountDue, currency }
// — show the amount yourself: invoice_id intents emit no invoicePreview.
func handleBillingInvoice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if apiV2Secret == "" {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "SOLIDGATE_API_V2_SECRET is not set"})
		return
	}
	u := currentUser(r)
	if u == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "not logged in / no Billing customer"})
		return
	}
	var req struct {
		InvoiceID string `json:"invoice_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.InvoiceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invoice_id is required"})
		return
	}

	// The invoice's customer, email and address end up in the form, so only the
	// invoice's own customer may open it.
	payload := map[string]any{"id": req.InvoiceID}
	if channelID != "" {
		payload["channel_id"] = channelID
	}
	status, body, err := callAPIV2(r.Context(), "/invoices/get", payload, nil)
	if err != nil {
		log.Printf("[ERROR] Billing API unreachable: %v", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Billing API unreachable"})
		return
	}
	if status == http.StatusNotFound {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invoice not found"})
		return
	}
	if status != http.StatusOK {
		log.Printf("[ERROR] Billing API /invoices/get returned HTTP %d", status)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "Billing API error"})
		return
	}
	invoice := body
	if inner, ok := body["invoice"].(map[string]any); ok {
		invoice = inner
	}
	owner, _ := invoice["customer_id"].(string)
	if c, ok := invoice["customer"].(map[string]any); ok {
		if id, ok := c["id"].(string); ok {
			owner = id
		}
	}
	if owner != u.BillingCustomerID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invoice not found"})
		return
	}
	invStatus, _ := invoice["status"].(string)
	if invStatus != "OPEN" && invStatus != "DUNNING" && invStatus != "UNPAID" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("invoice is %s, not payable", invStatus)})
		return
	}

	invoiceID, _ := invoice["id"].(string)
	intent := map[string]any{
		"order_id":          "ord-" + newID(),
		"order_description": "Invoice " + invoiceID,
		"platform":          "WEB",
		"invoice_id":        invoiceID, // never combine with checkout
	}
	if ip := clientIP(r); ip != "" {
		intent["ip_address"] = ip
	}
	merchantData, err := formMerchantData(intent)
	if err != nil {
		log.Printf("[ERROR] FormMerchantData: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "merchantData generation failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"merchantData": merchantData,
		"amountDue":    invoice["amount_due"], // minor units
		"currency":     invoice["currency"],
	})
}

// Billing v2 events: { event_id, event_type, occurred_at, data }.
// Deliveries can repeat and arrive out of order: deduplicate on event_id, and
// mark an event processed only AFTER the handler succeeded — otherwise a failed
// handler loses the event for good. Non-2xx makes Solidgate redeliver.
var (
	processedBillingEventsMu sync.Mutex
	processedBillingEvents   = map[string]bool{} // use your DB in production (keep >= 1 week)
)

type billingEvent struct {
	EventID   string `json:"event_id"`
	EventType string `json:"event_type"`
	Data      struct {
		// Subscription events: data.subscription.
		Subscription struct {
			ID                string `json:"id"`
			Status            string `json:"status"`
			MerchantReference string `json:"merchant_reference"`
			CustomerID        string `json:"customer_id"`
			NextBillingAt     string `json:"next_billing_at"`
			CancellationInfo  struct {
				Reason string `json:"reason"`
			} `json:"cancellation_info"`
			LatestInvoiceID string         `json:"latest_invoice_id"`
			TrialInfo       map[string]any `json:"trial_info"`
		} `json:"subscription"`
		// Invoice events nest the payload: data.invoice / data.invoice_payment.
		Invoice struct {
			ID                string `json:"id"`
			MerchantReference string `json:"merchant_reference"`
			SubscriptionID    string `json:"subscription_id"`
			BillingReason     string `json:"billing_reason"`
		} `json:"invoice"`
		InvoicePayment struct {
			PaymentID string `json:"payment_id"`
		} `json:"invoice_payment"`
	} `json:"data"`
}

func handleBillingEvent(event billingEvent) error {
	inv := event.Data.Invoice
	sub := event.Data.Subscription
	subUser := func(id string) string {
		subscriptionUsersMu.Lock()
		defer subscriptionUsersMu.Unlock()
		return subscriptionUsers[id]
	}
	switch event.EventType {
	case "SUBSCRIPTION_ACTIVATED", "SUBSCRIPTION_TRIAL_ACTIVATED":
		pendingCheckoutsMu.Lock()
		purchase, ok := pendingCheckouts[sub.MerchantReference]
		pendingCheckoutsMu.Unlock()
		if !ok {
			log.Printf("Subscription %s: unknown merchant_reference %q, ignoring", sub.ID, sub.MerchantReference)
			break
		}
		subscriptionUsersMu.Lock()
		subscriptionUsers[sub.ID] = purchase.UserID
		subscriptionUsersMu.Unlock()
		if event.EventType == "SUBSCRIPTION_TRIAL_ACTIVATED" {
			log.Printf("Grant access (trial) for user %s", purchase.UserID)
		} else {
			log.Printf("Grant access for user %s", purchase.UserID)
		}
	case "SUBSCRIPTION_RENEWED":
		log.Printf("Extend access for user %s", subUser(sub.ID))
	case "SUBSCRIPTION_UNPAID", "SUBSCRIPTION_EXPIRED":
		log.Printf("Revoke access for user %s", subUser(sub.ID))
	case "SUBSCRIPTION_CANCELLED":
		log.Printf("Revoke access for user %s (reason: %s)", subUser(sub.ID), sub.CancellationInfo.Reason)
	case "INVOICE_PAID":
		// billing_reason casing differs across docs — compare case-insensitively.
		reason := strings.ToUpper(inv.BillingReason)
		if inv.SubscriptionID != "" {
			// Subscription invoice: only renewals need action here; access is granted
			// on SUBSCRIPTION_ACTIVATED / SUBSCRIPTION_TRIAL_ACTIVATED.
			if reason == "SUBSCRIPTION_CYCLE" {
				log.Printf("Extend access for user %s", subUser(inv.SubscriptionID))
			}
		} else {
			// One-time invoice (checkout mode "invoice" or invoice_id): match by
			// merchant_reference or invoice id, then fulfil.
			pendingCheckoutsMu.Lock()
			purchase, ok := pendingCheckouts[inv.MerchantReference]
			pendingCheckoutsMu.Unlock()
			userID := "?"
			if ok {
				userID = purchase.UserID
			}
			log.Printf("Invoice %s paid (ref=%s, user=%s) — fulfil", inv.ID, inv.MerchantReference, userID)
		}
		// Entitlements come from what was paid, not from what the page asked for:
		// updateCheckout runs in the browser. Check invoice.line_items[].product_price_id.
	case "INVOICE_PAYMENT_FAILED":
		log.Printf("Payment %s failed — ask the customer to update the payment method", event.Data.InvoicePayment.PaymentID)
	case "INVOICE_UNPAID":
		if inv.SubscriptionID != "" {
			log.Printf("Subscription invoice %s unpaid (SUBSCRIPTION_UNPAID revokes access)", inv.ID)
		} else {
			log.Printf("Mark invoice %s unpaid", inv.ID)
		}
	}
	return nil
}

func handleBillingWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if billingWHSecret == "" {
		http.Error(w, "Billing webhook secret not set", http.StatusInternalServerError)
		return
	}
	body, err := io.ReadAll(r.Body) // raw bytes — never re-serialize
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	var signatures []string
	for _, v := range r.Header.Values("signature") {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				signatures = append(signatures, s)
			}
		}
	}
	if len(signatures) == 0 {
		http.Error(w, "Missing signature header", http.StatusBadRequest)
		return
	}
	if !verifyBillingWebhookSignature(body, signatures) {
		log.Println("[ERROR] Invalid Billing webhook signature")
		http.Error(w, "Invalid signature", http.StatusBadRequest)
		return
	}

	var event billingEvent
	if err := json.Unmarshal(body, &event); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	processedBillingEventsMu.Lock()
	done := processedBillingEvents[event.EventID]
	processedBillingEventsMu.Unlock()
	if done {
		fmt.Fprint(w, "OK")
		return
	}

	// Kept synchronous for the demo. In production, durably enqueue the event here,
	// return 200, and let the worker apply the same "mark after success" rule.
	log.Printf("[DEBUG] Billing event [%s] (%s)", event.EventType, event.EventID)
	if err := handleBillingEvent(event); err != nil {
		log.Printf("[ERROR] Billing event handler failed: %v", err)
		http.Error(w, "Retry later", http.StatusInternalServerError)
		return
	}
	processedBillingEventsMu.Lock()
	processedBillingEvents[event.EventID] = true
	processedBillingEventsMu.Unlock()
	fmt.Fprint(w, "OK")
}

func main() {
	if publicKey == "" || secretKey == "" {
		log.Fatal("SOLIDGATE_PUBLIC_KEY and SOLIDGATE_SECRET_KEY must be set.\n" +
			"  export SOLIDGATE_PUBLIC_KEY=\"api_pk_...\"\n" +
			"  export SOLIDGATE_SECRET_KEY=\"api_sk_...\"")
	}
	mustInitAPI()

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/payment-intent", handlePaymentIntent)
	http.HandleFunc("/webhook", handleWebhook)
	http.HandleFunc("/api/billing-v2/customers", handleBillingCreateCustomer)
	http.HandleFunc("/api/billing-v2/checkout", handleBillingCheckout)
	http.HandleFunc("/api/billing-v2/invoice", handleBillingInvoice)
	http.HandleFunc("/webhook/billing", handleBillingWebhook)

	log.Printf("Server running on http://localhost%s", port)
	log.Fatal(http.ListenAndServe(port, nil))
}

const indexHTML = `<!DOCTYPE html>
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
</html>`
