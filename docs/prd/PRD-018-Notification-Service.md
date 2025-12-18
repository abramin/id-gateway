# PRD-018: Notification Service

**Status:** Not Started
**Priority:** P0 (Critical)
**Owner:** Engineering Team
**Dependencies:** PRD-001 (Authentication), PRD-002 (Consent)

---

## 1. Overview

### Problem Statement

The system has no way to communicate with users outside of synchronous API responses. This blocks critical user flows:

- Email verification for account security
- MFA (OTP delivery via email/SMS)
- Account recovery (password reset links)
- Security alerts (suspicious login, password changed)
- Consent expiry notifications
- Partner webhook callbacks for event-driven integrations

### Goals

- Email delivery (transactional: welcome, verification, alerts)
- SMS delivery (OTP, security alerts)
- Webhook callbacks for partner integrations
- Notification templates with i18n support
- Delivery tracking & retry logic
- Unsubscribe management

### Non-Goals

- Marketing emails / newsletters
- Push notifications (mobile apps) - future
- In-app notifications
- Email campaigns / bulk sending

---

## 2. Functional Requirements

### FR-1: Email Delivery

**Provider Integration:** SendGrid, AWS SES, or Mailgun

**Email Types:**

| Type                   | Trigger               | Priority | Example                          |
| ---------------------- | --------------------- | -------- | -------------------------------- |
| **Welcome**            | User registration     | Low      | "Welcome to Credo"               |
| **Email Verification** | Account creation      | High     | "Verify your email"              |
| **Password Reset**     | Forgot password       | High     | "Reset your password"            |
| **Security Alert**     | Suspicious login      | Critical | "Unusual login detected"         |
| **MFA OTP**            | 2FA challenge         | Critical | "Your verification code: 123456" |
| **Consent Expiry**     | Consent expires in 7d | Medium   | "Your consent will expire soon"  |
| **Session Revoked**    | Admin action          | High     | "Your session was revoked"       |

**Interface:**

```go
type EmailNotifier interface {
    Send(ctx context.Context, email *Email) error
    SendTemplate(ctx context.Context, template string, recipient string, data map[string]interface{}) error
}

type Email struct {
    To          string
    From        string
    Subject     string
    Body        string
    BodyHTML    string
    ReplyTo     string
    TemplateID  string
    TemplateData map[string]interface{}
}
```

**Security (OWASP Forgot Password & Authentication Cheat Sheets):**

- Email domain must enforce SPF, DKIM, and DMARC; use subdomains dedicated to auth (`auth.example.com`).
- Do not include passwords or shared secrets in messages; OTPs and reset links must have short TTL (≤15 minutes) and single-use tokens.
- Templates include clear issuer name and anti-phishing copy; avoid clickable links for OTP delivery (numeric codes only) where possible.
- Sign reset and verification URLs with HMAC + expiration and avoid leaking whether an account exists (generic language).

### FR-2: SMS Delivery

**Provider Integration:** Twilio, AWS SNS

**SMS Types:**

| Type                 | Trigger            | Max Length | Example                            |
| -------------------- | ------------------ | ---------- | ---------------------------------- |
| **MFA OTP**          | 2FA challenge      | 160 chars  | "Your Credo code: 123456"          |
| **Security Alert**   | Account compromise | 160 chars  | "Security alert: Password changed" |
| **Account Recovery** | Forgot password    | 160 chars  | "Reset code: 789012"               |

**Interface:**

```go
type SMSNotifier interface {
    Send(ctx context.Context, phoneNumber string, message string) error
}
```

**Security (OWASP MFA & SMS Guidelines):**

- OTP messages exclude PII and links; include sender brand and expiry (≤5 minutes) to reduce phishing risk.
- Enforce per-recipient throttling (5 messages/hour, 10/day) and randomize OTP codes with cryptographic RNG.
- Use short codes/alphanumeric sender IDs to prevent spoofing where supported; log delivery failures and suspected SIM-swap indicators.

### FR-3: Webhook Callbacks

**Use Cases:**

- Notify partners of consent changes
- Notify partners of decision outcomes
- Notify partners of VC issuance

**Webhook Event Format:**

```json
{
  "event_id": "evt_abc123",
  "event_type": "consent.granted",
  "timestamp": "2025-12-12T10:00:00Z",
  "webhook_url": "https://partner.example.com/webhooks/credo",
  "data": {
    "user_id": "user_123",
    "purposes": ["registry_check"],
    "granted_at": "2025-12-12T10:00:00Z"
  },
  "signature": "sha256=..." // HMAC signature for verification
}
```

**Interface:**

```go
type WebhookNotifier interface {
    Send(ctx context.Context, webhook *Webhook) error
    Verify(payload []byte, signature string, secret string) bool
}

type Webhook struct {
    URL     string
    Event   Event
    Secret  string // For HMAC signature
    Retries int
}
```

### FR-4: Template Management

**Templates stored in:** `internal/platform/notify/templates/`

**Template Variables:**

```
{{.UserName}}
{{.Email}}
{{.VerificationLink}}
{{.OTPCode}}
{{.ExpiresAt}}
```

**Example Template (email-verification.html):**

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>Verify Your Email</h1>
    <p>Hi {{.UserName}},</p>
    <p>Click the link below to verify your email address:</p>
    <a href="{{.VerificationLink}}">Verify Email</a>
    <p>This link expires in 24 hours.</p>
  </body>
</html>
```

### FR-5: Delivery Tracking

**Store notification events:**

```go
type NotificationLog struct {
    ID          string
    Type        string // "email", "sms", "webhook"
    Recipient   string
    Status      string // "pending", "sent", "failed", "bounced"
    Provider    string // "sendgrid", "twilio"
    ProviderID  string // External message ID
    SentAt      *time.Time
    FailedAt    *time.Time
    ErrorMsg    string
    RetryCount  int
    CreatedAt   time.Time
}
```

### FR-6: Retry Logic

**Retry Strategy:**

- **Email:** 3 retries with exponential backoff (1m, 5m, 30m)
- **SMS:** 2 retries with exponential backoff (1m, 5m)
- **Webhook:** 5 retries with exponential backoff (1m, 5m, 30m, 2h, 24h)

**Dead Letter Queue:**

- After max retries, move to DLQ for manual review

---

## 3. Technical Requirements

### TR-1: Notification Service Interface

```go
type NotificationService interface {
    SendEmail(ctx context.Context, email *Email) error
    SendSMS(ctx context.Context, phone, message string) error
    SendWebhook(ctx context.Context, webhook *Webhook) error

    // Template-based sending
    SendEmailTemplate(ctx context.Context, template, recipient string, data map[string]interface{}) error
}
```

### TR-2: Provider Abstractions

```go
// Email Provider
type EmailProvider interface {
    Send(ctx context.Context, email *Email) (providerID string, err error)
}

// Implementations
type SendGridProvider struct { apiKey string }
type AWSMailProvider struct { sesClient *ses.Client }

// SMS Provider
type SMSProvider interface {
    Send(ctx context.Context, phone, message string) (providerID string, err error)
}

// Implementations
type TwilioProvider struct { accountSID, authToken string }
type AWSSNSProvider struct { snsClient *sns.Client }
```

### TR-3: Async Notification Queue

- Use buffered per-channel queues (email/sms/webhook) with configurable worker counts and rate limits per provider/channel.
- Workers run with shared `context.Context`, enforce retry/backoff, and drain queues on shutdown; publish metrics for queue depth, drops, and per-provider latency.
- Keep handlers thin: enqueue notification requests and return; orchestration (templating, routing, retries) lives in the service/queue layer.

---

## 4. Implementation Steps

### Phase 1: Email Integration (4-5 hours)

1. Integrate SendGrid/SES
2. Create email templates
3. Implement EmailService
4. Add async queue with workers
5. Test email delivery

### Phase 2: SMS Integration (3-4 hours)

1. Integrate Twilio/SNS
2. Implement SMSService
3. Add SMS worker
4. Test SMS delivery

### Phase 3: Webhooks (3-4 hours)

1. Implement webhook delivery
2. Add HMAC signature
3. Implement retry logic
4. Test webhook callbacks

---

## 5. Acceptance Criteria

- [ ] Emails delivered via SendGrid/SES
- [ ] SMS delivered via Twilio/SNS
- [ ] Webhooks delivered with HMAC signatures
- [ ] Templates support variable substitution
- [ ] Failed notifications retry with backoff
- [ ] Delivery status tracked in database
- [ ] Unsubscribe links work
- [ ] Rate limits prevent spam

---

## 6. API Examples

### Send Email

```go
err := notifier.SendEmailTemplate(ctx, "email-verification", "user@example.com", map[string]interface{}{
    "UserName": "Alice",
    "VerificationLink": "https://app.example.com/verify?token=abc123",
})
```

### Send SMS

```go
err := notifier.SendSMS(ctx, "+14155551234", "Your Credo verification code: 123456")
```

### Send Webhook

```go
webhook := &Webhook{
    URL: "https://partner.example.com/webhook",
    Event: Event{
        Type: "consent.granted",
        Data: map[string]interface{}{"user_id": "user_123"},
    },
    Secret: "webhook_secret_key",
}
err := notifier.SendWebhook(ctx, webhook)
```

---

## Revision History

| Version | Date       | Author       | Changes                                                                                     |
| ------- | ---------- | ------------ | ------------------------------------------------------------------------------------------- |
| 1.2     | 2025-12-16 | Engineering  | Define async worker-pool queue per channel with metrics/backpressure and handler boundaries |
| 1.1     | 2025-12-12 | Product Team | Added OWASP-aligned OTP handling, throttling, and anti-phishing controls                    |
| 1.0     | 2025-12-12 | Product Team | Initial PRD                                                                                 |
