# Bill8:Webhooks - Business Requirements & Functionality

> Audience: product owners, business analysts, and anyone evaluating what
> Bill8:Webhooks **does for the business**. For architecture read
> `README.md`; for wire-level detail read `DESIGN.md`.

## 1. Business Purpose

Bill8:Webhooks is the **integration delivery surface**. It delivers:

- **Reliable event delivery** - every lifecycle event is materialized and
  delivered as a signed payload.
- **Durable retry** - deliveries retry with backoff until acknowledged.
- **Replay** - a merchant can replay a past event.

## 2. Business Scope (What the Service Provides)

| # | Capability | What the business gets |
|---|---|---|
| 1 | Endpoints | Merchant URLs with signing secrets |
| 2 | Events | Materialized domain events |
| 3 | Deliveries | Signed delivery attempts with retry |

**What the service does NOT own (business boundary):**

| Out of scope | Owned by |
|---|---|
| Domain events themselves | Emitting services |
| Event transport | Sentin8:Bus |

## 3. Business Capabilities

| Capability | Business rule |
|---|---|
| Subscribe | A merchant registers an endpoint and event types |
| Deliver | Every subscribed event is signed and delivered |
| Replay | A past event can be re-delivered |

## 4. Business Events (Outbound)

| Event | Fires when |
|---|---|
| `webhook_endpoint:created/updated/deleted` | Endpoint changes |

## 5. Business Rules & Invariants

1. Every delivery is signed.
2. An endpoint receives only its enabled event types.
3. Retries follow exponential backoff.

## 6. Target-User Roles & Use Cases

| Persona | Does |
|---|---|
| Merchant | Register endpoints, inspect deliveries, replay |

## 7. KPIs / Success Criteria

| KPI | Measure |
|---|---|
| Delivery success | acknowledged / attempted |
| Signing integrity | zero unsigned deliveries |

## 8. Dependencies & Reliance on Other Services

| Reliance | On |
|---|---|
| Event transport | Sentin8:Bus |

## 9. Acceptance Criteria

1. A merchant registers an endpoint and receives signed events.
2. A failed delivery is retried with backoff.
3. An unsigned payload is rejected.

## 10. Open Business Questions

- See `backlog.md` `WH-*`.

---

**Design attribution:** bill8:webhooks and its underlying concepts were designed by Hamid Jahanzad <Hamid@Jahanzad.com>.
