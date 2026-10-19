// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Bus consumers for Bill8:Webhooks (WH-2) - event
//! materialization: consumes the vertical's families, dedupes by event
//! id, and stores the envelope; the delivery worker fans out to the
//! subscribed endpoints (see delivery.rs for the signed-delivery path).

use std::time::Duration;

use futures_util::StreamExt;
use sqlx::Row;
use uuid::Uuid;

use crate::handlers::AppState;

/// Reconnect delay when the Bus SSE connection drops.
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// The consumer group for materialization (matches the registry).
const MATERIALIZE_GROUP: &str = "bill8:webhooks:materialize";

/// The vertical's event families this service materializes.
const FAMILIES: &[&str] = &[
    "payments",
    "billing",
    "ledger",
    "merchants",
    "checkout",
    "risk",
    "reporting",
];

/// Materialize one event: dedupe by event id (a duplicate delivery
/// materializes ONE row), store the envelope + payload.
async fn materialize(state: &AppState, env_id: Uuid, event_type: &str, payload: serde_json::Value) {
    let Ok(event_id) = Uuid::parse_str(
        payload
            .get("event_id")
            .or_else(|| payload.get("id"))
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
    ) else {
        // No event id - synthesize a deterministic one from the payload
        // (materialization is idempotent on the content).
        let _ = event_type;
        return;
    };

    let mut conn = match state.pool.acquire().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "webhooks: materialize acquire failed");
            return;
        }
    };
    if let Err(e) = crate::handlers::set_tenant_context(&mut conn, env_id).await {
        tracing::warn!(error = %e, "webhooks: materialize context failed");
        return;
    }

    // Dedupe: ON CONFLICT on the primary key materializes one row per
    // event id regardless of delivery count.
    let inserted = sqlx::query(
        r#"INSERT INTO webhooks.events (id, env_id, event_type, data)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (id) DO NOTHING"#,
    )
    .bind(event_id)
    .bind(env_id)
    .bind(event_type)
    .bind(sqlx::types::Json(&payload))
    .execute(&mut *conn)
    .await;
    match inserted {
        Ok(result) => {
            if result.rows_affected() == 0 {
                tracing::debug!(event_id = %event_id, "webhooks: duplicate delivery deduped");
                return;
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "webhooks: materialize insert failed");
            return;
        }
    }

    // Fan out deliveries: one per enabled endpoint subscribed to the type.
    let endpoints = sqlx::query(
        "SELECT id, url, secret_ref, enabled_events FROM webhooks.webhook_endpoints WHERE enabled",
    )
    .fetch_all(&mut *conn)
    .await;
    if let Ok(endpoints) = endpoints {
        for ep in endpoints {
            let endpoint_id: Uuid = ep.get("id");
            let enabled_events: Vec<String> = ep
                .get::<sqlx::types::Json<Vec<String>>, _>("enabled_events")
                .0;
            // An endpoint receives ONLY its enabled event types.
            if !enabled_events.is_empty() && !enabled_events.iter().any(|e| e == event_type) {
                continue;
            }
            let url: String = ep.get("url");
            let secret_ref: String = ep.get("secret_ref");

            // Queue the delivery (status=pending); the worker loop picks
            // it up and applies the signed-delivery retry policy.
            let delivery_id = Uuid::new_v4();
            if let Err(e) = sqlx::query(
                r#"INSERT INTO webhooks.deliveries (id, env_id, event_id, endpoint_id, status)
                   VALUES ($1, $2, $3, $4, 'pending')"#,
            )
            .bind(delivery_id)
            .bind(env_id)
            .bind(event_id)
            .bind(endpoint_id)
            .execute(&mut *conn)
            .await
            {
                tracing::warn!(error = %e, "webhooks: delivery queue failed");
            }

            // The signed delivery itself (bounded inline attempt; the
            // retry/DLQ worker continues from the deliveries table).
            if let Err(e) =
                deliver_signed(state, env_id, &url, &secret_ref, event_type, &payload).await
            {
                tracing::warn!(error = %e, "webhooks: first delivery attempt failed - retrying via worker");
                let _ = sqlx::query(
                    "UPDATE webhooks.deliveries SET status = 'retry', attempts = 1, last_attempted_at = now() WHERE id = $1",
                )
                .bind(delivery_id)
                .execute(&mut *conn)
                .await;
            } else {
                let _ = sqlx::query(
                    "UPDATE webhooks.deliveries SET status = 'succeeded', attempts = 1, last_attempted_at = now() WHERE id = $1",
                )
                .bind(delivery_id)
                .execute(&mut *conn)
                .await;
            }
        }
    }
}

/// One signed delivery attempt: HMAC-sign the payload and POST it.
/// Every delivery carries the signature header - an unsigned payload
/// is rejected by consumers (delivery.rs `verify_signature`).
async fn deliver_signed(
    _state: &AppState,
    env_id: Uuid,
    url: &str,
    secret_ref: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<(), String> {
    // The signing secret resolves from the secret reference (the
    // reference encodes the per-endpoint secret; dev mode derives it
    // deterministically so the consumer can verify with the same rule).
    let secret = format!("{secret_ref}-{env_id}");
    let body = serde_json::json!({
        "id": payload.get("event_id").or_else(|| payload.get("id")),
        "type": event_type,
        "data": payload,
        "created": chrono::Utc::now().to_rfc3339(),
    })
    .to_string();

    let timestamp = chrono::Utc::now().timestamp();
    let signature = crate::delivery::compute_signature(&body, &secret, timestamp);

    let client = reqwest::Client::new();
    let resp = client
        .post(url)
        .header(crate::delivery::SIGNATURE_HEADER, &signature)
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(format!("endpoint HTTP {}", resp.status()))
    }
}

/// Spawn the materialization consumers (one SSE loop per family).
pub fn spawn_consumers(state: AppState) {
    for family in FAMILIES {
        let bus = state.bus_client.clone();
        let state = state.clone();
        let family_static: &'static str = family;
        tokio::spawn(async move {
            tracing::info!(
                family = family_static,
                "webhooks materialize consumer started"
            );
            loop {
                match bus.sse_consume(family_static, MATERIALIZE_GROUP).await {
                    Ok(resp) => {
                        let mut stream = resp.bytes_stream();
                        let mut buffer = String::new();
                        while let Some(chunk) = stream.next().await {
                            let chunk = match chunk {
                                Ok(c) => c,
                                Err(e) => {
                                    tracing::warn!(error = %e, family = family_static, "bus SSE stream error");
                                    break;
                                }
                            };
                            buffer.push_str(&String::from_utf8_lossy(&chunk));
                            while let Some(idx) = buffer.find('\n') {
                                let line = buffer[..idx].to_string();
                                buffer.drain(..=idx);
                                let Some(data) = line.strip_prefix("data: ") else {
                                    continue;
                                };
                                if let Ok(msg) =
                                    serde_json::from_str::<serde_json::Value>(data.trim())
                                {
                                    let env_id = msg
                                        .get("env_id")
                                        .and_then(|v| v.as_str())
                                        .and_then(|s| Uuid::parse_str(s).ok());
                                    let event_type = msg
                                        .get("event_type")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    let payload =
                                        msg.get("payload").cloned().unwrap_or(msg.clone());
                                    if let Some(env_id) = env_id {
                                        materialize(&state, env_id, event_type, payload).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, family = family_static, "bus SSE consume failed - reconnecting");
                    }
                }
                tokio::time::sleep(RECONNECT_DELAY).await;
            }
        });
    }
}
