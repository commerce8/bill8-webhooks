// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! Webhooks HTTP handlers - endpoints, events, deliveries, replay.

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use bill8::webhooks::contracts::{CreateWebhookEndpointRequest, Delivery, Event, WebhookEndpoint};
use bill8::wire::contracts::HealthBuild;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth;
use crate::config::WebhooksConfig;
use crate::policy::Engine;

/// Shared application state bound into the shell.
#[derive(Clone)]
pub struct AppState {
    /// Service configuration.
    pub config: Arc<WebhooksConfig>,
    /// Capped PostgreSQL pool.
    pub pool: sqlx::PgPool,
    /// M2M-backed Bus client.
    pub bus_client: sentin8::bus::client::BusClient,
    /// Shield policy engine - step 5 is the ONLY gate.
    pub policy: Arc<Engine>,
}

/// Set the transaction-local RLS tenant context.
pub async fn set_tenant_context(
    conn: &mut sqlx::PgConnection,
    env_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT sentin8_set_tenant_context($1, NULL, NULL, NULL, false, false, false, NULL, 'webhooks')")
        .bind(env_id)
        .execute(conn)
        .await
        .map(|_| ())
}

/// Standard DB error → HTTP 500.
pub fn err_db(e: sqlx::Error) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (status, service, version, build)", body = bill8::wire::contracts::HealthBuild),
    ),
    security(),
    tag = "meta",
)]
/// Health probe payload.
pub async fn health() -> axum::Json<HealthBuild> {
    axum::Json(HealthBuild {
        status: "ok".to_string(),
        service: "webhooks".to_string(),
        version: sentin8::build_info::id(),
        build: sentin8::build_info::build_hash().to_string(),
    })
}

/// `POST /v1/webhook-endpoints` - register an endpoint.
#[utoipa::path(
    post,
    path = "/v1/webhook-endpoints",
    request_body = CreateWebhookEndpointRequest,
    responses(
        (status = 200, description = "Endpoint created", body = WebhookEndpoint),
        (status = 403, description = "Missing bill8:webhooks:endpoints:write"),
    ),
    security(("bill8:webhooks:endpoints:write" = [])),
    tag = "webhooks",
)]
pub async fn create_endpoint(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateWebhookEndpointRequest>,
) -> Result<Json<WebhookEndpoint>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bill8:webhooks:endpoints:write"),
    )
    .await?;

    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;

    let id = Uuid::new_v4();
    // Signing secret: generated per endpoint, stored BY REFERENCE.
    let secret_ref = format!("whsec_ref_{id}");
    let row = sqlx::query(
        r#"INSERT INTO webhooks.webhook_endpoints (id, env_id, url, enabled_events, secret_ref)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, env_id, url, enabled_events, enabled, secret_ref, created_at"#,
    )
    .bind(id)
    .bind(a.env_id())
    .bind(&req.url)
    .bind(sqlx::types::Json(&req.enabled_events))
    .bind(&secret_ref)
    .fetch_one(&mut *conn)
    .await
    .map_err(err_db)?;

    sqlx::query(
        r#"INSERT INTO webhooks.outbox (env_id, event_type, payload)
           VALUES ($1, 'bill8:webhooks:webhook_endpoint:created', $2)"#,
    )
    .bind(a.env_id())
    .bind(serde_json::json!({ "endpoint_id": id }))
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(row_to_endpoint(&row)))
}

/// `GET /v1/webhook-endpoints` - list endpoints.
#[utoipa::path(
    get,
    path = "/v1/webhook-endpoints",
    responses(
        (status = 200, description = "List of endpoints", body = [WebhookEndpoint]),
        (status = 403, description = "Missing bill8:webhooks:endpoints:read"),
    ),
    security(("bill8:webhooks:endpoints:read" = [])),
    tag = "webhooks",
)]
pub async fn list_endpoints(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<WebhookEndpoint>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bill8:webhooks:endpoints:read"),
    )
    .await?;

    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;

    let rows = sqlx::query(
        "SELECT id, env_id, url, enabled_events, enabled, secret_ref, created_at FROM webhooks.webhook_endpoints ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(rows.iter().map(row_to_endpoint).collect()))
}

/// `GET /v1/events` - list materialized events.
#[utoipa::path(
    get,
    path = "/v1/events",
    responses(
        (status = 200, description = "List of events", body = [Event]),
        (status = 403, description = "Missing bill8:webhooks:events:read"),
    ),
    security(("bill8:webhooks:events:read" = [])),
    tag = "webhooks",
)]
pub async fn list_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<Event>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bill8:webhooks:events:read"),
    )
    .await?;

    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;

    let rows = sqlx::query(
        "SELECT id, env_id, event_type, data, created_at FROM webhooks.events ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(
        rows.iter()
            .map(|r| Event {
                id: r.get("id"),
                env_id: r.get("env_id"),
                event_type: r.get("event_type"),
                data: r.get::<sqlx::types::Json<serde_json::Value>, _>("data").0,
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `GET /v1/events/{id}/deliveries` - the delivery log for an event.
#[utoipa::path(
    get,
    path = "/v1/events/{id}/deliveries",
    responses(
        (status = 200, description = "Delivery attempts", body = [Delivery]),
        (status = 403, description = "Missing bill8:webhooks:events:read"),
    ),
    security(("bill8:webhooks:events:read" = [])),
    tag = "webhooks",
)]
pub async fn list_deliveries(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(event_id): Path<Uuid>,
) -> Result<Json<Vec<Delivery>>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bill8:webhooks:events:read"),
    )
    .await?;

    let mut conn = state.pool.acquire().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;

    let rows = sqlx::query(
        "SELECT id, event_id, endpoint_id, status, attempts, last_attempted_at, created_at FROM webhooks.deliveries WHERE event_id = $1 ORDER BY created_at DESC",
    )
    .bind(event_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(err_db)?;

    Ok(Json(
        rows.iter()
            .map(|r| Delivery {
                id: r.get("id"),
                event_id: r.get("event_id"),
                endpoint_id: r.get("endpoint_id"),
                status: r.get("status"),
                attempts: r.get("attempts"),
                last_attempted_at: r.get("last_attempted_at"),
                created_at: r.get("created_at"),
            })
            .collect(),
    ))
}

/// `POST /v1/events/{id}/replay` - re-queue a DLQ/failed delivery for
/// manual replay (never silently dropped).
#[utoipa::path(
    post,
    path = "/v1/events/{id}/replay",
    responses(
        (status = 200, description = "Requeued for delivery"),
        (status = 403, description = "Missing bill8:webhooks:events:write"),
    ),
    security(("bill8:webhooks:events:write" = [])),
    tag = "webhooks",
)]
pub async fn replay_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(event_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let a = auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &a,
        &headers,
        sentin8::shield::EvalTarget::new("bill8:webhooks:events:write"),
    )
    .await?;

    let mut conn = state.pool.begin().await.map_err(err_db)?;
    set_tenant_context(&mut conn, a.env_id())
        .await
        .map_err(err_db)?;

    // Reset dead/failed deliveries for this event to retry.
    let result = sqlx::query(
        "UPDATE webhooks.deliveries SET status = 'retry', attempts = 0 WHERE event_id = $1 AND status IN ('dead', 'retry')",
    )
    .bind(event_id)
    .execute(&mut *conn)
    .await
    .map_err(err_db)?;

    conn.commit().await.map_err(err_db)?;
    Ok(Json(
        serde_json::json!({ "requeued": result.rows_affected() }),
    ))
}

fn row_to_endpoint(row: &sqlx::postgres::PgRow) -> WebhookEndpoint {
    WebhookEndpoint {
        id: row.get("id"),
        env_id: row.get("env_id"),
        url: row.get("url"),
        enabled_events: row
            .get::<sqlx::types::Json<Vec<String>>, _>("enabled_events")
            .0,
        enabled: row.get("enabled"),
        secret_ref: row.get("secret_ref"),
        created_at: row.get("created_at"),
    }
}
