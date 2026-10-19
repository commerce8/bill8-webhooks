// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! Webhooks configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

/// Webhooks configuration.
#[derive(Clone)]
pub struct WebhooksConfig {
    /// Service port (assigned by Sentin8:Captain).
    pub port: u16,
    /// PostgreSQL DSN (role `bill8_webhooks_service`).
    pub database_url: String,
    /// Auth issuer base URL.
    pub sentin8_auth_issuer: String,
    /// Auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// Bus base URL (the SSE consume source).
    pub sentin8_bus_url: String,
    /// The vertical families this service materializes (its consumer
    /// groups subscribe per family).
    pub families: Vec<String>,
    /// Delivery worker concurrency.
    pub delivery_workers: usize,
    /// Shared Auth client.
    pub sentin8_auth_client: AuthClient,
    /// Certificate-presenting transport for the service's own workload
    /// identity (CERTFREE-4V - no M2M token exists).
    pub m2m_http: Option<reqwest::Client>,
}

impl std::fmt::Debug for WebhooksConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhooksConfig")
            .field("port", &self.port)
            .field("database_url", &"<redacted>")
            .field("families", &self.families)
            .finish_non_exhaustive()
    }
}

impl WebhooksConfig {
    /// Load configuration from environment variables.
    ///
    /// # Panics
    /// Panics when `BILL8_WEBHOOKS_PORT` is unset or invalid.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        let issuer = env::var("SENTIN8_AUTH_ISSUER").unwrap_or_else(|_| cfg.sentin8_auth_issuer());
        Self {
            port: env::var("BILL8_WEBHOOKS_PORT")
                .expect("BILL8_WEBHOOKS_PORT must be set by captain")
                .parse()
                .expect("BILL8_WEBHOOKS_PORT must be a valid u16"),
            database_url: env::var("BILL8_WEBHOOKS_DATABASE_URL")
                .or_else(|_| env::var("DATABASE_URL"))
                .unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                }),
            sentin8_auth_issuer: issuer.clone(),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            families: vec![
                "payments".into(),
                "billing".into(),
                "ledger".into(),
                "merchants".into(),
                "checkout".into(),
                "risk".into(),
                "reporting".into(),
            ],
            delivery_workers: env::var("BILL8_WEBHOOKS_WORKERS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4),
            sentin8_auth_client: AuthClient::new(ClientOptions {
                base_url: issuer.clone(),
                ..Default::default()
            }),
            m2m_http: None,
        }
    }
}
