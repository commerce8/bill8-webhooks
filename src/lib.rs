// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! # Bill8:Webhooks - event delivery
//!
//! Consumes the vertical's domain events from Sentin8:Bus, materializes
//! them (dedupe by event id), and delivers signed payloads to
//! merchant-configured endpoints with exponential backoff; exhausted
//! deliveries land in a DLQ with manual replay. Every delivery is
//! HMAC-SHA256-signed with a timestamp - an unsigned payload is
//! rejected by consumers. See `DESIGN.md`.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod consumers;
pub mod delivery;
pub mod handlers;
pub mod openapi;

// The utoipa dump for registration::print - mirrored from main.rs; the
// lib crate compiles registration::print too (test harnesses embedding
// via #[path] never invoke it, so the pointer is referenced, not run).
static OPENAPI_DUMP: fn() -> serde_json::Value = || {
    use utoipa::OpenApi as _;
    serde_json::to_value(openapi::WebhooksOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
};

pub mod policy;
pub mod registration;
pub mod server;
