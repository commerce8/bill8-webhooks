// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! OpenAPI spec for the Bill8:Webhooks API.

use utoipa::OpenApi;

use crate::handlers;

/// The webhooks service's OpenAPI document.
#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::create_endpoint,
        handlers::list_endpoints,
        handlers::list_events,
        handlers::list_deliveries,
        handlers::replay_event,
    )
)]
pub struct WebhooksOpenApi;