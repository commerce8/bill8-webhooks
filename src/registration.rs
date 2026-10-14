// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! Service self-registration data for Bill8:Webhooks. The event
//! triggers below declare the materialization consumer (direct consumer
//! over the vertical's families).

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, ErrorCode, M2mGrant, PgRole, PolicySetDecl,
    Registration, SqlMigration,
};
use utoipa::OpenApi;

const PG_ROLES: &[PgRole] = &[
    PgRole {
        scope: "bill8:webhooks:read,bill8:webhooks:write",
        role: "bill8_webhooks_service",
        bypass_rls: false,
        database: "bill8",
        cross_schema_grants: &[],
    },
];

const M2M_GRANTS: &[M2mGrant] = &[
    M2mGrant {
        workload: "bill8:webhooks",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "bill8:webhooks:admin",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "webhooks",
        scopes: &[
            "sentin8:bus:produce",
            "sentin8:bus:consume",
            "bill8:webhooks:admin",
            "sentin8:stat:measure",
        ],
    },
    M2mGrant {
        workload: "webhooks-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    M2mGrant {
        workload: "bill8:webhooks-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "webhooks-policy",
        scopes: &["sentin8:stat:measure"],
    },
    M2mGrant {
        workload: "bill8-webhooks-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

const ADMIN_SCOPES: &[AdminScope] = &[
    AdminScope::Typed { role: "bill8:webhooks:admin", scope: "bill8:webhooks:endpoints:read" },
    AdminScope::Typed { role: "bill8:webhooks:admin", scope: "bill8:webhooks:endpoints:write" },
    AdminScope::Typed { role: "bill8:webhooks:admin", scope: "bill8:webhooks:events:read" },
    AdminScope::Typed { role: "bill8:webhooks:admin", scope: "bill8:webhooks:events:write" },
    AdminScope::Typed { role: "bill8:webhooks:admin", scope: "bill8:webhooks:policy:read" },
    AdminScope::Typed { role: "bill8:webhooks:admin", scope: "bill8:webhooks:policy:write" },
];

const ERROR_CODES: &[ErrorCode] = &[
    ErrorCode { enum_name: "WebhooksEndpointNotFound", error_code: "webhooks_endpoint_not_found", status_code: 404 },
    ErrorCode { enum_name: "WebhooksEventNotFound", error_code: "webhooks_event_not_found", status_code: 404 },
];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage { route: "overview", label: "Overview", ui_endpoint: "/v1/admin/ui/overview", data_endpoint: "/v1/admin/overview", icon: "0xe1b1" },
    AdminUiPage { route: "endpoints", label: "Endpoints", ui_endpoint: "/v1/admin/ui/endpoints", data_endpoint: "/v1/admin/endpoints", icon: "0xe80b" },
    AdminUiPage { route: "events", label: "Events", ui_endpoint: "/v1/admin/ui/events", data_endpoint: "/v1/admin/events", icon: "0xe8af" },
    AdminUiPage { route: "deliveries", label: "Deliveries", ui_endpoint: "/v1/admin/ui/deliveries", data_endpoint: "/v1/admin/deliveries", icon: "0xe163" },
];

/// The scope-mirror Shield text.
pub const SCOPE_MIRROR_POLICIES: &str = "permit(principal, action == Action::\"bill8:webhooks:endpoints:read\", resource) when { principal.scopes.contains(\"bill8:webhooks:endpoints:read\") };\npermit(principal, action == Action::\"bill8:webhooks:endpoints:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bill8:webhooks:endpoints:write\", resource) when { principal.scopes.contains(\"bill8:webhooks:endpoints:write\") };\npermit(principal, action == Action::\"bill8:webhooks:endpoints:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bill8:webhooks:events:read\", resource) when { principal.scopes.contains(\"bill8:webhooks:events:read\") };\npermit(principal, action == Action::\"bill8:webhooks:events:read\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\npermit(principal, action == Action::\"bill8:webhooks:events:write\", resource) when { principal.scopes.contains(\"bill8:webhooks:events:write\") };\npermit(principal, action == Action::\"bill8:webhooks:events:write\", resource) when { principal.scopes.contains(\"sentin8:sys:admin\") };\n";

const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for bill8:webhooks over the LIVE effective scope set. Step 5 is the only gate.",
    policies: SCOPE_MIRROR_POLICIES,
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// The materialization consumer is declared in `vertical-registry.json`
/// (declarative registration) — `Registration.event_triggers` stays
/// empty; the consumer loop subscribes per family at runtime.
const EVENT_TRIGGERS: &[sentin8::registration::EventTriggerDecl] = &[];

const SQL_1_INIT: &str = include_str!("../sql/init.sql");

fn openapi_spec() -> serde_json::Value {
    serde_json::to_value(crate::openapi::WebhooksOpenApi::openapi()).unwrap_or(serde_json::Value::Null)
}

/// Print the registration JSON to stdout.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "bill8:webhooks",
        subdomain: "bill8-webhooks",
        health_path: "/v1/health",
        admin_scopes: ADMIN_SCOPES,
        error_codes: ERROR_CODES,
        consent_providers: &[],
        consent_flows: &[],
        policies: POLICIES,
        relations: &[],
        event_triggers: EVENT_TRIGGERS,
        schedules: &[],
        admin_ui: Some(AdminUi {
            label: "Webhooks",
            icon: "0xe80b",
            service_flag: "webhooks",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![SqlMigration { version: 1, name: "init", sql: SQL_1_INIT }],
        pg_roles: PG_ROLES,
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "/openapi.json",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}