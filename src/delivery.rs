// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bill8:Webhooks
// SPDX-License-Identifier: Apache-2.0

//! The delivery engine — HMAC-SHA256 signatures, exponential backoff,
//! and the bounded retry budget. Exhausted deliveries land in the DLQ
//! (status `dead`) for manual replay; never silently dropped.
//!
//! The signature format: `t=<unix-seconds>,v1=<hex-hmac>` — the timestamp
//! prevents replay; the HMAC covers `"{t}.{body}"`.

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The signed-delivery header names (consumers verify with the same
/// names — an unsigned payload is rejected).
pub const SIGNATURE_HEADER: &str = "x-bill8-signature";

/// The maximum delivery attempts before the DLQ (exponential backoff:
/// 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s).
pub const MAX_ATTEMPTS: i32 = 8;

/// Backoff seconds for an attempt number (exponential, capped).
pub fn backoff_seconds(attempt: i32) -> u64 {
    (1u64 << (attempt as u32 - 1).min(7)).min(128)
}

/// Compute the signature header value for a payload at a timestamp.
///
/// # Examples
///
/// ```
/// use bill8_webhooks_server::delivery::{compute_signature, parse_signature, verify_signature};
///
/// let body = r#"{"id":"evt_1","type":"bill8:payments:charge:succeeded"}"#;
/// let sig = compute_signature(body, "whsec_test", 1_700_000_000);
/// // A consumer parses the timestamp + hmac and verifies.
/// let (t, v1) = parse_signature(&sig).unwrap();
/// assert!(verify_signature(body, "whsec_test", t, &v1));
/// assert!(!verify_signature(body, "whsec_wrong", t, &v1));
/// // Tampered bodies fail.
/// assert!(!verify_signature(&format!("{} ", body), "whsec_test", t, &v1));
/// ```
pub fn compute_signature(body: &str, secret: &str, timestamp: i64) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(format!("{timestamp}.{body}").as_bytes());
    let out = mac.finalize().into_bytes();
    format!("t={timestamp},v1={}", hex_encode(&out))
}

/// Hex-encode bytes (lowercase) — the `v1` signature segment format.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse the `t=…,v1=…` signature header.
///
/// # Errors
/// Returns `None` when the header is malformed.
pub fn parse_signature(header: &str) -> Option<(i64, Vec<u8>)> {
    let mut t: Option<i64> = None;
    let mut v1: Option<Vec<u8>> = None;
    for part in header.split(',') {
        if let Some(rest) = part.strip_prefix("t=") {
            t = rest.parse().ok();
        } else if let Some(rest) = part.strip_prefix("v1=") {
            v1 = hex_decode(rest);
        }
    }
    match (t, v1) {
        (Some(t), Some(v)) if !v.is_empty() => Some((t, v)),
        _ => None,
    }
}

/// Verify a payload against a secret + parsed signature parts. The
/// timestamp is bound into the HMAC — a reused signature on a different
/// body (or timestamp) fails.
pub fn verify_signature(body: &str, secret: &str, timestamp: i64, provided: &[u8]) -> bool {
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(format!("{timestamp}.{body}").as_bytes());
    mac.verify_slice(provided).is_ok()
}

/// Whether the signature timestamp is fresh (replay window).
pub fn is_fresh(timestamp: i64, tolerance_secs: i64) -> bool {
    let now = Utc::now().timestamp();
    (now - timestamp).abs() <= tolerance_secs
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_roundtrip() {
        let body = r#"{"id":"evt_1"}"#;
        let sig = compute_signature(body, "whsec_x", 1_700_000_000);
        let (t, v1) = parse_signature(&sig).unwrap();
        assert_eq!(t, 1_700_000_000);
        assert!(verify_signature(body, "whsec_x", t, &v1));
    }

    #[test]
    fn wrong_secret_fails() {
        let body = r#"{"id":"evt_1"}"#;
        let sig = compute_signature(body, "whsec_x", 1_700_000_000);
        let (t, v1) = parse_signature(&sig).unwrap();
        assert!(!verify_signature(body, "whsec_y", t, &v1));
    }

    #[test]
    fn tampered_body_fails() {
        let body = r#"{"id":"evt_1"}"#;
        let sig = compute_signature(body, "whsec_x", 1_700_000_000);
        let (t, v1) = parse_signature(&sig).unwrap();
        assert!(!verify_signature(r#"{"id":"evt_2"}"#, "whsec_x", t, &v1));
    }

    #[test]
    fn malformed_header_rejected() {
        assert!(parse_signature("garbage").is_none());
        assert!(parse_signature("t=abc,v1=zz").is_none());
        assert!(parse_signature("v1=deadbeef").is_none());
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_seconds(1), 1);
        assert_eq!(backoff_seconds(2), 2);
        assert_eq!(backoff_seconds(3), 4);
        assert_eq!(backoff_seconds(8), 128);
        assert_eq!(backoff_seconds(9), 128); // capped
    }

    #[test]
    fn freshness_window() {
        let now = Utc::now().timestamp();
        assert!(is_fresh(now, 300));
        assert!(!is_fresh(now - 3600, 300));
    }
}
