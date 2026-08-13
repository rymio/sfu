//! HMAC-SHA1 primitives for TURN credential issuance and join-token auth.
//!
//! Both mirror the sigs.au signaling service's existing scheme (`turn-credentials.ts` /
//! `token-validator.ts` in the `sigsaum-infra` repo) so credentials/tokens issued here
//! follow the same shape and secret-rotation story as the rest of that infrastructure,
//! even though this SFU is a separate, standalone service from it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hmac::{Hmac, Mac};
use rand::RngExt;
use sfu::{ClientId, RoomId};
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha1 = Hmac<sha1::Sha1>;

fn hmac_sha1_base64(secret: &str, message: &str) -> String {
    let mut mac =
        HmacSha1::new_from_slice(secret.as_bytes()).expect("HMAC accepts a key of any length");
    mac.update(message.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is before the Unix epoch")
        .as_secs()
}

/// Constant-time equality, for comparing an attacker-suppliable signature against the
/// expected one. HMAC output is fixed-length base64, so a length mismatch alone already
/// proves the input wasn't forged from a real signature — bailing out early on that check
/// leaks nothing an attacker doesn't already know (their guess had the wrong shape).
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

/// Everything a signaling connection needs to authenticate a `register` and hand back
/// TURN credentials. Built once from CLI flags in `chat.rs`'s `main()`, then shared
/// (`Arc`) across every connection thread — never mutated after construction.
///
/// Both secrets are optional and independently toggle their feature: unset `join_secret`
/// means `register` accepts any room/client with no token check at all (the tests in
/// `tests/` rely on exactly this — they never send a token, matching the crate's original,
/// unauthenticated behavior), and unset `turn_secret` means no TURN credentials are issued.
/// A real deployment (see `DEPLOY.md`) is expected to set both; `chat.rs`'s `main()` warns
/// loudly at startup if either is missing so this isn't silently forgotten in production.
pub struct SignalingSecurity {
    pub join_secret: Option<String>,
    pub turn_secret: Option<String>,
    pub turn_uris: Vec<String>,
    pub turn_credential_ttl: u64,
}

// ───────────────────────────────── TURN credentials ─────────────────────────────────

/// Mirrors `signaling/src/turn-credentials.ts`'s `TurnCredentials` shape, so an existing
/// client-side parser for that service's response works unchanged against this one.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TurnCredentials {
    pub username: String,
    pub credential: String,
    pub ttl: u64,
    pub uris: Vec<String>,
}

/// Generate short-lived TURN REST API credentials (username = `"<expiry>:<random>"`,
/// credential = `base64(hmac_sha1(secret, username))`) against a TURN server's
/// `static-auth-secret` — e.g. `turn1.sigs.au`'s.
///
/// The SFU itself never needs these for its own connectivity: it's ICE-lite, so it only
/// ever gathers a single host candidate (`rtc-ice`'s `lite` mode asserts exactly one
/// `CandidateType::Host`), never a TURN relay candidate. This exists purely so signaling
/// can hand the *client* something to configure its own `RTCPeerConnection({iceServers})`
/// with, for when the client can't reach the SFU's public address directly.
pub fn generate_turn_credentials(
    secret: &str,
    ttl_seconds: u64,
    uris: &[String],
) -> TurnCredentials {
    let expiry = now_unix() + ttl_seconds;
    let random_id: u64 = rand::rng().random();
    let username = format!("{expiry}:{random_id:016x}");
    let credential = hmac_sha1_base64(secret, &username);
    TurnCredentials {
        username,
        credential,
        ttl: ttl_seconds,
        uris: uris.to_vec(),
    }
}

// ────────────────────────────────── Join tokens ──────────────────────────────────

/// A short-lived, room+client-bound grant a client must present in `register` to join.
///
/// Not an identity system — like the delivery tokens this deliberately parallels
/// (`token-validator.ts`'s doc comment: "cannot link tokens to identities — it only
/// validates the format"), this only proves "someone who holds the shared secret
/// authorized this specific (room, client) pair to join," nothing more. Real
/// identity/authorization integration (binding a join to an actual account, minting
/// tokens from the mobile app's own auth flow) is separate, later, app-side work — see
/// `sigsau-mobile/Docs/sfu-server-plan.md`, Phase 4.
pub fn mint_join_token(
    secret: &str,
    room_id: RoomId,
    client_id: ClientId,
    ttl_seconds: u64,
) -> String {
    let expiry = now_unix() + ttl_seconds;
    let signature = hmac_sha1_base64(secret, &signing_input(room_id, client_id, expiry));
    format!("{expiry}:{signature}")
}

/// Verify a token minted by [`mint_join_token`] for this exact `(room_id, client_id)`.
/// A token minted for a different room or client fails even if otherwise well-formed and
/// unexpired — the signature covers all three fields, so it can't be replayed elsewhere.
pub fn verify_join_token(secret: &str, room_id: RoomId, client_id: ClientId, token: &str) -> bool {
    let Some((expiry_str, signature)) = token.split_once(':') else {
        return false;
    };
    let Ok(expiry) = expiry_str.parse::<u64>() else {
        return false;
    };
    if expiry < now_unix() {
        return false;
    }
    let expected = hmac_sha1_base64(secret, &signing_input(room_id, client_id, expiry));
    ct_eq(signature, &expected)
}

fn signing_input(room_id: RoomId, client_id: ClientId, expiry: u64) -> String {
    format!("{room_id}:{client_id}:{expiry}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-shared-secret";

    fn room() -> RoomId {
        RoomId::from_u128(42)
    }

    #[test]
    fn turn_credentials_round_trip_against_their_own_hmac() {
        let uris = vec!["turn:turn1.sigs.au:3478".to_string()];
        let creds = generate_turn_credentials(SECRET, 3600, &uris);

        let expected = hmac_sha1_base64(SECRET, &creds.username);
        assert_eq!(creds.credential, expected);
        assert_eq!(creds.ttl, 3600);
        assert_eq!(creds.uris, uris);
    }

    #[test]
    fn join_token_verifies_for_the_room_and_client_it_was_minted_for() {
        let token = mint_join_token(SECRET, room(), 7, 60);
        assert!(verify_join_token(SECRET, room(), 7, &token));
    }

    #[test]
    fn join_token_rejects_wrong_client() {
        let token = mint_join_token(SECRET, room(), 7, 60);
        assert!(!verify_join_token(SECRET, room(), 8, &token));
    }

    #[test]
    fn join_token_rejects_wrong_room() {
        let token = mint_join_token(SECRET, room(), 7, 60);
        assert!(!verify_join_token(SECRET, RoomId::from_u128(99), 7, &token));
    }

    #[test]
    fn join_token_rejects_wrong_secret() {
        let token = mint_join_token(SECRET, room(), 7, 60);
        assert!(!verify_join_token("a-different-secret", room(), 7, &token));
    }

    #[test]
    fn join_token_rejects_expired() {
        let token = mint_join_token(SECRET, room(), 7, 0);
        // ttl_seconds = 0 means expiry == now_unix() at mint time; by the time we verify,
        // real wall-clock time has ticked forward at least a little, so `expiry <
        // now_unix()` should already hold. This is inherently a hair racy on an
        // extraordinarily fast/frozen clock, but not in practice on real hardware.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        assert!(!verify_join_token(SECRET, room(), 7, &token));
    }

    #[test]
    fn join_token_rejects_malformed_input() {
        assert!(!verify_join_token(SECRET, room(), 7, ""));
        assert!(!verify_join_token(SECRET, room(), 7, "not-a-token"));
        assert!(!verify_join_token(SECRET, room(), 7, "not-a-number:sig"));
    }
}
