//! Parser for the `AmneziaWG` additions to a `WireGuard` config body.
//!
//! The stock parser in [`crate::wireguard::parser`] deliberately ignores
//! unknown keys, which is what makes an `AmneziaWG` profile look like plain
//! `WireGuard` and then fail on `wg-quick`. This module recognizes the
//! AmneziaWG-only keys, classifies the config by the release those keys
//! belong to, and leaves value validation to `awg` itself: the binary is
//! the authority on ranges and tag syntax, and a stricter copy here would
//! drift the moment upstream extends the protocol.

use crate::tunnel::ParseError;
use crate::wireguard::parser::WgParsedProfile;

/// `[Interface]` keys `AmneziaWG` 1.x ("Legacy" in the current app) adds:
/// junk packets and header overrides.
const LEGACY_KEYS: &[&str] = &[
    "Jc",
    "Jmin",
    "Jmax",
    "S1",
    "S2",
    "S3",
    "S4",
    "H1",
    "H2",
    "H3",
    "H4",
    "AdvancedSecurity",
];
/// Keys `AmneziaWG` 2.0 adds: the CPS signature packets `I1`–`I5`.
const V2_KEYS: &[&str] = &["I1", "I2", "I3", "I4", "I5"];
/// Keys `AmneziaWG` 3.x adds: header protection, content padding and
/// randomized protocol timers.
const V3_KEYS: &[&str] = &[
    "HeaderProtectionKey",
    "ContentPaddingAddition",
    "RekeyAfterTime",
    "RekeyTimeout",
    "RejectAfterTime",
    "KeepaliveTimeout",
    "MaxHandshakeAttempts",
    "RandomTrailers",
    "DisableCookies",
];

/// Which `AmneziaWG` release a config's obfuscation keys belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AwgGeneration {
    /// AWG 1.x: junk packets and header overrides only.
    Legacy,
    /// AWG 2.0: padding on every packet type and CPS signature packets.
    V2,
    /// AWG 3.x: header protection, content padding and randomized timers.
    V3,
}

impl AwgGeneration {
    /// The release name the `AmneziaVPN` app shows for this generation.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Legacy => "AmneziaWG Legacy",
            Self::V2 => "AmneziaWG 2.0",
            Self::V3 => "AmneziaWG 3.x",
        }
    }
}

impl std::fmt::Display for AwgGeneration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// A stock `WireGuard` parse plus the `AmneziaWG` keys the body carries.
#[derive(Debug, Clone)]
pub struct AwgParsedProfile {
    /// Routes, DNS and peers — everything the engine plans with.
    pub base: WgParsedProfile,
    /// The newest release any present obfuscation key belongs to.
    pub generation: Option<AwgGeneration>,
    /// The `AmneziaWG` keys the body carries, in file order.
    pub obfuscation_keys: Vec<String>,
}

/// Whether a `.conf` body carries `AmneziaWG`-only keys and so cannot run on
/// stock `wg-quick`.
#[must_use]
pub fn looks_like_amnezia(text: &str) -> bool {
    text.lines().any(|line| amnezia_key_of(line).is_some())
}

/// The `AmneziaWG` generation a single `key = value` line belongs to, or
/// `None` for stock `WireGuard` syntax.
fn amnezia_key_of(line: &str) -> Option<AwgGeneration> {
    let line = line.trim();
    if line.is_empty() || line.starts_with(['#', ';']) {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    let in_group = |group: &[&str]| {
        group
            .iter()
            .any(|candidate| key.eq_ignore_ascii_case(candidate))
    };
    if in_group(V3_KEYS) {
        return Some(AwgGeneration::V3);
    }
    if in_group(V2_KEYS) {
        return Some(AwgGeneration::V2);
    }
    if in_group(LEGACY_KEYS) {
        return Some(AwgGeneration::Legacy);
    }
    // A `PersistentKeepalive` range (`25-45`) is AWG 3 peer syntax; stock
    // `WireGuard` takes one integer.
    if key.eq_ignore_ascii_case("PersistentKeepalive")
        && value
            .split(['#', ';'])
            .next()
            .is_some_and(|value| value.trim().contains('-'))
    {
        return Some(AwgGeneration::V3);
    }
    None
}

/// Parse an `AmneziaWG` `.conf` body: the stock `WireGuard` fields plus the
/// obfuscation keys and their generation.
///
/// # Errors
///
/// Returns the stock parser's errors; obfuscation values are not validated
/// here (`awg` is the authority on ranges and tag syntax).
pub fn parse_awg_conf(text: &str) -> Result<AwgParsedProfile, ParseError> {
    let base = crate::wireguard::parser::parse_wg_conf(text)?;
    let mut generation = None;
    let mut obfuscation_keys = Vec::new();
    for line in text.lines() {
        let Some(found) = amnezia_key_of(line) else {
            continue;
        };
        generation = Some(generation.map_or(found, |current: AwgGeneration| current.max(found)));
        let key = line
            .trim()
            .split_once('=')
            .map_or(line.trim(), |(key, _)| key.trim());
        obfuscation_keys.push(key.to_string());
    }
    Ok(AwgParsedProfile {
        base,
        generation,
        obfuscation_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WG_BODY: &str = "[Interface]\nPrivateKey = x\nAddress = 10.8.1.2/32\n\n[Peer]\n\
                           PublicKey = y\nEndpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn stock_wireguard_body_is_not_amnezia() {
        assert!(!looks_like_amnezia(WG_BODY));
        let parsed = parse_awg_conf(WG_BODY).unwrap();
        assert_eq!(parsed.generation, None);
        assert!(parsed.obfuscation_keys.is_empty());
        assert_eq!(parsed.base.peers.len(), 1);
    }

    #[test]
    fn legacy_keys_classify_as_legacy() {
        let body = "[Interface]\nPrivateKey = x\nJc = 5\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 16\n\
                    H1 = 100-200\nH2 = 300-400\nH3 = 500-600\nH4 = 700-800\n";
        assert!(looks_like_amnezia(body));
        let parsed = parse_awg_conf(body).unwrap();
        assert_eq!(parsed.generation, Some(AwgGeneration::Legacy));
        assert_eq!(parsed.obfuscation_keys.len(), 9);
    }

    #[test]
    fn v2_and_v3_keys_raise_the_generation() {
        let v2 = "[Interface]\nJc = 4\nS3 = 12\nS4 = 12\nI1 = <b 0xd100000001><rc 8><t><r 50>\n";
        let parsed = parse_awg_conf(v2).unwrap();
        assert_eq!(parsed.generation, Some(AwgGeneration::V2));
        // S3/S4 alone are 1.x keys; they do not raise the generation.
        let s34 = "[Interface]\nS3 = 12\nS4 = 12\n";
        assert_eq!(
            parse_awg_conf(s34).unwrap().generation,
            Some(AwgGeneration::Legacy)
        );

        let v3 = "[Interface]\nJc = 4\nHeaderProtectionKey = abc\n\
                  ContentPaddingAddition = 10-50\nRekeyAfterTime = 100-200\n";
        let parsed = parse_awg_conf(v3).unwrap();
        assert_eq!(parsed.generation, Some(AwgGeneration::V3));
        // The newest key wins even when legacy keys are present.
        assert_eq!(parsed.obfuscation_keys.len(), 4);
    }

    #[test]
    fn v31_toggles_are_v3() {
        let body = "[Interface]\nRandomTrailers = on\nDisableCookies = on\n";
        let parsed = parse_awg_conf(body).unwrap();
        assert_eq!(parsed.generation, Some(AwgGeneration::V3));
    }

    #[test]
    fn keys_match_case_insensitively_and_ignore_comments() {
        assert!(looks_like_amnezia("[Interface]\njc = 3\n"));
        assert!(looks_like_amnezia("[Interface]\nHEADERPROTECTIONKEY = k\n"));
        assert!(!looks_like_amnezia("# Jc = 3 explained in a comment\n"));
        // A directive that merely carries an AmneziaWG-looking word inside
        // another value must not trip detection.
        assert!(!looks_like_amnezia("[Interface]\nDNS = jc.example.com\n"));
    }

    #[test]
    fn ranged_keepalive_marks_v3() {
        assert!(looks_like_amnezia(
            "[Interface]\nPrivateKey = x\n[Peer]\nPersistentKeepalive = 25-45\n"
        ));
        assert_eq!(
            parse_awg_conf("[Peer]\nPersistentKeepalive = 25-45\n")
                .unwrap()
                .generation,
            Some(AwgGeneration::V3)
        );
        // A plain keepalive stays stock WireGuard.
        assert!(!looks_like_amnezia("[Peer]\nPersistentKeepalive = 25\n"));
    }

    #[test]
    fn labels_name_the_release() {
        assert_eq!(AwgGeneration::Legacy.label(), "AmneziaWG Legacy");
        assert_eq!(AwgGeneration::V2.label(), "AmneziaWG 2.0");
        assert_eq!(AwgGeneration::V3.label(), "AmneziaWG 3.x");
    }
}
