//! AmneziaWG — a `WireGuard`-compatible stack with protocol obfuscation.
//!
//! An AmneziaWG profile is a stock `WireGuard` `.conf` body plus
//! obfuscation keys (`Jc`, `S1`–`S4`, `H1`–`H4`, `I1`–`I5`, …) that stock
//! `wg-quick` rejects, so it needs its own binaries. Lifecycle, routing,
//! DNS and the kill switch treat it exactly like `WireGuard`: this module
//! only names the toolchain and parses the extra keys, and
//! [`crate::wireguard::WgTunnel`] drives it.

pub mod parser;

use crate::wireguard::tunnel::WgTools;

/// The quick wrapper binary, `awg-quick`.
pub const QUICK: &str = "awg-quick";
/// The status binary, `awg`; its `show … dump` output matches `wg`'s.
pub const SHOW: &str = "awg";
/// Where the macOS userspace runtime writes `<name>.name`/`.sock`.
pub const RUN_DIR: &str = "/var/run/amneziawg";
/// Substring identifying the userspace daemon's process path.
pub const PROCESS_NEEDLE: &str = "amnezia";
/// No distribution ships an `AppArmor` profile confining `awg-quick`, so a
/// staged lifecycle config needs no canonical directory.
const STAGING_DIR: Option<&std::path::Path> = None;

/// The toolchain a [`crate::wireguard::WgTunnel`] drives for `AmneziaWG`.
#[must_use]
pub const fn tools() -> WgTools {
    WgTools {
        quick: QUICK,
        show: SHOW,
        run_dir: RUN_DIR,
        process_needle: PROCESS_NEEDLE,
        staging_dir: STAGING_DIR,
    }
}
