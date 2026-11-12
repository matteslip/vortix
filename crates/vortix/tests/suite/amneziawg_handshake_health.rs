//! `AmneziaWG` adapter behavior: dispatch, evidence reuse and detection.

use std::time::{Duration, UNIX_EPOCH};

use vortix::amneziawg;
use vortix::control::tunnels::{Settings, TunnelKind};
use vortix::profile::ProtocolKind;
use vortix::wireguard::tunnel::{parse_wg_dump, WgTools};

fn settings() -> Settings {
    Settings {
        config_dir: std::env::temp_dir(),
        openvpn_verbosity: "3".to_string(),
        connect_timeout_secs: 30,
        wireguard_handshake_timeout_secs: 20,
        wireguard_health_targets: Vec::new(),
    }
}

#[test]
fn amnezia_profiles_dispatch_to_the_awg_toolchain() {
    let kind = TunnelKind::new(ProtocolKind::AmneziaWg, &settings());
    let TunnelKind::WireGuard(tunnel) = kind else {
        panic!("AmneziaWG rides the WireGuard lifecycle");
    };
    assert_eq!(tunnel.tools(), amneziawg::tools());
    assert_eq!(tunnel.tools().quick, "awg-quick");
    assert_eq!(tunnel.tools().show, "awg");
}

#[test]
fn wireguard_profiles_keep_the_stock_toolchain() {
    let kind = TunnelKind::new(ProtocolKind::WireGuard, &settings());
    let TunnelKind::WireGuard(tunnel) = kind else {
        panic!("WireGuard dispatch changed shape");
    };
    assert_eq!(tunnel.tools(), WgTools::default());
    assert_ne!(tunnel.tools(), amneziawg::tools());
}

#[test]
fn awg_status_dump_reuses_the_wireguard_evidence_parser() {
    // `awg show <iface> dump` prints the same peer lines and leading
    // interface fields as `wg`'s, with ~25 obfuscation parameters inserted
    // before the trailing fwmark (the shape amnezia-wg-tools' dump_print
    // emits; equal-bound ranges print as one integer); handshake health and
    // peer evidence flow through the same parser.
    let observed = UNIX_EPOCH + Duration::from_secs(1_000);
    let dump = concat!(
        "priv\tpub\t51820\t4\t40\t70\t15\t16\t12\t12\t100-200\t300-400\t500-600\t",
        "700-800\t(null)\t(null)\t(null)\t(null)\t(null)\t(none)\t0\t0\t0\t0\t0\t0\t",
        "off\toff\toff\n",
        "peer\t(none)\t198.51.100.7:51820\t10.8.0.0/24\t999\t12\t34\t25-30\n",
    );
    let parsed = parse_wg_dump("awg0", dump, observed, 5).unwrap();
    assert_eq!(parsed.interface_name, "awg0");
    assert_eq!(parsed.peers.len(), 1);
    assert_eq!(parsed.peers[0].evidence_generation, 5);
    assert!(parsed.peers[0].latest_handshake.is_some());
    assert_eq!(
        parsed.peers[0].persistent_keepalive,
        Some(Duration::from_secs(25))
    );
}

#[test]
fn conf_detection_separates_amnezia_from_stock_wireguard() {
    let stock = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\nAllowedIPs = 10.0.0.0/8\n";
    let amnezia = "[Interface]\nPrivateKey = x\nJc = 5\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 16\n";
    assert_eq!(
        vortix::profile::detect_conf_protocol(stock).unwrap(),
        ProtocolKind::WireGuard
    );
    assert_eq!(
        vortix::profile::detect_conf_protocol(amnezia).unwrap(),
        ProtocolKind::AmneziaWg
    );
}

#[test]
fn amnezia_parse_keeps_routes_and_names_the_generation() {
    let body = "[Interface]\nPrivateKey = x\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\n\
                Jc = 4\nHeaderProtectionKey = k\n\n[Peer]\nPublicKey = y\n\
                Endpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0, ::/0\n";
    let parsed = amneziawg::parser::parse_awg_conf(body).unwrap();
    assert_eq!(
        parsed.generation,
        Some(amneziawg::parser::AwgGeneration::V3)
    );
    assert_eq!(parsed.base.peers.len(), 1);
    assert_eq!(parsed.base.peers[0].allowed_ips.len(), 2);
    assert!(parsed.base.has_dns());
}

#[test]
fn amnezia_bootstrap_routes_become_the_platform_default_claim_after_handshake() {
    use vortix::config::profiles::VpnProfile;
    use vortix::control::{killswitch::KillSwitchMode, plan, specs, state::State};
    use vortix::profile::ProfileId;

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("awg01.conf");
    std::fs::write(&path, "[Interface]\nPrivateKey = x\nAddress = 10.80.0.2/32\nDNS = 10.80.0.1\nHeaderProtectionKey = k\n[Peer]\nPublicKey = peer\nEndpoint = 198.51.100.1:51820\nAllowedIPs = 0.0.0.0/0\n").unwrap();
    let id = ProfileId::new("awg-bootstrap");
    let profiles = vec![VpnProfile {
        id: id.clone(),
        name: "awg01".into(),
        protocol: ProtocolKind::AmneziaWg,
        location: String::new(),
        config_path: path,
        last_used: None,
        group: None,
    }];
    let mut entries = specs::load(directory.path(), profiles);
    let spec = entries.remove(&id).unwrap().spec.unwrap();
    assert_eq!(spec.protocol, ProtocolKind::AmneziaWg);
    let mut state = State::new(KillSwitchMode::AlwaysOn);
    state.begin(spec, 1, None, false).unwrap();
    state
        .prepare_probe_routes(&id, "utun4".into(), &["1.1.1.1".parse().unwrap()])
        .unwrap();
    let bootstrap = plan::plan(&state.plan_input());
    assert_eq!(bootstrap.routes.len(), 1);
    assert_eq!(bootstrap.routes[&"1.1.1.1/32".parse().unwrap()], "utun4");
    assert!(bootstrap.dns.is_empty());
    assert!(bootstrap.primary.is_none());

    state.came_up(&id, "utun4".into(), [], [], None);
    let connected = plan::plan(&state.plan_input());
    let first_claim = if vortix::platform::DECOMPOSED_V4_DEFAULT_CLAIM {
        "1.0.0.0/8"
    } else {
        "0.0.0.0/1"
    };
    assert_eq!(connected.routes[&first_claim.parse().unwrap()], "utun4");
    assert!(!connected
        .routes
        .contains_key(&"1.1.1.1/32".parse().unwrap()));
    assert_eq!(connected.primary, Some(id));
    assert_eq!(
        connected.dns[0].request.servers,
        vec!["10.80.0.1".parse::<std::net::IpAddr>().unwrap()]
    );
}
