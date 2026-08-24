// SPDX-License-Identifier: BUSL-1.1
//! P2P node configuration — ADR-041.

use std::net::SocketAddr;

/// Network role for this node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRole {
    /// Validator node — connects to validator-private network (port 26656).
    Validator,
    /// VFN (Validator Fullnode) — connects to trusted VFN network (port 26666).
    ValidatorFullnode,
    /// Public fullnode — connects to public network (port 26676).
    PublicFullnode,
}

/// P2P configuration for a Viper PQ Chain node — ADR-041.
#[derive(Debug, Clone)]
pub struct P2pConfig {
    /// This node's role (determines which network(s) to join).
    pub role: NodeRole,
    /// Listen address for validator-private network (port 26656).
    pub validator_listen: Option<SocketAddr>,
    /// Listen address for VFN network (port 26666).
    pub vfn_listen: Option<SocketAddr>,
    /// Listen address for public network (port 26676).
    pub public_listen: Option<SocketAddr>,
    /// Bootstrap peers (multiaddr format). Minimum 8, maximum 16, on diverse operators.
    pub bootstrap_peers: Vec<String>,
    /// GossipSub mesh size (D parameter). Default 6.
    pub gossip_mesh_n: usize,
    /// GossipSub D_low. Default 4.
    pub gossip_mesh_n_low: usize,
    /// GossipSub D_high. Default 12.
    pub gossip_mesh_n_high: usize,
    /// Enable QUIC transport (primary). Default true.
    pub quic_enabled: bool,
    /// Enable TCP/TLS 1.3 fallback transport. Default true.
    pub tcp_tls_fallback: bool,
    /// Maximum peers per ASN (anti-eclipse, /24 diversity enforcement).
    pub max_peers_per_asn: usize,
    /// Chain ID (used for topic derivation).
    pub chain_id: String,
    /// Negotiate the X25519MLKEM768 hybrid post-quantum group on every TLS
    /// handshake (both the TCP/TLS fallback and the QUIC primary). Requires
    /// the binary to have been built with the `hybrid-kem-tls` Cargo feature
    /// enabled — when the feature is off, this flag is silently ignored.
    /// Default `true`: a binary that has the feature compiled in defaults to
    /// the strongest available KEX. See
    /// the private design notes.
    pub hybrid_kem_enabled: bool,
}

impl P2pConfig {
    pub fn devnet(chain_id: impl Into<String>) -> Self {
        Self {
            role: NodeRole::Validator,
            validator_listen: Some("0.0.0.0:26656".parse().unwrap()),
            vfn_listen: Some("0.0.0.0:26666".parse().unwrap()),
            public_listen: Some("0.0.0.0:26676".parse().unwrap()),
            bootstrap_peers: vec![],
            gossip_mesh_n: 6,
            gossip_mesh_n_low: 4,
            gossip_mesh_n_high: 12,
            quic_enabled: true,
            tcp_tls_fallback: true,
            max_peers_per_asn: 3,
            chain_id: chain_id.into(),
            hybrid_kem_enabled: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SPEC-P2P-002 §3 / docs/operators/RUNBOOK.md §18: validator-private on 26656, VFN on 26666,
    // public on 26676. Ansible templates and firewall rules hard-code these.
    // If a devnet rebuild silently drifts a port, the ops playbooks go stale
    // and the cutover fails at runtime — pin them here.
    #[test]
    fn devnet_binds_standard_ports_on_all_three_networks() {
        let cfg = P2pConfig::devnet("viper-devnet-2");
        assert_eq!(
            cfg.validator_listen.unwrap().port(),
            26656,
            "validator-private port must match firewall UFW rule and cutover playbook"
        );
        assert_eq!(
            cfg.vfn_listen.unwrap().port(),
            26666,
            "VFN port must match firewall UFW rule and cutover playbook"
        );
        assert_eq!(
            cfg.public_listen.unwrap().port(),
            26676,
            "public fullnode port must match firewall UFW rule and cutover playbook"
        );
    }

    // libp2p-gossipsub rejects a config where mesh_n_low > mesh_n or
    // mesh_n > mesh_n_high at build time. The chosen devnet defaults must
    // satisfy the inequality — otherwise swarm construction panics at startup.
    // behaviour.rs also derives mesh_outbound_min = min(n_low, n/2, 2), so
    // n/2 must be >= 1 as well.
    #[test]
    fn devnet_gossipsub_mesh_inequality_holds() {
        let cfg = P2pConfig::devnet("x");
        assert!(
            cfg.gossip_mesh_n_low <= cfg.gossip_mesh_n,
            "n_low ({}) must be <= n ({})",
            cfg.gossip_mesh_n_low,
            cfg.gossip_mesh_n
        );
        assert!(
            cfg.gossip_mesh_n <= cfg.gossip_mesh_n_high,
            "n ({}) must be <= n_high ({})",
            cfg.gossip_mesh_n,
            cfg.gossip_mesh_n_high
        );
        assert!(
            cfg.gossip_mesh_n >= 2,
            "n ({}) must be >= 2 so mesh_outbound_min >= 1 after n/2 floor",
            cfg.gossip_mesh_n
        );
    }

    // ADR-041: QUIC is primary, TCP/TLS 1.3 is fallback — both enabled by
    // default so a node can reach peers whose NAT blocks UDP. If a refactor
    // flips this default, peer reachability silently regresses.
    #[test]
    fn devnet_enables_both_quic_and_tcp_fallback_by_default() {
        let cfg = P2pConfig::devnet("x");
        assert!(cfg.quic_enabled, "QUIC is the primary transport (ADR-041)");
        assert!(
            cfg.tcp_tls_fallback,
            "TCP/TLS 1.3 fallback required for UDP-blocked peers (ADR-041)"
        );
    }

    // SPEC-P2P-002 §5 anti-eclipse: max 3 peers per ASN so a single hosting
    // provider can't surround a node. Default must not regress past 3.
    #[test]
    fn devnet_caps_peers_per_asn_for_eclipse_resistance() {
        let cfg = P2pConfig::devnet("x");
        assert!(
            cfg.max_peers_per_asn <= 3,
            "max_peers_per_asn ({}) must stay <= 3 for /24 diversity (SPEC-P2P-002 §5)",
            cfg.max_peers_per_asn
        );
    }

    // devnet() role defaults to Validator; VFN/PublicFullnode are opt-in.
    // A producer that silently switches role would stop participating in
    // consensus without any explicit misconfiguration error.
    #[test]
    fn devnet_defaults_to_validator_role() {
        let cfg = P2pConfig::devnet("x");
        assert_eq!(cfg.role, NodeRole::Validator);
    }

    // chain_id is plumbed verbatim into Topics::for_chain; a lossy conversion
    // here would silently route onto a different topic namespace.
    #[test]
    fn devnet_preserves_chain_id_verbatim() {
        let cfg = P2pConfig::devnet("viper-devnet-2");
        assert_eq!(cfg.chain_id, "viper-devnet-2");
    }
}
