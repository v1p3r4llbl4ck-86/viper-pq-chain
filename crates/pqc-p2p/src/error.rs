// SPDX-License-Identifier: BUSL-1.1
use thiserror::Error;

#[derive(Debug, Error)]
pub enum P2pError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("gossip publish failed: {0}")]
    GossipPublish(String),
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("config error: {0}")]
    Config(String),
}
