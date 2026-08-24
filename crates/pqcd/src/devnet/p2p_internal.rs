// SPDX-License-Identifier: BUSL-1.1
//! Internal HTTP P2P channel — KEM-authenticated devnet sync protocol.
//!
//! Extracted from `devnet.rs` 2026-05-10 as the eighth slice of the
//! split. Both halves of the protocol live here — the *client* side
//! (follower's outbound sync loop) above, the *server* side (router
//! and handlers exposed at `/internal/p2p/*`) below — bound by the
//! shared `PeerSession` and `KemKeyset` types and per-request
//! SHAKE-256 authentication tokens.
//!
//! Two cold-start helpers (`cold_start_from_snapshot`,
//! `cold_start_from_libp2p_snapshot`) live with the server side
//! because they consume the same snapshot path and reuse the
//! `compute_snapshot_token` derivation.
//!
//! `use super::*;` keeps every sibling helper (KEM session types,
//! LiveNodeState fields, gossip telemetry, etc) in scope.
//!
//! Note: `handle_metrics` and the chain-data sampling helpers stayed
//! in `devnet.rs` — they're tightly coupled to LiveNodeState's
//! private fields and a snapshot-pattern extraction is non-trivial
//! (see APPARMOR-PROFILE-AUDIT methodology comment for the same
//! rationale on a separate concern).

use super::*;

// ── P2P client side: outbound sync loop ──────────────────────────────────

/// Perform the three-step ML-KEM-768 handshake with a peer to establish an
/// authenticated P2P session.
///
/// 1. Fetch the peer's encapsulation key (`GET /internal/p2p/kem-pubkey`).
/// 2. Encapsulate a shared secret using 32 bytes of secure randomness.
/// 3. POST the ciphertext (`POST /internal/p2p/session`) — the peer decapsulates
///    and returns a session_id (hex of the first 16 bytes of the shared secret).
pub(super) async fn establish_session(client: &Client, peer: &PeerConfig) -> Result<PeerSession> {
    // Step 1: fetch peer's ML-KEM-768 encapsulation key.
    let pk_url = format!("http://{}/internal/p2p/kem-pubkey", peer.p2p_addr);
    let pk_resp: serde_json::Value = client
        .get(&pk_url)
        .send()
        .await
        .with_context(|| format!("KEM pubkey request to {} failed", peer.node_id))?
        .error_for_status()
        .with_context(|| format!("KEM pubkey response from {} not OK", peer.node_id))?
        .json()
        .await
        .context("failed to decode KEM pubkey response")?;
    let pk_hex = pk_resp["kem_pk"]
        .as_str()
        .context("kem_pk field missing from KEM pubkey response")?;
    let pk_bytes = hex::decode(pk_hex).context("invalid kem_pk hex")?;
    let kem_pk: [u8; KEM_PK_LEN] = pk_bytes
        .try_into()
        .map_err(|_| anyhow!("kem_pk must be {KEM_PK_LEN} bytes"))?;

    // Step 2: encapsulate using cryptographically secure randomness.
    let mut rand_bytes = [0u8; 32];
    getrandom::fill(&mut rand_bytes).context("getrandom failed for KEM encapsulation")?;
    let (ct, shared_secret) = kem_encapsulate(&kem_pk, &rand_bytes)
        .context("peer KEM public key failed mathematical validation")?;

    // Step 3: POST ciphertext; peer decapsulates and returns a session_id.
    let sess_url = format!("http://{}/internal/p2p/session", peer.p2p_addr);
    let sess_resp: serde_json::Value = client
        .post(&sess_url)
        .json(&serde_json::json!({ "ciphertext": hex::encode(ct) }))
        .send()
        .await
        .with_context(|| format!("session request to {} failed", peer.node_id))?
        .error_for_status()
        .with_context(|| format!("session response from {} not OK", peer.node_id))?
        .json()
        .await
        .context("failed to decode session response")?;
    let session_id = sess_resp["session_id"]
        .as_str()
        .context("session_id missing from session response")?
        .to_owned();

    tracing::info!(
        peer = %peer.node_id,
        session_id = %session_id,
        "ML-KEM-768 P2P session established"
    );
    Ok(PeerSession {
        session_id,
        shared_secret,
    })
}

pub(super) async fn sync_loop(
    state: SharedLiveNodeState,
    mut shutdown_rx: watch::Receiver<bool>,
    peers: Vec<PeerConfig>,
) -> Result<()> {
    let sync_interval_ms = {
        let guard = state.lock().await;
        guard.config.devnet.sync_interval_ms.max(25)
    };
    let client = Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .context("failed to build p2p HTTP client")?;
    let mut ticker = time::interval(Duration::from_millis(sync_interval_ms));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    // Per-peer KEM sessions. Cleared on sync error; re-established on next tick.
    let mut sessions: HashMap<String, PeerSession> = HashMap::new();

    loop {
        tokio::select! {
            _ = shutdown_rx.changed() => break,
            _ = ticker.tick() => {
                for peer in &peers {
                    if let Err(err) = sync_from_peer(&state, &client, peer, &mut sessions).await {
                        tracing::warn!(peer = %peer.node_id, error = %err, "peer sync failed");
                        // Clear session so it is re-established on the next tick.
                        sessions.remove(&peer.node_id);
                        let mut guard = state.lock().await;
                        guard.last_sync_error = Some(format!("{}: {err:#}", peer.node_id));
                        guard.peer_sync_errors += 1;
                    }
                }
            }
        }
    }

    Ok(())
}

pub(super) async fn sync_from_peer(
    state: &SharedLiveNodeState,
    client: &Client,
    peer: &PeerConfig,
    sessions: &mut HashMap<String, PeerSession>,
) -> Result<()> {
    // Establish or reuse an ML-KEM-768 authenticated session with this peer.
    if !sessions.contains_key(&peer.node_id) {
        let session = establish_session(client, peer)
            .await
            .with_context(|| format!("KEM session establishment with {} failed", peer.node_id))?;
        sessions.insert(peer.node_id.clone(), session);
    }
    let session = sessions.get(&peer.node_id).ok_or_else(|| {
        anyhow::anyhow!("session for peer {} missing after insertion", peer.node_id)
    })?;

    let status = fetch_peer_status(client, peer).await?;

    loop {
        let next_height = {
            let guard = state.lock().await;
            let local_height = guard.disk.height();
            if local_height >= status.height {
                return Ok(());
            }
            local_height + 1
        };

        let bytes = fetch_peer_block(client, peer, next_height, session).await?;
        let stored = RocksDbChainStore::decode_block_bytes(&bytes).with_context(|| {
            format!(
                "failed to decode block {next_height} from peer {}",
                peer.node_id
            )
        })?;

        let mut guard = state.lock().await;
        // ADR-054 §Stage 4 — the legacy HTTP sync_loop has no by-hash
        // parent-fetch primitive (that lives in the libp2p path,
        // TASK-212), so an `OrphanedNeedsParent` outcome on this path
        // can only mean the peer is serving a block whose prev_hash
        // does not link to our local tip — i.e. a fork attempt or a
        // chain divergence. Bail with a sync error so the outer
        // `sync_loop` records `last_sync_error`, clears the KEM
        // session, and the operator + monitoring can flag the peer.
        // The orphan stays buffered in `orphan_cache` per ADR-054 §4
        // and will drain via `drain_orphan_children` if a future
        // peer/tick supplies the legitimate parent at the same height.
        let outcome = guard.import_remote_block(stored).with_context(|| {
            format!(
                "failed to import block {next_height} from peer {}",
                peer.node_id
            )
        })?;
        if let ImportOutcome::OrphanedNeedsParent { parent_hash } = outcome {
            anyhow::bail!(
                "ADR-054: peer {} served block at height {next_height} with prev_hash={} \
                 that does not link to local tip — buffered as orphan, halting sync from this peer",
                peer.node_id,
                hex::encode(parent_hash.0)
            );
        }
    }
}

pub(super) async fn fetch_peer_status(
    client: &Client,
    peer: &PeerConfig,
) -> Result<PeerStatusResponse> {
    let url = format!("http://{}/internal/p2p/status", peer.p2p_addr);
    client
        .get(url)
        .send()
        .await
        .context("peer status request failed")?
        .error_for_status()
        .context("peer status response was not successful")?
        .json::<PeerStatusResponse>()
        .await
        .context("failed to decode peer status response")
}

pub(super) async fn fetch_peer_block(
    client: &Client,
    peer: &PeerConfig,
    height: u64,
    session: &PeerSession,
) -> Result<Vec<u8>> {
    let token = compute_block_token(&session.shared_secret, height);
    let url = format!("http://{}/internal/p2p/blocks/{}", peer.p2p_addr, height);
    let response = client
        .get(url)
        .header("X-P2P-Session", &session.session_id)
        .header("X-P2P-Token", hex::encode(token))
        .send()
        .await
        .with_context(|| format!("peer block request failed for height {height}"))?
        .error_for_status()
        .with_context(|| format!("peer block response was not successful for height {height}"))?;
    response
        .bytes()
        .await
        .with_context(|| format!("failed to read peer block bytes for height {height}"))
        .map(|bytes| bytes.to_vec())
}

// ── P2P server side: routes + handlers + cold-start ─────────────────────

pub(super) fn p2p_router(state: SharedLiveNodeState) -> Router {
    Router::new()
        .route("/internal/p2p/status", get(handle_p2p_status))
        .route("/internal/p2p/kem-pubkey", get(handle_p2p_kem_pubkey))
        .route("/internal/p2p/session", post(handle_p2p_session))
        .route("/internal/p2p/blocks/{height}", get(handle_p2p_block))
        .route("/internal/p2p/snapshot", get(handle_p2p_snapshot))
        .route("/internal/metrics", get(handle_metrics))
        .with_state(state)
}

pub(super) async fn handle_p2p_status(
    State(state): State<SharedLiveNodeState>,
) -> Json<PeerStatusResponse> {
    let guard = state.lock().await;
    let snapshot = guard.snapshot();
    Json(PeerStatusResponse {
        node_id: snapshot.node_id,
        height: snapshot.height,
        tip_hash: hex::encode(snapshot.tip_hash.0),
        state_root: hex::encode(snapshot.state_root.0),
    })
}

pub(super) async fn handle_p2p_kem_pubkey(
    State(state): State<SharedLiveNodeState>,
) -> Json<serde_json::Value> {
    // Always serve the CURRENT epoch's encapsulation key — peers should
    // re-fetch this before establishing a new session so a rotation that
    // happens between session attempts is invisible to them. The previous
    // epoch's pk is intentionally NOT exposed: it lives in
    // `kem_keyset.previous` solely for grace-window decap of in-flight
    // session-establishment requests (see `handle_p2p_session`).
    let guard = state.lock().await;
    Json(serde_json::json!({
        "kem_pk": hex::encode(guard.kem_keyset.current.pk),
        "epoch_number": guard.kem_keyset.current.epoch_number,
    }))
}

#[derive(Deserialize)]
pub(super) struct SessionRequest {
    ciphertext: String,
}

pub(super) async fn handle_p2p_session(
    State(state): State<SharedLiveNodeState>,
    Json(req): Json<SessionRequest>,
) -> Result<Json<serde_json::Value>, DevnetHttpError> {
    let ct_bytes = hex::decode(&req.ciphertext)
        .map_err(|_| DevnetHttpError(StatusCode::BAD_REQUEST, "invalid ciphertext hex".into()))?;
    let ct: [u8; KEM_CT_LEN] = ct_bytes.try_into().map_err(|_| {
        DevnetHttpError(
            StatusCode::BAD_REQUEST,
            format!("ciphertext must be {KEM_CT_LEN} bytes"),
        )
    })?;

    let mut guard = state.lock().await;
    let current_height = guard.disk.height();
    // Decap with current.sk (and previous.sk if grace window is open).
    // Both candidate session_ids are inserted into `p2p_sessions` so an
    // already-established session that was decapped with the previous
    // epoch's key continues to validate; new session establishment that
    // raced a rotation may need the peer to retry. See `KemKeyset::
    // decapsulate_all` doc for the asymmetric grace-window semantics.
    let candidates = guard.kem_keyset.decapsulate_all(&ct, current_height);

    // The current-epoch decap is always first; that session_id is the
    // one returned in the response (peers in this codebase trust the
    // response session_id directly). The previous-epoch session_id, if
    // any, is registered server-side as defence-in-depth — costs ~1 ms
    // and creates an audit trail entry under the previous epoch number.
    let response_candidate = candidates
        .first()
        .expect("KemKeyset::decapsulate_all always returns at least the current-epoch result");
    let response_session_bytes =
        shake256_32(&[response_candidate.shared_secret.as_slice(), b"session-id"].concat());
    let response_session_id = hex::encode(&response_session_bytes[..16]);

    for candidate in &candidates {
        let session_bytes =
            shake256_32(&[candidate.shared_secret.as_slice(), b"session-id"].concat());
        let session_id = hex::encode(&session_bytes[..16]);
        guard
            .p2p_sessions
            .insert(session_id.clone(), candidate.shared_secret);
        tracing::debug!(
            session_id = %session_id,
            kem_epoch = candidate.epoch_number,
            "new P2P session established"
        );
    }

    Ok(Json(serde_json::json!({
        "session_id": response_session_id,
        "kem_epoch": response_candidate.epoch_number,
    })))
}

pub(super) async fn handle_p2p_block(
    State(state): State<SharedLiveNodeState>,
    axum_headers: axum::http::HeaderMap,
    AxumPath(height): AxumPath<u64>,
) -> Result<Response, DevnetHttpError> {
    // Authenticate the request using the KEM-derived session token.
    let session_id = axum_headers
        .get("x-p2p-session")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            DevnetHttpError(
                StatusCode::UNAUTHORIZED,
                "missing X-P2P-Session header".into(),
            )
        })?;
    let token_hex = axum_headers
        .get("x-p2p-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            DevnetHttpError(
                StatusCode::UNAUTHORIZED,
                "missing X-P2P-Token header".into(),
            )
        })?;

    let ss = {
        let guard = state.lock().await;
        guard.p2p_sessions.get(session_id).copied().ok_or_else(|| {
            DevnetHttpError(
                StatusCode::UNAUTHORIZED,
                "unknown or expired session".into(),
            )
        })?
    };

    let expected = compute_block_token(&ss, height);
    if token_hex != hex::encode(expected) {
        return Err(DevnetHttpError(
            StatusCode::UNAUTHORIZED,
            "invalid session token".into(),
        ));
    }

    let bytes = {
        let guard = state.lock().await;
        guard
            .disk
            .export_block_bytes(height)
            .map_err(|err| DevnetHttpError(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    };
    let Some(bytes) = bytes else {
        return Err(DevnetHttpError(
            StatusCode::NOT_FOUND,
            format!("block {height} not found"),
        ));
    };

    Ok(([(header::CONTENT_TYPE, "application/cbor")], bytes).into_response())
}

/// Compute the per-request SHAKE-256 authentication token for a block fetch.
///
/// `token = SHAKE-256(ss || "block-fetch" || height_be64)[..32]`
pub(super) fn compute_block_token(ss: &[u8; 32], height: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(51);
    input.extend_from_slice(ss);
    input.extend_from_slice(b"block-fetch");
    input.extend_from_slice(&height.to_be_bytes());
    shake256_32(&input)
}

/// Compute the session-scoped SHAKE-256 authentication token for a snapshot fetch.
///
/// `token = SHAKE-256(ss || "snapshot-fetch")[..32]`
pub(super) fn compute_snapshot_token(ss: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(44);
    input.extend_from_slice(ss);
    input.extend_from_slice(b"snapshot-fetch");
    shake256_32(&input)
}

/// Serve the current trusted checkpoint as a distributed snapshot.
///
/// Authentication: same ML-KEM-768 session as block fetch, but uses the
/// snapshot-fetch domain token (`compute_snapshot_token`).
///
/// Returns 404 if no checkpoint has been written yet.
pub(super) async fn handle_p2p_snapshot(
    State(state): State<SharedLiveNodeState>,
    axum_headers: axum::http::HeaderMap,
) -> Result<Response, DevnetHttpError> {
    let session_id = axum_headers
        .get("x-p2p-session")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            DevnetHttpError(
                StatusCode::UNAUTHORIZED,
                "missing X-P2P-Session header".into(),
            )
        })?;
    let token_hex = axum_headers
        .get("x-p2p-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            DevnetHttpError(
                StatusCode::UNAUTHORIZED,
                "missing X-P2P-Token header".into(),
            )
        })?;

    let ss = {
        let guard = state.lock().await;
        guard.p2p_sessions.get(session_id).copied().ok_or_else(|| {
            DevnetHttpError(
                StatusCode::UNAUTHORIZED,
                "unknown or expired session".into(),
            )
        })?
    };

    let expected = compute_snapshot_token(&ss);
    if token_hex != hex::encode(expected) {
        return Err(DevnetHttpError(
            StatusCode::UNAUTHORIZED,
            "invalid session token".into(),
        ));
    }

    let bytes = {
        let guard = state.lock().await;
        guard
            .disk
            .export_checkpoint_bytes()
            .map_err(|err| DevnetHttpError(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    };
    let Some(bytes) = bytes else {
        return Err(DevnetHttpError(
            StatusCode::NOT_FOUND,
            "no snapshot available yet".into(),
        ));
    };

    Ok(([(header::CONTENT_TYPE, "application/cbor")], bytes).into_response())
}

/// Fetch the snapshot (checkpoint bytes) from a peer via the authenticated P2P endpoint.
pub(super) async fn fetch_peer_snapshot(
    client: &Client,
    peer: &PeerConfig,
    session: &PeerSession,
) -> Result<Vec<u8>> {
    let token = compute_snapshot_token(&session.shared_secret);
    let url = format!("http://{}/internal/p2p/snapshot", peer.p2p_addr);
    let response = client
        .get(url)
        .header("X-P2P-Session", &session.session_id)
        .header("X-P2P-Token", hex::encode(token))
        .send()
        .await
        .with_context(|| format!("snapshot request to {} failed", peer.node_id))?
        .error_for_status()
        .with_context(|| format!("snapshot response from {} was not successful", peer.node_id))?;
    response
        .bytes()
        .await
        .context("failed to read snapshot bytes")
        .map(|bytes| bytes.to_vec())
}

/// Perform a cold-start snapshot bootstrap from a trusted peer.
///
/// Called when the local disk store is empty AND `devnet.snapshot_source` is configured.
/// This function:
/// 1. Establishes a KEM session with the snapshot source peer.
/// 2. Fetches the peer's current status to determine the tip height.
/// 3. Downloads the snapshot (checkpoint at height H).
/// 4. Downloads tail blocks H+1..peer_height.
/// 5. Calls `disk.bootstrap_from_external_snapshot` to validate and persist everything.
///
/// After return, the disk store is at the peer's tip height and ready for
/// `recover_tip_with_checkpoint` followed by normal tail sync.
pub(super) async fn cold_start_from_snapshot(
    disk: &mut RocksDbChainStore,
    snapshot_source_addr: &str,
    chain_id: &[u8],
) -> Result<()> {
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("failed to build snapshot HTTP client")?;

    let snapshot_peer = PeerConfig {
        node_id: "snapshot-source".to_owned(),
        p2p_addr: snapshot_source_addr.to_owned(),
    };

    tracing::info!(
        peer = %snapshot_source_addr,
        "cold-start: establishing KEM session with snapshot source",
    );
    let session = establish_session(&client, &snapshot_peer)
        .await
        .with_context(|| format!("cold-start: KEM session with {snapshot_source_addr} failed"))?;

    let peer_status = fetch_peer_status(&client, &snapshot_peer)
        .await
        .context("cold-start: peer status fetch failed")?;
    let peer_height = peer_status.height;

    tracing::info!(
        peer = %snapshot_source_addr,
        peer_height,
        "cold-start: fetching snapshot",
    );
    let snapshot_bytes = fetch_peer_snapshot(&client, &snapshot_peer, &session)
        .await
        .context("cold-start: snapshot download failed")?;

    // Decode the snapshot height so we know how many tail blocks to fetch.
    // Use a minimal decode — just the outer fields needed for height.
    let snapshot_height = {
        let record = RocksDbChainStore::decode_snapshot_metadata(&snapshot_bytes)
            .context("cold-start: failed to parse snapshot metadata")?;
        record.0
    };

    // Fetch tail blocks (snapshot_height+1)..peer_height.
    let mut tail_block_bytes: Vec<Vec<u8>> = Vec::new();
    for height in (snapshot_height + 1)..=peer_height {
        tracing::debug!(height, "cold-start: fetching tail block");
        let block_bytes = fetch_peer_block(&client, &snapshot_peer, height, &session)
            .await
            .with_context(|| format!("cold-start: tail block at height {height} failed"))?;
        tail_block_bytes.push(block_bytes);
    }

    tracing::info!(
        peer = %snapshot_source_addr,
        snapshot_height,
        tail_blocks = tail_block_bytes.len(),
        "cold-start: applying snapshot and tail blocks",
    );

    disk.bootstrap_from_external_snapshot(&snapshot_bytes, &tail_block_bytes, chain_id)
        .context("cold-start: bootstrap_from_external_snapshot failed")?;

    tracing::info!(
        final_height = disk.height(),
        "cold-start: bootstrap complete",
    );
    Ok(())
}

/// Phase 8 M1 cold-start via libp2p. Fetches the first bootstrap peer's
/// latest trusted checkpoint via `/viper/<chain>/snapshot/1.0.0`, then
/// hands off to `bootstrap_from_external_snapshot` with an empty tail
/// slice. Tail-block catch-up is deliberately NOT performed here: the
/// steady-state gossip + block-fetch path (TASK-135 steps 11–13) closes
/// the resulting gap incrementally once the node starts processing
/// events, which keeps the cold-start critical section short and avoids
/// competing with the main consumer loop for the `inbound_rx` channel.
///
/// The responder's PeerId is extracted from the bootstrap multiaddr
/// (the mandatory `/p2p/<peer_id>` suffix that libp2p requires for
/// routing-aware dials). The initial dial is scheduled by
/// `start_libp2p` via `bootstrap_peers`; the brief sleep below is to
/// let the libp2p transport finish handshaking before we enqueue the
/// request (without it, libp2p buffers the request but delivery blocks
/// on connection establishment).
///
/// Failure paths (all bailed with a descriptive error — the caller
/// treats libp2p cold-start failures as non-fatal):
///   * bootstrap multiaddr missing the `/p2p/<peer_id>` component
///   * response timeout (no peer connected or peer unresponsive)
///   * responder replied with an empty body (no checkpoint yet)
///   * `bootstrap_from_external_snapshot` rejected the bytes
pub(super) async fn cold_start_from_libp2p_snapshot(
    disk: &mut RocksDbChainStore,
    handle: &pqc_p2p::SwarmHandle,
    inbound_rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::p2p::InboundP2pEvent>,
    libp2p_cfg: &crate::node::Libp2pConfig,
    chain_id: &[u8],
) -> Result<()> {
    let bootstrap_first = libp2p_cfg
        .bootstrap_peers
        .first()
        .ok_or_else(|| anyhow!("libp2p cold-start: no bootstrap_peers configured"))?;
    let ma: pqc_p2p::Multiaddr = bootstrap_first
        .parse()
        .with_context(|| format!("libp2p cold-start: parse {bootstrap_first}"))?;
    let peer_id = ma
        .iter()
        .find_map(|p| match p {
            pqc_p2p::Protocol::P2p(id) => Some(id),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow!(
                "libp2p cold-start: bootstrap multiaddr {bootstrap_first} missing /p2p/<peer_id>"
            )
        })?;

    tracing::info!(
        peer = %peer_id,
        bootstrap = %bootstrap_first,
        "libp2p cold-start: waiting for transport handshake"
    );
    // TASK-234 — retry-with-backoff. The request-response sub-behaviour
    // returns `SnapshotFetchFailed("Failed to dial the requested peer")`
    // immediately when the swarm has no established connection to the
    // target PeerId yet — which is the common case at boot, since the
    // bootstrap auto-dial is racing the request dispatch. The original
    // single-shot path (1 s pre-sleep + 20 s response wait) failed
    // every attempt during the 2026-05-05 kind smoke (`viper-libp2p`
    // cluster) because the validator's libp2p TLS handshake had not
    // completed within the first second. Retry with widening windows
    // covers the race; libp2p's own redial loop (TASK-148, 15 s cadence)
    // continues in parallel so by the second attempt the connection
    // should be established.
    //
    // Retry schedule: 6 attempts, with `pre_sleep` waiting 5 s before
    // attempt 1 (initial transport-handshake grace) and 8 s between
    // each subsequent attempt. Each attempt waits up to 8 s for a
    // SnapshotFetchResponse from `peer_id`. Non-target events are
    // dropped on the floor (steady-state path re-observes them).
    // Total worst-case time: 5 + 6×(8+8) = 101 s before falling back
    // to genesis replay, comfortably above the libp2p auto-dial +
    // TLS-handshake budget on a busy cluster.
    const MAX_ATTEMPTS: u32 = 6;
    const INITIAL_HANDSHAKE_GRACE: Duration = Duration::from_secs(5);
    const RETRY_BACKOFF: Duration = Duration::from_secs(8);
    const PER_ATTEMPT_RESPONSE_TIMEOUT: Duration = Duration::from_secs(8);

    tokio::time::sleep(INITIAL_HANDSHAKE_GRACE).await;

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        // Drain any stale events from earlier failed attempts so the
        // wait below sees only fresh response events.
        while inbound_rx.try_recv().is_ok() {}

        if let Err(e) = handle
            .request_snapshot(peer_id, pqc_p2p::SnapshotFetchRequest::default())
            .await
            .context("libp2p cold-start: request_snapshot dispatch failed")
        {
            last_err = Some(e);
            tracing::warn!(
                peer = %peer_id,
                attempt,
                max_attempts = MAX_ATTEMPTS,
                "libp2p cold-start: dispatch failed, retrying after backoff"
            );
            if attempt < MAX_ATTEMPTS {
                tokio::time::sleep(RETRY_BACKOFF).await;
            }
            continue;
        }
        crate::p2p::incr_snapshot_requests_sent();
        tracing::info!(
            peer = %peer_id,
            attempt,
            max_attempts = MAX_ATTEMPTS,
            "libp2p cold-start: snapshot request dispatched"
        );

        let deadline = tokio::time::Instant::now() + PER_ATTEMPT_RESPONSE_TIMEOUT;
        let mut got_response_this_attempt = false;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            let Some(event) = tokio::time::timeout(remaining, inbound_rx.recv())
                .await
                .ok()
                .flatten()
            else {
                // Channel closed or per-attempt timeout — out of inner
                // loop, into the retry.
                break;
            };
            match event {
                crate::p2p::InboundP2pEvent::SnapshotFetchResponse { peer, response }
                    if peer == peer_id =>
                {
                    crate::p2p::incr_snapshot_responses_received();
                    if response.is_empty() {
                        anyhow::bail!(
                            "libp2p cold-start: peer {peer_id} has no checkpoint (empty response)"
                        );
                    }
                    tracing::info!(
                        peer = %peer_id,
                        snapshot_height = response.snapshot_height,
                        snapshot_bytes_len = response.snapshot_bytes.len(),
                        attempt,
                        "libp2p cold-start: snapshot received — bootstrapping"
                    );
                    disk.bootstrap_from_external_snapshot(&response.snapshot_bytes, &[], chain_id)
                        .context("libp2p cold-start: bootstrap_from_external_snapshot failed")?;
                    tracing::info!(
                        final_height = disk.height(),
                        "libp2p cold-start: bootstrap complete; tail catch-up will follow via block-fetch"
                    );
                    return Ok(());
                }
                _ => {
                    // Non-target-peer or non-snapshot event: drop and
                    // continue. Deliberate drop documented in the
                    // function preamble.
                    got_response_this_attempt = true;
                }
            }
        }

        if !got_response_this_attempt {
            tracing::warn!(
                peer = %peer_id,
                attempt,
                max_attempts = MAX_ATTEMPTS,
                "libp2p cold-start: no response in {PER_ATTEMPT_RESPONSE_TIMEOUT:?}; retrying"
            );
        }
        if attempt < MAX_ATTEMPTS {
            tokio::time::sleep(RETRY_BACKOFF).await;
        }
    }

    if let Some(e) = last_err {
        return Err(e);
    }
    anyhow::bail!(
        "libp2p cold-start: timed out after {MAX_ATTEMPTS} attempts waiting for snapshot from {peer_id}"
    );
}
