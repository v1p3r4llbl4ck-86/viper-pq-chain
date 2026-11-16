#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Join the public Viper PQ Chain TEST network as a full node.
#
#   curl -fsSL https://raw.githubusercontent.com/v1p3r4llbl4ck-86/viper-pq-chain/main/scripts/join-testnet.sh | bash
#
# What it does, nothing more:
#   1. downloads the latest `pqcd` release for linux x86_64, verifies the Sigstore signature of
#      SHA256SUMS (made by this repository's release workflow) with `cosign`, then checks the
#      tarball against SHA256SUMS;
#   2. downloads the testnet node config and genesis from this repository and checks
#      the genesis against its published SHA-256;
#   3. writes a per-node identity (node_id + libp2p seed salt) into the config;
#   4. prints the command that starts the node, or installs a systemd unit when run as root
#      with --systemd.
#
# THIS IS A TEST NETWORK. There is no token and nothing of value on it; it can be reset at
# any time (a reset means a new chain id and a new genesis — re-run this script).
#
# Options:
#   --dir DIR        where config, data and the binary go (default: ~/.viper-testnet,
#                    or /var/lib/viper-testnet with --systemd)
#   --network NAME   network to join (default: viper-testnet-4)
#   --version vX.Y.Z release to download (default: latest)
#   --systemd        install and start a systemd unit (root only)
#   --api-public     bind the read API on 0.0.0.0 instead of 127.0.0.1
#   --skip-signature run without cosign: the tarball is then checked only against a
#                    SHA256SUMS served from the same place (integrity, not authenticity)
set -euo pipefail

REPO="v1p3r4llbl4ck-86/viper-pq-chain"
NETWORK="viper-testnet-4"
DIR=""
VERSION="latest"
SYSTEMD=0
API_BIND="127.0.0.1"
SKIP_SIG=0

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) DIR=$2; shift 2 ;;
    --network) NETWORK=$2; shift 2 ;;
    --version) VERSION=$2; shift 2 ;;
    --systemd) SYSTEMD=1; shift ;;
    --api-public) API_BIND="0.0.0.0"; shift ;;
    --skip-signature) SKIP_SIG=1; shift ;;
    -h|--help) sed -n '3,29p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
# A systemd service runs as the unprivileged `pqchain` user, which cannot enter
# /root: default to /var/lib there, to the caller's home otherwise.
if [ -z "$DIR" ]; then
  if [ "$SYSTEMD" = 1 ]; then DIR=/var/lib/viper-testnet; else DIR="${HOME}/.viper-testnet"; fi
fi

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Linux" ] || die "Linux only (got $(uname -s)); build from source elsewhere"
[ "$(uname -m)" = "x86_64" ] || die "release binaries are x86_64 only (got $(uname -m)); build from source: cargo build --release -p pqcd --no-default-features --features hybrid-kem-tls"
for t in curl tar sha256sum python3; do command -v "$t" >/dev/null || die "missing tool: $t"; done
glibc=$(ldd --version 2>/dev/null | head -1 | grep -o '[0-9]\+\.[0-9]\+$' || true)
if [ -n "$glibc" ] && [ "$(printf '%s\n2.35\n' "$glibc" | sort -V | head -1)" != "2.35" ]; then
  die "glibc $glibc is too old: the release binaries need glibc >= 2.35 (Ubuntu 22.04+, Debian 12+). Use the container image or build from source."
fi
if [ "$SYSTEMD" = 1 ] && [ "$(id -u)" != 0 ]; then die "--systemd needs root"; fi
if [ "$SKIP_SIG" = 0 ] && ! command -v cosign >/dev/null; then
  die "cosign not found. Install it (https://docs.sigstore.dev/cosign/system_config/installation/)
       so the release signature can be verified, or re-run with --skip-signature to accept
       a checksum-only check (... | bash -s -- --skip-signature)."
fi

RAW="https://raw.githubusercontent.com/${REPO}/main/genesis/${NETWORK}"
if [ "$VERSION" = latest ]; then
  VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"])') \
    || die "cannot read the latest release from GitHub"
fi
REL="https://github.com/${REPO}/releases/download/${VERSION}"

mkdir -p "$DIR"/{bin,data}
chmod 0700 "$DIR"
TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT

say "pqcd ${VERSION}: download and verify"
TARBALL="pqcd-${VERSION}-linux-x86_64.tar.gz"
curl -fsSL -o "$TMP/$TARBALL" "$REL/$TARBALL"
curl -fsSL -o "$TMP/SHA256SUMS" "$REL/SHA256SUMS"
if [ "$SKIP_SIG" = 0 ]; then
  curl -fsSL -o "$TMP/SHA256SUMS.sigstore.json" "$REL/SHA256SUMS.sigstore.json" \
    || die "release ${VERSION} has no SHA256SUMS signature"
  cosign verify-blob --bundle "$TMP/SHA256SUMS.sigstore.json" \
    --certificate-identity-regexp "^https://github\.com/${REPO//./\\.}/\.github/workflows/release\.yml@refs/tags/v" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    "$TMP/SHA256SUMS" >/dev/null 2>&1 \
    || die "SHA256SUMS signature does not verify — do not run this release"
  echo "SHA256SUMS signed by ${REPO} release workflow (Sigstore)"
else
  echo "WARNING: signature not checked (--skip-signature)"
fi
( cd "$TMP" && grep " ${TARBALL}\$" SHA256SUMS | sha256sum -c --status ) \
  || die "checksum mismatch for $TARBALL — do not run it"
tar -xzf "$TMP/$TARBALL" -C "$TMP"
install -m 0755 "$(find "$TMP" -type f -name pqcd | head -1)" "$DIR/bin/pqcd"
VIPER_AUDIT_LOG_DIR="$DIR/audit" "$DIR/bin/pqcd" version | head -1

say "${NETWORK}: genesis and node config"
# Releases from v0.2.3 carry the network files inside the signed SHA256SUMS;
# older ones fall back to the repository branch (digest file only).
if grep -q " ${NETWORK}-genesis.json\$" "$TMP/SHA256SUMS"; then
  curl -fsSL -o "$TMP/${NETWORK}-genesis.json" "$REL/${NETWORK}-genesis.json"
  curl -fsSL -o "$TMP/${NETWORK}-full.json" "$REL/${NETWORK}-full.json"
  ( cd "$TMP" && grep -E " ${NETWORK}-(genesis|full)\.json\$" SHA256SUMS | sha256sum -c --status ) \
    || die "genesis or node template does not match the signed SHA256SUMS"
  cp "$TMP/${NETWORK}-genesis.json" "$DIR/genesis.json"
  FULL_TEMPLATE="$TMP/${NETWORK}-full.json"
  echo "genesis and node template covered by the release signature"
else
  curl -fsSL -o "$DIR/genesis.json" "$RAW/genesis.json"
  curl -fsSL -o "$TMP/genesis.sha256" "$RAW/genesis.sha256"
  want=$(awk '{print $1}' "$TMP/genesis.sha256")
  got=$(sha256sum "$DIR/genesis.json" | awk '{print $1}')
  [ "$want" = "$got" ] || die "genesis digest mismatch (want $want, got $got)"
  curl -fsSL -o "$TMP/full.json" "$RAW/full.json"
  FULL_TEMPLATE="$TMP/full.json"
  echo "WARNING: release ${VERSION} predates signed network files; genesis checked against the repository digest only"
fi
echo "genesis sha256 $(sha256sum "$DIR/genesis.json" | awk '{print $1}')"

if [ -f "$DIR/node.json" ] && python3 - "$DIR/node.json" "$NETWORK" <<'EOF'
import json, sys
c = json.load(open(sys.argv[1]))
sys.exit(0 if bytes.fromhex(c["chain_id_hex"]).decode() == sys.argv[2] else 1)
EOF
then
  say "keeping the existing $DIR/node.json (same network)"
else
  if [ -d "$DIR/data/rocksdb" ]; then
    say "the data directory belongs to another chain: moving it aside"
    mv "$DIR/data" "$DIR/data.old-$(date +%Y%m%d%H%M%S)"; mkdir -p "$DIR/data"
  fi
  cp "$FULL_TEMPLATE" "$DIR/node.json"
  NODE_ID="full-$(hostname -s | tr -cd 'a-zA-Z0-9-' | cut -c1-20)-$(head -c3 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  python3 - "$DIR/node.json" "$NODE_ID" "$DIR/data" "$API_BIND" <<'EOF'
import json, sys
p, node_id, data, api = sys.argv[1:]
c = json.load(open(p))
c["node_id"] = node_id
c["data_dir"] = data
c["api_listen_addr"] = f"{api}:26657"
json.dump(c, open(p, "w"), indent=2)
EOF
  VIPER_AUDIT_LOG_DIR="$DIR/audit" "$DIR/bin/pqcd" wallet libp2p-init --node-config "$DIR/node.json" >/dev/null
  # Both identity salts are secret and per node: without them the libp2p and
  # ML-KEM identity keys would be derivable from the (public) node_id.
  VIPER_AUDIT_LOG_DIR="$DIR/audit" "$DIR/bin/pqcd" wallet kem-init --node-config "$DIR/node.json" >/dev/null
  chmod 0600 "$DIR/node.json"
  echo "node_id $NODE_ID"
fi

SALT=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["devnet"]["libp2p_seed_salt_hex"])' "$DIR/node.json")
NODE_ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["node_id"])' "$DIR/node.json")
echo "peer id $("$DIR/bin/pqcd" peer-id "$NODE_ID" --salt "$SALT" 2>/dev/null | tail -1)"

if [ "$SYSTEMD" = 1 ]; then
  say "systemd unit viper-testnet.service"
  id pqchain >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin pqchain
  chown -R pqchain:pqchain "$DIR"
  cat > /etc/systemd/system/viper-testnet.service <<EOF
[Unit]
Description=Viper PQ Chain test network node (${NETWORK})
After=network-online.target
Wants=network-online.target

[Service]
User=pqchain
Environment=VIPER_AUDIT_LOG_DIR=${DIR}/audit
ExecStart=${DIR}/bin/pqcd devnet-serve ${DIR}/node.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now viper-testnet.service
  say "started — logs: journalctl -u viper-testnet -f"
else
  say "ready. Start the node with:"
  echo "    VIPER_AUDIT_LOG_DIR=$DIR/audit $DIR/bin/pqcd devnet-serve $DIR/node.json"
fi
cat <<EOF

Open 26656/udp (QUIC) and 26656/tcp (TCP/TLS fallback) if you want other nodes to reach you;
outbound-only works too. Check progress with:
    curl -s http://127.0.0.1:26657/v1/status
and compare the height with https://pqchain.agwswebconsulting.it/v1/status
EOF
