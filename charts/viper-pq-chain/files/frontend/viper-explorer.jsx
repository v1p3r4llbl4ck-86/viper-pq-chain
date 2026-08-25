/**
 * Viper Chain — Block Explorer
 *
 * Single-file React app. Requires:
 *   - React 18+
 *   - No build step needed if served via CDN imports (see <script> tags below)
 *
 * Design: dark industrial, Viper green (#39FF14) primary accent, amber (#FFB800)
 * for warnings/secondary. Monospace type for hashes and values.
 *
 * To run standalone:
 *   npx serve . -p 3000
 * and open index.html that imports this file, or use Vite/CRA.
 *
 * baseUrl defaults to the page origin (the ingress serves /v1 next to the explorer). Override via ?node=<url>.
 */
const { useState, useEffect, useRef, useMemo, useCallback } = React;


// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const POLL_INTERVAL_MS = 3_000;
const VENOM_SCALE = 10n ** 18n;

const COLORS = {
  bg: "#0a0c0f",
  surface: "#111318",
  border: "#1e2430",
  green: "#39FF14",
  amber: "#FFB800",
  red: "#FF3B30",
  text: "#c8d0dc",
  muted: "#5a6478",
  white: "#e8ecf2",
};

const CSS = `
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: ${COLORS.bg}; color: ${COLORS.text}; font-family: 'Inter', system-ui, sans-serif; font-size: 14px; }
  a { color: ${COLORS.green}; text-decoration: none; cursor: pointer; }
  a:hover { text-decoration: underline; }
  code, .mono { font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace; font-size: 12px; }
  input { background: ${COLORS.surface}; border: 1px solid ${COLORS.border}; color: ${COLORS.white}; padding: 8px 12px; border-radius: 6px; font-size: 14px; outline: none; }
  input:focus { border-color: ${COLORS.green}; }
  button { cursor: pointer; font-size: 13px; }
  ::-webkit-scrollbar { width: 6px; }
  ::-webkit-scrollbar-track { background: ${COLORS.bg}; }
  ::-webkit-scrollbar-thumb { background: ${COLORS.border}; border-radius: 3px; }
`;

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// Maps consensus_alg_id (u16) to a display label.
function algIdToName(id) {
  return id != null ? `0x${id.toString(16).padStart(4, "0")}` : null;
}

function venomToVpr(venom) {
  try {
    const v = BigInt(venom);
    const whole = v / VENOM_SCALE;
    const frac = v % VENOM_SCALE;
    if (frac === 0n) return whole.toString();
    const fracStr = frac.toString().padStart(18, "0").replace(/0+$/, "");
    return `${whole}.${fracStr}`;
  } catch {
    return venom?.toString() ?? "0";
  }
}

function shortHash(hash, n = 8) {
  if (!hash) return "—";
  return `${hash.slice(0, n)}…${hash.slice(-4)}`;
}

function timeAgo(ms) {
  const delta = Date.now() - ms;
  if (delta < 5_000) return "just now";
  if (delta < 60_000) return `${Math.floor(delta / 1_000)}s ago`;
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  return `${Math.floor(delta / 3_600_000)}h ago`;
}

function getBaseUrl() {
  try {
    const url = new URL(window.location.href);
    return url.searchParams.get("node") ?? window.location.origin;
  } catch {
    return window.location.origin;
  }
}

// ---------------------------------------------------------------------------
// API layer
// ---------------------------------------------------------------------------

async function apiFetch(baseUrl, path) {
  const res = await fetch(`${baseUrl}${path}`, {
    headers: { Accept: "application/json" },
    signal: AbortSignal.timeout(8_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${path}`);
  return res.json();
}

// ---------------------------------------------------------------------------
// Styled primitives
// ---------------------------------------------------------------------------

function Card({ children, style }) {
  return (
    <div
      style={{
        background: COLORS.surface,
        border: `1px solid ${COLORS.border}`,
        borderRadius: 8,
        padding: 16,
        ...style,
      }}
    >
      {children}
    </div>
  );
}

function Badge({ label, color = COLORS.muted }) {
  return (
    <span
      style={{
        display: "inline-block",
        padding: "2px 8px",
        borderRadius: 4,
        fontSize: 11,
        fontWeight: 600,
        background: `${color}22`,
        color,
        border: `1px solid ${color}44`,
        textTransform: "uppercase",
        letterSpacing: "0.05em",
      }}
    >
      {label}
    </span>
  );
}

function HashCell({ hash, onClick }) {
  if (!hash) return <span style={{ color: COLORS.muted }}>—</span>;
  return (
    <span
      className="mono"
      style={{ color: COLORS.green, cursor: onClick ? "pointer" : "default" }}
      onClick={onClick}
      title={hash}
    >
      {shortHash(hash)}
    </span>
  );
}

function StatBox({ label, value, unit, accent }) {
  return (
    <Card style={{ flex: 1, minWidth: 140 }}>
      <div style={{ color: COLORS.muted, fontSize: 11, marginBottom: 6, textTransform: "uppercase", letterSpacing: "0.08em" }}>
        {label}
      </div>
      <div style={{ fontSize: 24, fontWeight: 700, color: accent ?? COLORS.white }}>
        {value ?? "—"}
      </div>
      {unit && <div style={{ color: COLORS.muted, fontSize: 11, marginTop: 2 }}>{unit}</div>}
    </Card>
  );
}

function SectionHeader({ title }) {
  return (
    <div
      style={{
        borderBottom: `1px solid ${COLORS.border}`,
        paddingBottom: 8,
        marginBottom: 12,
        fontSize: 12,
        fontWeight: 600,
        color: COLORS.muted,
        textTransform: "uppercase",
        letterSpacing: "0.1em",
      }}
    >
      {title}
    </div>
  );
}

function Table({ columns, rows, emptyMsg = "No data." }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr>
            {columns.map((col) => (
              <th
                key={col.key}
                style={{
                  textAlign: "left",
                  padding: "6px 12px",
                  color: COLORS.muted,
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.08em",
                  borderBottom: `1px solid ${COLORS.border}`,
                }}
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr>
              <td
                colSpan={columns.length}
                style={{ padding: 16, color: COLORS.muted, textAlign: "center" }}
              >
                {emptyMsg}
              </td>
            </tr>
          ) : (
            rows.map((row, i) => (
              <tr
                key={i}
                style={{
                  borderBottom: `1px solid ${COLORS.border}`,
                  transition: "background 0.1s",
                }}
                onMouseEnter={(e) => (e.currentTarget.style.background = COLORS.border + "55")}
                onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
              >
                {columns.map((col) => (
                  <td key={col.key} style={{ padding: "8px 12px" }}>
                    {col.render ? col.render(row) : row[col.key]}
                  </td>
                ))}
              </tr>
            ))
          )}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header / Status Bar
// ---------------------------------------------------------------------------

function Header({ status, baseUrl, onBaseUrlChange, lastUpdate }) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(baseUrl);

  const live = status != null;

  return (
    <header
      style={{
        background: COLORS.surface,
        borderBottom: `1px solid ${COLORS.border}`,
        padding: "0 24px",
        height: 56,
        display: "flex",
        alignItems: "center",
        gap: 16,
        position: "sticky",
        top: 0,
        zIndex: 100,
      }}
    >
      {/* Logo */}
      <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>
        <div
          style={{
            width: 28,
            height: 28,
            borderRadius: 6,
            background: `${COLORS.green}22`,
            border: `1px solid ${COLORS.green}66`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 14,
            color: COLORS.green,
            fontWeight: 800,
          }}
        >
          V
        </div>
        <span style={{ fontWeight: 700, fontSize: 15, color: COLORS.white }}>
          Viper Explorer
        </span>
      </div>

      {/* Status pill */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          padding: "3px 10px",
          borderRadius: 20,
          background: live ? `${COLORS.green}18` : `${COLORS.red}18`,
          border: `1px solid ${live ? COLORS.green : COLORS.red}44`,
          fontSize: 11,
          fontWeight: 600,
          color: live ? COLORS.green : COLORS.red,
          flexShrink: 0,
        }}
      >
        <div
          style={{
            width: 6,
            height: 6,
            borderRadius: "50%",
            background: live ? COLORS.green : COLORS.red,
            animation: live ? "pulse 2s infinite" : "none",
          }}
        />
        {live ? "LIVE" : "OFFLINE"}
      </div>

      {/* Height pill */}
      {status && (
        <div style={{ color: COLORS.muted, fontSize: 12, flexShrink: 0 }}>
          <span style={{ color: COLORS.white, fontWeight: 600 }}>#{status.height}</span>
          {" "}· {status.chain_id}
        </div>
      )}

      <div style={{ flex: 1 }} />

      {/* Node URL editor */}
      {editing ? (
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            style={{ width: 280 }}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                onBaseUrlChange(draft.trim());
                setEditing(false);
              }
              if (e.key === "Escape") setEditing(false);
            }}
            autoFocus
          />
          <button
            onClick={() => { onBaseUrlChange(draft.trim()); setEditing(false); }}
            style={{
              background: COLORS.green,
              color: COLORS.bg,
              border: "none",
              borderRadius: 4,
              padding: "6px 12px",
              fontWeight: 700,
            }}
          >
            Connect
          </button>
        </div>
      ) : (
        <button
          onClick={() => { setDraft(baseUrl); setEditing(true); }}
          style={{
            background: "transparent",
            border: `1px solid ${COLORS.border}`,
            borderRadius: 4,
            padding: "5px 10px",
            color: COLORS.muted,
            fontSize: 12,
          }}
        >
          {baseUrl}
        </button>
      )}

      {lastUpdate && (
        <div style={{ color: COLORS.muted, fontSize: 11, flexShrink: 0 }}>
          updated {timeAgo(lastUpdate)}
        </div>
      )}
    </header>
  );
}

// ---------------------------------------------------------------------------
// Search bar
// ---------------------------------------------------------------------------

function SearchBar({ onSearch }) {
  const [query, setQuery] = useState("");

  const submit = () => {
    const q = query.trim();
    if (!q) return;
    onSearch(q);
    setQuery("");
  };

  return (
    <div style={{ display: "flex", gap: 8, marginBottom: 24 }}>
      <input
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && submit()}
        placeholder="Search by block height, tx hash, account address, or attestation ID…"
        style={{ flex: 1, fontSize: 14 }}
      />
      <button
        onClick={submit}
        style={{
          background: COLORS.green,
          color: COLORS.bg,
          border: "none",
          borderRadius: 6,
          padding: "8px 20px",
          fontWeight: 700,
          fontSize: 14,
        }}
      >
        Search
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

function Dashboard({ status, validators, baseUrl, navigate }) {
  const [recentBlocks, setRecentBlocks] = useState([]);
  const [recentTxs, setRecentTxs] = useState([]);

  useEffect(() => {
    if (!status || !baseUrl) return;

    const fetchRecent = async () => {
      try {
        const blocks = [];
        const hi = status.height;
        for (let h = hi; h > Math.max(0, hi - 5); h--) {
          try {
            const b = await apiFetch(baseUrl, `/v1/blocks/${h}`);
            blocks.push(b);
          } catch { /* block may not exist */ }
        }
        setRecentBlocks(blocks);

        // API returns tx_hashes (strings), not full tx objects.
        const txs = blocks.flatMap((b) =>
          (b.tx_hashes ?? []).slice(0, 3).map((hash) => ({
            tx_hash: hash,
            op_type: "—",
            sender: b.proposer,
            fee_venom: "0",
            block_height: b.height,
          }))
        ).slice(0, 10);
        setRecentTxs(txs);
      } catch { /* ignore */ }
    };

    fetchRecent();
  }, [status?.height, baseUrl]);

  if (!status) {
    return (
      <div style={{ textAlign: "center", padding: 60, color: COLORS.muted }}>
        Connecting to node…
      </div>
    );
  }

  const activeValidators = (validators ?? []).filter((v) => v.status === "active").length;
  const totalStaked = (validators ?? []).reduce((acc, v) => {
    try { return acc + BigInt(v.self_bond ?? "0"); } catch { return acc; }
  }, 0n);

  return (
    <div>
      {/* Stat boxes */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 24 }}>
        <StatBox label="Latest block" value={`#${status.height}`} accent={COLORS.green} />
        <StatBox label="Chain ID" value={status.chain_id} />
        <StatBox label="Active validators" value={activeValidators} />
        <StatBox
          label="Total staked"
          value={venomToVpr(totalStaked)}
          unit="VPR"
          accent={COLORS.amber}
        />
        <StatBox
          label="State root"
          value={<span className="mono" style={{ fontSize: 12 }}>{shortHash(status.state_root, 10)}</span>}
        />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        {/* Recent blocks */}
        <Card>
          <SectionHeader title="Recent Blocks" />
          <Table
            columns={[
              { key: "height", label: "Height", render: (b) => (
                <a onClick={() => navigate({ type: "block", height: b.height })}>
                  #{b.height ?? "?"}
                </a>
              )},
              { key: "block_hash", label: "Hash", render: (b) => <HashCell hash={b.block_hash} onClick={() => navigate({ type: "block", hash: b.block_hash })} /> },
              { key: "tx_count", label: "Txs", render: (b) => b.tx_count ?? 0 },
              { key: "proposer", label: "Proposer", render: (b) => <HashCell hash={b.proposer} /> },
            ]}
            rows={recentBlocks}
            emptyMsg="No blocks yet."
          />
        </Card>

        {/* Recent transactions */}
        <Card>
          <SectionHeader title="Recent Transactions" />
          <Table
            columns={[
              { key: "tx_hash", label: "Tx Hash", render: (tx) => <HashCell hash={tx.tx_hash} onClick={() => navigate({ type: "tx", hash: tx.tx_hash })} /> },
              { key: "op_type", label: "Op", render: (tx) => <Badge label={tx.op_type} color={COLORS.green} /> },
              { key: "sender", label: "Sender", render: (tx) => <HashCell hash={tx.sender} onClick={() => navigate({ type: "account", address: tx.sender })} /> },
              { key: "fee", label: "Fee", render: (tx) => venomToVpr(tx.fee_venom ?? "0") },
            ]}
            rows={recentTxs}
            emptyMsg="No transactions yet."
          />
        </Card>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Block view
// ---------------------------------------------------------------------------

function BlockView({ baseUrl, height, hash, navigate }) {
  const [block, setBlock] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const path = height != null ? `/v1/blocks/${height}` : `/v1/blocks/${hash}`;
    setBlock(null);
    setError(null);
    apiFetch(baseUrl, path)
      .then(setBlock)
      .catch((e) => setError(e.message));
  }, [baseUrl, height, hash]);

  if (error) return <Card><div style={{ color: COLORS.red }}>{error}</div></Card>;
  if (!block) return <Card><div style={{ color: COLORS.muted }}>Loading…</div></Card>;

  const h = block.header ?? {};
  const txs = block.transactions ?? [];

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ fontSize: 20, fontWeight: 700, color: COLORS.white }}>Block #{h.height}</div>
        <Badge label="block" color={COLORS.green} />
      </div>

      <Card style={{ marginBottom: 16 }}>
        <SectionHeader title="Header" />
        <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: "8px 16px" }}>
          {[
            ["Hash", <span className="mono" style={{ color: COLORS.green }}>{block.hash}</span>],
            ["Height", h.height],
            ["Prev Hash", <span className="mono" style={{ color: COLORS.muted }}>{h.prev_hash}</span>],
            ["State Root", <span className="mono">{h.state_root}</span>],
            ["Proposer", <a onClick={() => navigate({ type: "account", address: h.proposer_address })}><span className="mono">{h.proposer_address}</span></a>],
            ["Timestamp", h.timestamp_ms ? new Date(h.timestamp_ms).toISOString() : "—"],
            ["Tx Count", txs.length],
          ].map(([k, v]) => (
            <React.Fragment key={k}>
              <div style={{ color: COLORS.muted, fontSize: 12 }}>{k}</div>
              <div style={{ wordBreak: "break-all" }}>{v}</div>
            </React.Fragment>
          ))}
        </div>
      </Card>

      <Card>
        <SectionHeader title={`Transactions (${txs.length})`} />
        <Table
          columns={[
            { key: "tx_hash", label: "Hash", render: (tx) => <HashCell hash={tx.tx_hash} onClick={() => navigate({ type: "tx", hash: tx.tx_hash })} /> },
            { key: "op_type", label: "Op", render: (tx) => <Badge label={tx.op_type} color={COLORS.green} /> },
            { key: "sender", label: "Sender", render: (tx) => <HashCell hash={tx.sender} onClick={() => navigate({ type: "account", address: tx.sender })} /> },
            { key: "fee", label: "Fee", render: (tx) => venomToVpr(tx.fee_venom ?? "0") },
          ]}
          rows={txs}
          emptyMsg="No transactions in this block."
        />
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Transaction view
// ---------------------------------------------------------------------------

function TxView({ baseUrl, hash, navigate }) {
  const [tx, setTx] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setTx(null);
    setError(null);
    apiFetch(baseUrl, `/v1/txs/${hash}`)
      .then(setTx)
      .catch((e) => setError(e.message));
  }, [baseUrl, hash]);

  if (error) return <Card><div style={{ color: COLORS.red }}>{error}</div></Card>;
  if (!tx) return <Card><div style={{ color: COLORS.muted }}>Loading…</div></Card>;

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ fontSize: 20, fontWeight: 700, color: COLORS.white }}>Transaction</div>
        <Badge label={tx.op_type} color={COLORS.green} />
      </div>

      <Card>
        <SectionHeader title="Details" />
        <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: "8px 16px" }}>
          {[
            ["Hash", <span className="mono" style={{ color: COLORS.green }}>{tx.tx_hash}</span>],
            ["Operation", <Badge label={tx.op_type} color={COLORS.green} />],
            ["Sender", <a onClick={() => navigate({ type: "account", address: tx.sender })}><span className="mono">{tx.sender}</span></a>],
            ["Nonce", tx.nonce],
            ["Fee", venomToVpr(tx.fee_venom ?? "0")],
            ["Algorithm", <Badge label={tx.alg_id} color={COLORS.amber} />],
            ["Signature", <span className="mono" style={{ color: COLORS.muted, wordBreak: "break-all" }}>{tx.signature ? shortHash(tx.signature, 16) + "…" : "—"}</span>],
          ].map(([k, v]) => (
            <React.Fragment key={k}>
              <div style={{ color: COLORS.muted, fontSize: 12 }}>{k}</div>
              <div>{v}</div>
            </React.Fragment>
          ))}
        </div>

        {tx.op_payload && (
          <div style={{ marginTop: 16 }}>
            <div style={{ color: COLORS.muted, fontSize: 11, marginBottom: 6 }}>PAYLOAD (HEX)</div>
            <pre
              className="mono"
              style={{
                background: COLORS.bg,
                border: `1px solid ${COLORS.border}`,
                borderRadius: 6,
                padding: 12,
                overflowX: "auto",
                fontSize: 11,
                color: COLORS.text,
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
              }}
            >
              {tx.op_payload}
            </pre>
          </div>
        )}
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Account view
// ---------------------------------------------------------------------------

function AccountView({ baseUrl, address, navigate }) {
  const [account, setAccount] = useState(null);
  const [attestations, setAttestations] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setAccount(null);
    setAttestations(null);
    setError(null);
    Promise.all([
      apiFetch(baseUrl, `/v1/accounts/${address}`),
      apiFetch(baseUrl, `/v1/accounts/${address}/attestations`).catch(() => []),
    ])
      .then(([acc, atts]) => { setAccount(acc); setAttestations(atts); })
      .catch((e) => setError(e.message));
  }, [baseUrl, address]);

  if (error) return <Card><div style={{ color: COLORS.red }}>{error}</div></Card>;
  if (!account) return <Card><div style={{ color: COLORS.muted }}>Loading…</div></Card>;

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ fontSize: 20, fontWeight: 700, color: COLORS.white }}>Account</div>
        <Badge label="vault" color={COLORS.green} />
      </div>

      <Card style={{ marginBottom: 16 }}>
        <SectionHeader title="Overview" />
        <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: "8px 16px" }}>
          {[
            ["Address", <span className="mono" style={{ color: COLORS.green }}>{account.address}</span>],
            ["Balance", <span style={{ fontSize: 18, fontWeight: 700, color: COLORS.white }}>{venomToVpr(account.balance_venom)} <span style={{ color: COLORS.muted, fontSize: 13 }}>VPR</span></span>],
            ["Nonce", account.nonce],
            ["Keys", account.keys?.length ?? 0],
          ].map(([k, v]) => (
            <React.Fragment key={k}>
              <div style={{ color: COLORS.muted, fontSize: 12 }}>{k}</div>
              <div>{v}</div>
            </React.Fragment>
          ))}
        </div>
      </Card>

      <Card style={{ marginBottom: 16 }}>
        <SectionHeader title="Cryptographic Keys" />
        <Table
          columns={[
            { key: "key_version", label: "Version" },
            { key: "alg_id", label: "Algorithm", render: (k) => <Badge label={k.alg_id} color={COLORS.amber} /> },
            { key: "public_key", label: "Public Key", render: (k) => <span className="mono" style={{ color: COLORS.muted }}>{shortHash(k.public_key, 12)}</span> },
            { key: "added_at_height", label: "Added at", render: (k) => `#${k.added_at_height}` },
            { key: "status", label: "Status", render: (k) => k.revoked_at_height
              ? <Badge label="revoked" color={COLORS.red} />
              : <Badge label="active" color={COLORS.green} />
            },
          ]}
          rows={account.keys ?? []}
          emptyMsg="No keys."
        />
      </Card>

      {attestations && attestations.length > 0 && (
        <Card>
          <SectionHeader title="Attestations" />
          <Table
            columns={[
              { key: "attestation_id", label: "ID", render: (a) => <HashCell hash={a.attestation_id} onClick={() => navigate({ type: "attestation", id: a.attestation_id })} /> },
              { key: "issuer", label: "Issuer", render: (a) => <HashCell hash={a.issuer} onClick={() => navigate({ type: "account", address: a.issuer })} /> },
              { key: "schema_id", label: "Schema", render: (a) => <span className="mono" style={{ fontSize: 11 }}>{shortHash(a.schema_id)}</span> },
              { key: "status", label: "Status", render: (a) => a.revoked_at_height
                ? <Badge label="revoked" color={COLORS.red} />
                : <Badge label="active" color={COLORS.green} />
              },
              { key: "issued_at_height", label: "Issued at", render: (a) => `#${a.issued_at_height}` },
            ]}
            rows={attestations}
            emptyMsg="No attestations."
          />
        </Card>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attestation view
// ---------------------------------------------------------------------------

function AttestationView({ baseUrl, id, navigate }) {
  const [att, setAtt] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    setAtt(null);
    setError(null);
    apiFetch(baseUrl, `/v1/attestations/${id}`)
      .then(setAtt)
      .catch((e) => setError(e.message));
  }, [baseUrl, id]);

  if (error) return <Card><div style={{ color: COLORS.red }}>{error}</div></Card>;
  if (!att) return <Card><div style={{ color: COLORS.muted }}>Loading…</div></Card>;

  return (
    <div>
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
        <div style={{ fontSize: 20, fontWeight: 700, color: COLORS.white }}>Attestation</div>
        {att.revoked_at_height
          ? <Badge label="revoked" color={COLORS.red} />
          : <Badge label="active" color={COLORS.green} />
        }
      </div>

      <Card>
        <SectionHeader title="Proof Anchor" />
        <div style={{ display: "grid", gridTemplateColumns: "160px 1fr", gap: "8px 16px" }}>
          {[
            ["Attestation ID", <span className="mono" style={{ color: COLORS.green }}>{att.attestation_id}</span>],
            ["Issuer", <a onClick={() => navigate({ type: "account", address: att.issuer })}><span className="mono">{att.issuer}</span></a>],
            ["Subject", <a onClick={() => navigate({ type: "account", address: att.subject })}><span className="mono">{att.subject}</span></a>],
            ["Schema ID", <span className="mono">{att.schema_id}</span>],
            ["Payload Hash", <span className="mono" style={{ wordBreak: "break-all" }}>{att.payload_hash}</span>],
            ["Issued at block", `#${att.issued_at_height}`],
            ["Revoked at block", att.revoked_at_height ? `#${att.revoked_at_height}` : <span style={{ color: COLORS.muted }}>not revoked</span>],
          ].map(([k, v]) => (
            <React.Fragment key={k}>
              <div style={{ color: COLORS.muted, fontSize: 12 }}>{k}</div>
              <div>{v}</div>
            </React.Fragment>
          ))}
        </div>
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Validators view
// ---------------------------------------------------------------------------

function ValidatorsView({ validators, loading, navigate }) {
  if (loading) return <Card><div style={{ color: COLORS.muted }}>Loading validators…</div></Card>;

  const sorted = [...(validators ?? [])].sort((a, b) => {
    try { return Number(BigInt(b.self_bond ?? "0") - BigInt(a.self_bond ?? "0")); } catch { return 0; }
  });

  const totalStaked = sorted.reduce((acc, v) => {
    try { return acc + BigInt(v.self_bond ?? "0"); } catch { return acc; }
  }, 0n);

  return (
    <div>
      <div style={{ marginBottom: 16, fontSize: 20, fontWeight: 700, color: COLORS.white }}>
        Validators
      </div>
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginBottom: 16 }}>
        <StatBox label="Total validators" value={sorted.length} />
        <StatBox label="Active" value={sorted.filter((v) => v.status === "active").length} accent={COLORS.green} />
        <StatBox label="Total staked" value={venomToVpr(totalStaked)} unit="VPR" accent={COLORS.amber} />
      </div>
      <Card>
        <Table
          columns={[
            { key: "rank", label: "#", render: (_, i) => i + 1 },
            { key: "address", label: "Address", render: (v) => <HashCell hash={v.address} onClick={() => navigate({ type: "account", address: v.address })} /> },
            { key: "status", label: "Status", render: (v) => {
              const c = v.status === "active" ? COLORS.green : v.status === "jailed" ? COLORS.red : COLORS.amber;
              return <Badge label={v.status} color={c} />;
            }},
            { key: "alg", label: "Algorithm", render: (v) => <Badge label={algIdToName(v.consensus_alg_id) ?? "—"} color={COLORS.amber} /> },
            { key: "stake", label: "Stake", render: (v) => venomToVpr(v.self_bond ?? "0") },
            { key: "registered_height", label: "Joined", render: (v) => v.registered_height != null ? `#${v.registered_height}` : "—" },
          ]}
          rows={sorted.map((v, i) => ({ ...v, _rank: i + 1 }))}
          emptyMsg="No validators found."
        />
      </Card>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Footer
// ---------------------------------------------------------------------------

function Footer({ status }) {
  return (
    <footer
      style={{
        borderTop: `1px solid ${COLORS.border}`,
        padding: "16px 24px",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center",
        color: COLORS.muted,
        fontSize: 12,
        marginTop: 48,
      }}
    >
      <span>Viper Chain Explorer</span>
      <span>
        {status
          ? `${status.chain_id} · height #${status.height}`
          : "not connected"
        }
      </span>
    </footer>
  );
}

// ---------------------------------------------------------------------------
// Top-level navigation
// ---------------------------------------------------------------------------

function NavBar({ view, setView }) {
  const items = [
    { id: "dashboard", label: "Dashboard" },
    { id: "validators", label: "Validators" },
  ];

  return (
    <nav
      style={{
        display: "flex",
        gap: 4,
        marginBottom: 24,
        borderBottom: `1px solid ${COLORS.border}`,
        paddingBottom: 0,
      }}
    >
      {items.map((item) => {
        const active = view?.type === item.id || (item.id === "dashboard" && !view?.type);
        return (
          <button
            key={item.id}
            onClick={() => setView({ type: item.id })}
            style={{
              background: "transparent",
              border: "none",
              borderBottom: active ? `2px solid ${COLORS.green}` : "2px solid transparent",
              color: active ? COLORS.green : COLORS.muted,
              padding: "10px 16px",
              fontWeight: active ? 700 : 400,
              fontSize: 13,
              borderRadius: 0,
            }}
          >
            {item.label}
          </button>
        );
      })}
    </nav>
  );
}

// ---------------------------------------------------------------------------
// Root App
// ---------------------------------------------------------------------------

function App() {
  const [baseUrl, setBaseUrl] = useState(getBaseUrl);
  const [status, setStatus] = useState(null);
  const [validators, setValidators] = useState([]);
  const [validatorsLoading, setValidatorsLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [view, setView] = useState({ type: "dashboard" });

  // Inject styles
  useEffect(() => {
    const style = document.createElement("style");
    style.textContent = CSS + `
      @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.3; }
      }
    `;
    document.head.appendChild(style);
    return () => document.head.removeChild(style);
  }, []);

  // Polling
  const poll = useCallback(async () => {
    try {
      const s = await apiFetch(baseUrl, "/v1/status");
      setStatus(s);
      setLastUpdate(Date.now());
    } catch {
      setStatus(null);
    }
  }, [baseUrl]);

  useEffect(() => {
    poll();
    const timer = setInterval(poll, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [poll]);

  // Validators on mount / baseUrl change
  useEffect(() => {
    setValidatorsLoading(true);
    apiFetch(baseUrl, "/v1/validators")
      .then(setValidators)
      .catch(() => setValidators([]))
      .finally(() => setValidatorsLoading(false));
  }, [baseUrl]);

  // Smart search
  const handleSearch = useCallback((query) => {
    const q = query.trim();
    if (!q) return;
    // Pure number → block height
    if (/^\d+$/.test(q)) {
      setView({ type: "block", height: parseInt(q) });
    // 64-char hex → could be account address or attestation ID
    } else if (/^[0-9a-fA-F]{64}$/.test(q)) {
      // Try as tx hash first (heuristic — no way to distinguish statically)
      setView({ type: "tx", hash: q });
    } else if (/^[0-9a-fA-F]{32,}$/.test(q)) {
      // Long hex → block hash or attestation
      setView({ type: "block", hash: q });
    } else {
      alert(`Cannot determine type for query: ${q}`);
    }
  }, []);

  const navigate = useCallback((target) => setView(target), []);

  const renderMain = () => {
    switch (view.type) {
      case "dashboard":
        return (
          <Dashboard
            status={status}
            validators={validators}
            baseUrl={baseUrl}
            navigate={navigate}
          />
        );
      case "validators":
        return (
          <ValidatorsView
            validators={validators}
            loading={validatorsLoading}
            navigate={navigate}
          />
        );
      case "block":
        return (
          <BlockView
            baseUrl={baseUrl}
            height={view.height}
            hash={view.hash}
            navigate={navigate}
          />
        );
      case "tx":
        return (
          <TxView
            baseUrl={baseUrl}
            hash={view.hash}
            navigate={navigate}
          />
        );
      case "account":
        return (
          <AccountView
            baseUrl={baseUrl}
            address={view.address}
            navigate={navigate}
          />
        );
      case "attestation":
        return (
          <AttestationView
            baseUrl={baseUrl}
            id={view.id}
            navigate={navigate}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <Header
        status={status}
        baseUrl={baseUrl}
        onBaseUrlChange={(url) => { setBaseUrl(url); setStatus(null); }}
        lastUpdate={lastUpdate}
      />
      <main style={{ flex: 1, maxWidth: 1200, width: "100%", margin: "0 auto", padding: "24px 24px 0" }}>
        <SearchBar onSearch={handleSearch} />
        <NavBar view={view} setView={setView} />
        {renderMain()}
      </main>
      <Footer status={status} />
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
