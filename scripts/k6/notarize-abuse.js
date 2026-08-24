// notarize-abuse.js — TASK-220 / L6a — k6 abuse + race tests against the
// Viper Notary `/api/notarize` endpoint.
//
// Four scenarios run sequentially in one k6 run:
//   1. burst         — 100 RPS sustained for 60 s; expect graceful
//                       degradation (status code distribution stays sane,
//                       NO 5xx; tail latency p95 < 30 s — the notary's
//                       own NOTARY_FINALIZATION_TIMEOUT_MS upper bound).
//   2. race          — 50 concurrent submissions with the SAME document
//                       hash; expect at most 1 success + others rejected
//                       cleanly (REPLACEMENT_UNDERPRICED or duplicate).
//   3. malformed     — random byte payloads; expect HTTP 400 always
//                       (NEVER 5xx, NEVER timeout).
//   4. auth_bypass   — POST over plain HTTP to the public hostname;
//                       expect 426 Upgrade Required from nginx (HSTS).
//
// # Running
//
//   docker run --rm -i grafana/k6 run --quiet --summary-export=summary.json - \
//     < scripts/k6/notarize-abuse.js
//
// or via local k6 binary:
//
//   k6 run --quiet --summary-export=reports/k6/$(date +%F).json \
//     scripts/k6/notarize-abuse.js
//
// # Dependencies
//
// k6 0.50+. NO node/npm. Inputs are inline; output is one JSON summary.
//
// # Why not in CI by default
//
// The notary backend is the live production service on the 3-host cluster.
// We do NOT want to hammer it on every push. Run manually after a notary
// release or when the canary cron rolls a new fee-market dimension.

import http from "k6/http";
import { check, sleep } from "k6";
import crypto from "k6/crypto";
import { randomBytes } from "k6/crypto";
import { SharedArray } from "k6/data";
import { Counter, Rate, Trend } from "k6/metrics";

const BASE_URL_HTTPS = __ENV.NOTARY_HTTPS || "https://pqchain.agwswebconsulting.it";
const BASE_URL_HTTP  = __ENV.NOTARY_HTTP  || "http://pqchain.agwswebconsulting.it";

// Per-scenario custom metrics so the summary distinguishes outcomes.
const burst_5xx        = new Counter("burst_5xx");
const burst_429        = new Counter("burst_429");
const burst_201        = new Counter("burst_201");
const burst_p95        = new Trend("burst_e2e_ms", true);
const race_201         = new Counter("race_201");
const race_dedup       = new Counter("race_dedup");
const malformed_400    = new Counter("malformed_400");
const malformed_5xx    = new Counter("malformed_5xx");
const auth_bypass_426  = new Rate("auth_bypass_426_rate");

export const options = {
  scenarios: {
    burst: {
      executor: "constant-arrival-rate",
      rate: 100,
      timeUnit: "1s",
      duration: "60s",
      preAllocatedVUs: 50,
      maxVUs: 200,
      exec: "burst",
      startTime: "0s",
    },
    race: {
      executor: "per-vu-iterations",
      vus: 50,
      iterations: 1,
      maxDuration: "30s",
      exec: "race",
      startTime: "65s",
    },
    malformed: {
      executor: "shared-iterations",
      vus: 10,
      iterations: 200,
      maxDuration: "60s",
      exec: "malformed",
      startTime: "100s",
    },
    auth_bypass: {
      executor: "shared-iterations",
      vus: 5,
      iterations: 20,
      maxDuration: "20s",
      exec: "auth_bypass",
      startTime: "165s",
    },
  },
  thresholds: {
    // Production SLOs (informational; the script never `--fail`s on them
    // — operators read the summary and decide).
    "http_req_failed":         ["rate<0.20"],
    "burst_e2e_ms":            ["p(95)<30000"],
    "auth_bypass_426_rate":    ["rate>0.95"],
    "malformed_5xx":           ["count<2"],
  },
  summaryTrendStats: ["min", "med", "avg", "p(90)", "p(95)", "p(99)", "max"],
};

function sha256_hex(s) {
  return crypto.sha256(s, "hex");
}

function unique_doc_hash() {
  // 32-byte SHA-256 of the VU id + iteration + a little entropy.
  const seed = `${__VU}-${__ITER}-${Date.now()}-${Math.random()}`;
  return sha256_hex(seed);
}

// ── Scenario 1 — burst ───────────────────────────────────────────────────
export function burst() {
  const body = JSON.stringify({ document_hash: unique_doc_hash() });
  const t0 = Date.now();
  const r  = http.post(`${BASE_URL_HTTPS}/api/notarize`, body, {
    headers: { "Content-Type": "application/json" },
    timeout: "30s",
  });
  burst_p95.add(Date.now() - t0);
  if (r.status === 201)              burst_201.add(1);
  else if (r.status === 429)         burst_429.add(1);
  else if (r.status >= 500)          burst_5xx.add(1);
  check(r, {
    "burst: no 5xx":   (resp) => resp.status < 500,
    "burst: 201 or rate-limited": (resp) => resp.status === 201 || resp.status === 429,
  });
}

// ── Scenario 2 — race (same doc_hash from 50 VUs simultaneously) ────────
const SHARED_DOC_HASH = sha256_hex("k6-race-" + Date.now());
export function race() {
  const body = JSON.stringify({ document_hash: SHARED_DOC_HASH });
  const r = http.post(`${BASE_URL_HTTPS}/api/notarize`, body, {
    headers: { "Content-Type": "application/json" },
    timeout: "20s",
  });
  if (r.status === 201)               race_201.add(1);
  else if (r.status === 400 || r.status === 409) race_dedup.add(1);
  check(r, {
    "race: no 5xx": (resp) => resp.status < 500,
  });
}

// ── Scenario 3 — malformed payloads ─────────────────────────────────────
function rand_payload() {
  const n = 16 + (__ITER % 256);
  const buf = randomBytes(n);
  // Sometimes valid JSON with garbage doc_hash, sometimes raw bytes.
  if (__ITER % 3 === 0) return new Uint8Array(buf);
  if (__ITER % 3 === 1) return JSON.stringify({ document_hash: "not-a-hex" });
  return JSON.stringify({ unrelated: "field", document_hash: "Z".repeat(64) });
}
export function malformed() {
  const r = http.post(`${BASE_URL_HTTPS}/api/notarize`, rand_payload(), {
    headers: { "Content-Type": "application/json" },
    timeout: "15s",
  });
  if (r.status === 400)        malformed_400.add(1);
  else if (r.status >= 500)    malformed_5xx.add(1);
  check(r, {
    "malformed: rejected with 4xx, never 5xx": (resp) => resp.status >= 400 && resp.status < 500,
  });
}

// ── Scenario 4 — auth bypass via plain HTTP ─────────────────────────────
export function auth_bypass() {
  const body = JSON.stringify({ document_hash: unique_doc_hash() });
  const r = http.post(`${BASE_URL_HTTP}/api/notarize`, body, {
    headers: { "Content-Type": "application/json" },
    timeout: "10s",
    redirects: 0,
  });
  // Accept either:
  //   - 426 Upgrade Required (server enforces TLS)
  //   - 301/302/308 to https:// (also acceptable hardening posture)
  const ok =
    r.status === 426 ||
    (r.status >= 300 && r.status < 400 && r.headers["Location"] && r.headers["Location"].startsWith("https://"));
  auth_bypass_426.add(ok ? 1 : 0);
  check(r, {
    "auth_bypass: HTTP either upgraded or redirected to HTTPS": () => ok,
  });
}
