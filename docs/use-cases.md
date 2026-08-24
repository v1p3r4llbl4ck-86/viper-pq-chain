# Viper PQ Chain — Use Cases

Concrete use cases for Viper PQ Chain as digital-trust infrastructure,
ordered by distance from a working deployment. This is a description of
what the chain is designed to certify; it is not a commercial offer.
`viper-testnet-1` has no native token and nothing is sold on it.

Originally written 2026-04-17; revised for the public release.

---

## Guiding principle

The chain does not issue documents and does not hold personal data. It
**certifies** that a document was issued, by whom, when, and that it has
not been altered since. Only the document's hash is anchored on chain;
the original stays with the issuer. The certification is post-quantum
(ML-DSA / SLH-DSA signatures, SHA3/SHAKE hashing, see `specs/`) and is
meant to remain verifiable for 20+ years — the real lifetime of legal
records, credentials and industrial certifications.

Two protocol primitives cover every case below:

- **Attestation** — an issuer-signed record binding a subject, a content
  hash and a schema identifier (`/v1/attestations/{id}`, issued through
  `/api/credentials/issue`).
- **Proof anchor** — a timestamped hash of an arbitrary document or
  batch (`/v1/proofs/{anchor_id}`, created through `/api/proofs/anchor`).

Both are ordinary transactions validated by every full node and served
by every `rpc` node; the optional notary service in the Helm chart is a
convenience front-end, not a protocol component.

---

## 1. Document notarisation

**Status**: exercised on the retired research chains (hash anchoring,
verification by attestation id, explorer).

**Who uses it**: notaries, law firms, companies, professionals.

**What the chain does**: a document (contract, deed, appraisal, balance
sheet) is hashed client-side in the browser. The hash is anchored on
chain with an immutable timestamp and the signer's identity. The
original never leaves the user's device.

**Problem addressed**: a notary certifies today with a classical digital
signature (RSA/ECDSA). Within 10–15 years a quantum computer may forge
that signature retroactively, while a notarial deed must stay valid for
30+ years. A post-quantum signature from day one avoids a retrofit.

**Example**: a notary certifies a property sale. The deed's hash is
anchored on chain. Twenty years later anyone can verify that the
document existed in that form on that date; verification uses an
attestation id and exposes no personal data.

---

## 2. Academic credentials

**Status**: implementable with the current primitives (attestation +
proof anchor).

**Who uses it**: universities, vocational training bodies, education
ministries.

**What the chain does**: the university issues a digital diploma. The
diploma's hash and its metadata (student, course, date, grade, issuer)
are anchored as an attestation; only the university's key can issue
attestations for its schema.

**Problem addressed**: forged diplomas are a global problem and
traditional verification takes weeks. With an attestation, an employer
verifies in seconds that a diploma is genuine, issued by that
university, on that date.

**Example**: a recruiter abroad scans a QR code printed on the
certificate and gets an instant, unforgeable verification that stays
valid for decades.

**Reference points**: MIT already issues blockchain-based digital
diplomas; the European Blockchain Services Infrastructure (EBSI) runs a
pilot for educational credentials. Neither carries a post-quantum
guarantee.

---

## 3. Supply chain and origin certification

**Status**: implementable with proof anchors plus one attestation per
step of the chain.

**Who uses it**: food producers, protected-origin consortia (PDO/PGI),
luxury brands, exporters.

**What the chain does**: every step of the production chain (raw
material intake, processing, ageing, quality control, packaging,
shipping) is attested on chain by the party responsible for that step.
The end consumer scans a QR code and sees the whole chain of
certifications, each with a timestamp, the attesting identity and the
hash of the supporting document.

**Problem addressed**: counterfeit origin claims are worth tens of
billions of euro per year. Today's certifications are PDF documents
sent by e-mail — easy to forge, not verifiable by the consumer, not
independently traceable. An attestation is immutable, public and
verifiable by anyone with internet access.

**Example**: a dairy in a protected-origin consortium anchors each
phase — milk received (date, farm, health certificate), ageing started
(date, warehouse, lot), ageing completed (24 months verified, quality
check), shipment (destination, carrier). A restaurant on another
continent scans the wheel's QR code and sees the certified path.

---

## 4. Long-term enterprise digital signatures

**Status**: implementable (signing through the wallet CLI + on-chain
attestation).

**Who uses it**: banks, insurers, leasing companies, large corporates.

**What the chain does**: digitally signed documents (contracts, policies,
mortgages, framework agreements) are anchored at signing time. The
proof anchor holds the document hash, the parties' identities and the
timestamp. The on-chain signature is post-quantum and independent of
the signature algorithm used in the original document.

**Problem addressed**: a mortgage lasts 30 years. The signature it
was signed with in 2026 (typically RSA-2048 or ECDSA P-256) may be
forgeable in 2040. The post-quantum anchor makes the proof of signing
independent of the original algorithm — even if RSA is broken, the
anchor stays valid.

**Example**: a bank signs a thirty-year mortgage. The contract hash,
timestamp and parties' identities are anchored. Twenty-five years later,
in a dispute, the bank produces the anchor as evidence that the
contract existed in that form on that date.

---

## 5. Identity-document issuance certification

**Status**: medium-to-long-term direction (requires institutional
partners).

**Who uses it**: governments, interior ministries, digital-identity
agencies, border control.

**What the chain does**: the issuing office anchors the proof that "the
document with serial X was issued on date D by office Y for citizen Z".
Only the hash of the biometric and identity data is anchored; personal
data is never published on chain.

**Problem addressed**: electronic passports (ICAO 9303) carry RFID
chips with classical digital signatures. ICAO has started to study the
migration to post-quantum cryptography because a passport is valid for
10 years and must be verifiable for 30+. European electronic identity
cards (eIDAS 2.0) have the same problem.

**Example**: a border check verifies the passport chip (classical
signature) and the issuance attestation on chain (post-quantum
signature). If the chip signature is compromised in the future, the
attestation still holds.

---

## 6. Healthcare — informed consent and clinical records

**Status**: technically implementable; subject to healthcare compliance.

**Who uses it**: hospitals, local health authorities, pharmaceutical
companies (clinical trials), contract research organisations.

**What the chain does**: the patient's informed consent is hashed and
anchored. Parts of the clinical record (reports, prescriptions, test
results) can be attested with an immutable timestamp. No health data is
on chain — only hashes and metadata.

**Problem addressed**: GDPR requires demonstrable proof of consent. In a
medico-legal dispute, proving that consent was given in that form on
that date is decisive; the limitation period for medical liability in
several EU jurisdictions is 10–20 years, longer than the expected
lifetime of today's classical signatures.

**Clinical trials**: a pharmaceutical company runs a multi-centre trial.
The data of every visit is hashed and anchored; a regulator can verify
that the data was not altered after the fact.

---

## 7. Industrial IoT — sensor-data certification for compliance

**Status**: implementable with batched proof anchors (one anchor per
batch of readings).

**Who uses it**: manufacturers, energy companies, automotive, companies
under the EU Emissions Trading System.

**What the chain does**: industrial sensor data (temperature, pressure,
emissions, energy consumption) is grouped into periodic batches (hourly,
per shift), hashed and anchored as a proof anchor. The anchor attests
that the data existed in that form at that moment.

**Problem addressed**: environmental compliance (EU ETS, carbon credits,
ESG reporting) requires verifiable, tamper-proof data. Today sensor
data lives in corporate databases that can be edited retroactively
without trace, so an auditor has to trust the company's IT systems.

**Example**: a steel plant under EU ETS anchors its hourly CO2
measurements. The auditor reads the on-chain timeline and checks that
the declared figures match. If data is manipulated before anchoring,
the hash will not match the sensor's own independent log.

---

## What every case has in common

| Property | How the protocol provides it |
|----------|------------------------------|
| No custody of documents or personal data | only hashes and issuer-signed metadata go on chain |
| Long verifiability horizon | post-quantum signatures at genesis, hash-based archival overlay (`specs/archival-overlay.md`) |
| Independent verification | any `full`, `rpc` or `archive` node serves the read API; the light-client verifier (`crates/pqc-light-client`, Apache-2.0) checks proofs without a full node |
| Attributable issuance | attestations are signed with the issuer's registered key set (`specs/account-keyset-registry.md`) |

Prioritisation, pricing and go-to-market considerations are business
material and are kept out of the public technical documentation.
