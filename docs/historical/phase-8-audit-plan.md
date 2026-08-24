# Audit esterni di sicurezza per un L1 post-quantum: guida operativa alla Fase 8

L'audit esterno non è un evento, è un'infrastruttura. Per un L1 scritto in Rust, con consenso BFT, ML-DSA primario e SLH-DSA secondario, e un orizzonte di verificabilità di 20+ anni, servono **quattro audit distinti, coordinati, sequenziati** e un budget realistico di **€600k–€1,5M** — di cui una quota reimbursabile sotto il grant EIC Accelerator. Il rischio più serio nella Fase 8 non è "trovare bug", è **arrivare impreparati** e bruciare le prime due settimane di ogni engagement per carenze di igiene di codice che qualunque CI avrebbe dovuto catturare. Questo rapporto definisce esattamente cosa preparare, come scegliere i vendor, come gestire il processo, come coordinare quattro audit paralleli senza gap di copertura e come integrare il tutto nelle certificazioni UE pertinenti (EUCC, eIDAS 2.0, TR-ESOR). La sezione finale contiene un piano d'azione aprile–giugno 2026 tarato sul progetto.

---

## 1. Il quadro: quattro audit, una sola catena di fiducia

Un L1 post-quantum richiede **quattro domini di audit** che coprono superfici d'attacco non sovrapposte ma interdipendenti.

Il **code audit** (stile Trail of Bits, OpenZeppelin, Halborn, Sigma Prime, Zellic, Quantstamp, ConsenSys Diligence) guarda il codice Rust: overflow, panic, serializzazione, unsafe, concorrenza, gestione degli errori. Il **cryptographic audit** (PQShield, NCC Group Cryptography Services, Kudelski, Cure53, Least Authority, Cryspen, Quarkslab, Fraunhofer AISEC) guarda le primitive — conformità FIPS 204/205, canali laterali, sampling, randomness, agility. Il **protocol/consensus audit** (Informal Systems, Runtime Verification, Certora, ChainSecurity, Galois) guarda safety e liveness del BFT, view change, equivocation, riconfigurazione, e spesso richiede una **specifica formale** in TLA+/Quint/Lean. L'**infrastructure audit** (Bishop Fox, NCC Group, Trail of Bits, Praetorian, Kudelski, Cure53, Doyensec, Atredis) guarda validator setup, HSM, separazione hot/cold, remote signer, DVT, pipeline di supply chain, time synchronization.

**La catena di dipendenze è rigida**: la crypto viene prima del protocollo (il consenso assume signature forgery-resistant), il codice prima dell'ops (l'infra protegge codice validato), la specifica formale prima o in parallelo al code audit. Saltare quest'ordine significa che un bug crypto invalida i risultati del consensus audit, oppure che l'infra audit blinda codice che a sua volta cambia radicalmente dopo il code audit.

**La lezione generale** — confermata dalle statistiche pubbliche di Trail of Bits — è che **~35% dei finding high-severity non sono rilevabili da tool automatici** e quasi la metà richiede ragionamento semantico su invarianti documentali. Nessun audit, da solo, è sufficiente: si combinano audit multi-vendor, bug bounty continuo, monitoring runtime, e re-audit periodico.

---

## 2. Audit del codice Rust: come prepararsi e cosa aspettarsi

### 2.1 Preparazione — il filtro "is this codebase ready?"

Un auditor tier-1 decide nelle prime 48 ore se la codebase è "ready" o se il cliente ha buttato i soldi. I segnali che fanno dire *"come back when you've done your homework"* sono ben noti: dipendenze non pinnate, `unsafe` senza commento `// SAFETY:`, `.unwrap()` nell'hot path del consenso, mancanza di test di canonicità sulla serializzazione, zero fuzzing commit su corpus persistente, nessun tag firmato, nessun SBOM. Al contrario, la codebase "ready" arriva con una **cartella `audit/` dedicata** contenente tutto quanto segue.

**Documentazione minima**: `README` con toolchain pinnata (`rust-toolchain.toml`); `ARCHITECTURE.md` con crate graph e trust boundaries; `THREAT-MODEL.md` che enumera asset (chiavi validator, fondi, liveness, finality), avversari (validator bizantino, RPC malevolo, MEV searcher, network-level attacker), superfici e invarianti di sicurezza; la specifica del protocollo in forma machine-checkable (Quint o TLA+) o almeno pseudocodice che rispecchia l'implementazione; un `KNOWN-ISSUES.md` — il documento di disclosure interna — con tutto ciò che il team sa essere rotto, accettato come rischio, o in TODO, che paradossalmente **aumenta la credibilità** dell'ingaggio invece di diminuirla.

**Code freeze e signed tag**: `git tag -s audit-v1.0.0` con GPG o Sigstore. Trail of Bits, NCC, Informal Systems esigono un commit hash frozen al kickoff. Qualunque cambio post-freeze richiede change-order scritto.

**Igiene Rust obbligatoria**: `cargo clippy --all-targets --all-features -- -D warnings` pulito; `cargo fmt --check` passante; lint denied in `clippy.toml` per `unwrap_used`, `expect_used`, `indexing_slicing`, `integer_arithmetic`; **zero `TODO`/`FIXME`/`todo!()`/`unimplemented!()`** nei path critici (consenso, crypto, verifica firma, state transition, slashing). `overflow-checks = true` anche in release.

**Toolchain di supply chain e analisi statica che deve girare in CI prima dell'audit**:

| Tool | Scopo | Comando |
|---|---|---|
| `cargo-audit` | Scan RustSec advisory DB | `cargo audit --deny warnings` |
| `cargo-deny` | License, duplicate deps, banned crates | `cargo deny check` |
| `cargo-vet` (Mozilla) | Supply-chain, import delle decisioni di audit da Mozilla/Google/Bytecode Alliance/ISRG/Zcash | `cargo vet` |
| `cargo-geiger` | Metrica unsafe nell'albero | `cargo geiger` |
| MIRI | UB interpreter su MIR (aliasing, data race, leak) | `cargo +nightly miri test` |
| `cargo-careful` | Extra-check su std in debug | `cargo +nightly careful test` |
| Sanitizers | ASan/TSan/MSan via `-Zsanitizer=` | `RUSTFLAGS` nightly |
| Loom | Tester esaustivo del C11 memory model | `--cfg loom` |
| Shuttle (AWS) | Randomized concurrency tester | Libreria |
| **Kani** (AWS) | Bounded model checker MIR→CBMC; usato in Firecracker, s2n-quic | `cargo kani` |
| Creusot / Prusti / Verus | Verifica deduttiva | Annotazioni |

**Fuzzing**: `cargo-fuzz` (libFuzzer) è il minimo; `honggfuzz-rs` e `LibAFL` per coverage avanzata. Ogni *fuzz target* deve avere un corpus committato in `fuzz/corpus/<target>/` seminato con dati reali (blocchi mainnet di test, tx, frame p2p). Lo standard OSS-Fuzz e la norma industriale pongono **minimo 24–72 CPU-hour per target**, preferibilmente **settimane continue**. Saturazione = `cov:`/`ft:` in plateau oltre 24h. **Differential fuzzing** è critico per codec (Borsh, SCALE, bincode, protobuf): due decoder, stesso input, asserire equivalenza. Fuzzing struttura-aware via crate `arbitrary` + `#[derive(Arbitrary)]` evita sprechi su input triviali. Integrazione continua con ClusterFuzzLite o OSS-Fuzz. Property testing con `proptest` e `quickcheck`.

**Reproducible builds** via Nix flakes o Docker determinista, con SBOM CycloneDX/SPDX generato via Syft o `cargo-cyclonedx`, firmato con Sigstore Cosign. **SLSA v1.1 Build Track L3** è il target per il testnet pubblico: provenance non-forgiabile, build isolato, policy-controller in ammissione.

**Bug bounty e disclosure policy**: prima dell'audit, pubblicare `/.well-known/security.txt` (RFC 9116) con Contact ed Expires; avere una disclosure policy scritta; il programma Immunefi/Cantina/Sherlock si lancia **dopo** l'audit ma **prima** del mainnet (il ragionamento: l'audit elimina il low-hanging fruit, altrimenti si brucia budget bounty su finding banali; ma il bounty cattura ciò che l'audit ha mancato prima che il TVL cresca).

### 2.2 Cosa cercano gli auditor nel codice Rust

La metodologia combina **threat modeling** (STRIDE prevale; DREAD deprecato; PASTA per workflow strutturati; attack tree alla Schneier con costi), **manual review** con mindset avversariale, **scanning automatico**, **fuzzing**, e **symbolic/bounded model checking** (Kani è la scelta pratica per Rust; KLEE e Crux-MIR sono limitati).

Le **classi di finding tipiche in un L1 Rust** sono:

- **Integer overflow** nonostante Rust: uso di `+` invece di `checked_add` in contabilità stake/reward/supply — il bug Solana 2022 che moltiplicò stake ×100 è il caso paradigmatico. Mitigazione: `checked_*` con errore esplicito per contabilità finanziaria, `saturating_*` per metriche non critiche.
- **Panic safety sui validator**: un `.unwrap()` o uno slice `[..]` su input di rete = halting del validator; se deterministico, halting di tutta la rete. Ogni unwrap deve avere `// SAFETY:` che prova infallibilità.
- **Unsafe code**: UAF, `transmute`, impl unsound di `Send`/`Sync`, FFI. Audit con MIRI, cargo-geiger, Kani.
- **Serializzazione malleable**: encoding non canonici in serde/bincode/Borsh/SCALE/protobuf — rompono signature verification, Merkle root, dedup per tx-hash. Borsh e SCALE sono canonici by design ma i bug su length-prefix e trailing-byte ricorrono.
- **Async cancellation safety**: future droppate a metà `.await` lasciano lock acquisiti o contatori inconsistenti. Tokio `select!` è fonte ricorrente.
- **Lock-ordering deadlock**: nested `Mutex`/`RwLock` in ordini differenti — Loom/Shuttle li trovano.
- **Unbounded allocation da input di rete**: `Vec::with_capacity(attacker_len)`, canali senza limite, queue gossipsub senza bound → OOM DoS.

**Tassonomia di severità** (stile Trail of Bits/NCC): **Critical** = perdita diretta di fondi, consensus halt esploitabile da singolo attaccante, forgery di firma, safety violation (Wormhole guardian bypass, 120k wETH coniati); **High** = validator crash, slashing di validator onesti, MEV significativa, escalation (Solana duplicate-block fork-choice bug, outage di 8,5h nel 2022); **Medium** = degradazione sotto condizioni avversariali, info leak, griefing a costo limitato; **Low** = defense-in-depth; **Informational** = hardening e documentazione. Trail of Bits aggiunge una **scala di difficoltà** ortogonale: il worst case è "high-severity / low-difficulty".

### 2.3 Vendor per il code audit

I riferimenti tier-1 per Rust L1 sono **Trail of Bits** (New York, publicazioni complete su github.com/trailofbits/publications; maintainer di Slither/Echidna/Medusa; forte in Rust), **Zellic** (team ex-Perfect Blue CTF, specialisti Rust/Move/Cairo, audit Aptos/Sui/EigenLayer/Arbitrum), **Sigma Prime** (Melbourne, costruttori del client Lighthouse in Rust, profonda expertise su Ethereum), **OtterSec** (Solana/Move/Aptos/Sui, pioneri dell'uso di Kani su programmi Solana), **Halborn** (Miami, ampia copertura L1 con Solana/Avalanche/Polygon/THORChain), **ChainSecurity** (Zurigo, spinout ETH, ora acquisita da PwC, forte metodologia accademica), **ConsenSys Diligence** (Ethereum-centric, tool MythX/Scribble), **OpenZeppelin** (standard industriale ma meno L1-focused), **Dedaub** (Malta/UK, analisi a livello bytecode), **Spearbit/Cantina** (rete distribuita di researcher, buon per review complementari). Escluderei **CertiK** dalla shortlist tier-1 nonostante il volume: la reputazione tecnica è mista e il "Security Score" pubblico è visto con scetticismo dalla community.

**Costi 2025–2026 per L1 Rust**: code audit medio $150k–$500k per 3–8 settimane; audit premium su codebase ampia $500k–$1M. Rush premium 30–50%. Formal verification add-on $20–50k.

### 2.4 Report pubblici da studiare come modelli

Studiare **il report Trail of Bits su Drift** (drift.trade/updates/tob-security-audit) per il formato "Resolved/Partially/Unresolved/Risk Accepted"; il repo **github.com/trailofbits/publications** per lo stile ToB; **github.com/informalsystems/audits** per audit formalmente-specificati su Cosmos/Celestia; **github.com/availproject/audits** e **github.com/Hexens/Smart-Contract-Review-Public-Reports** come cataloghi aperti; gli audit di **Lighthouse ETH2 da Sigma Prime**, di **Prysm da Quantstamp/Trail of Bits**, di **Zcash da NCC Group/Least Authority** (cryptoservices.github.io) per standard di comunicazione. L'**OtterSec report su Solana Anchor** dimostra l'uso di Kani in produzione (osec.io/blog/2023-01-26-formally-verifying-solana-programs).

---

## 3. Audit crittografico post-quantum: il dominio più scarso del mercato

### 3.1 Il problema dell'offerta

A livello globale, il numero di firm realmente qualificate per un audit PQ rigoroso si conta su due mani. Le credenziali autoritative, non autodichiarate, sono:

- **Cryspen** (Germania/Francia): maintainer di **libcrux**, libreria Rust formalmente verificata (ML-KEM, ML-DSA, SHA-3) via **hax** + **F***. Hanno trovato un timing bug nel loro stesso ML-KEM tramite la verifica — è il livello più alto di assurance crypto disponibile per Rust.
- **Quarkslab** (Francia): **CESTI** accreditato ANSSI — credenziale formale, non autodichiarata. Esegue valutazioni CSPN per il settore difesa francese. Tooling proprietario (Crypto Condor, DeltAFLy) per FIPS 203/204/205.
- **Fraunhofer AISEC** (Germania): commissionata da **BSI** per studi di laser fault injection su XMSS (2024). Research su Impeccable Keccak, masking di Kyber/Dilithium. Partner riconosciuto dal governo tedesco.
- **PQShield** (UK, Oxford): co-author delle submission NIST (Falcon, CRYSTALS, Classic McEliece, SPHINCS+); partecipa al pilot NCSC ACSC. FIPS 140-3 dichiarato "in progress" — **da verificare sulla lista NIST CMVP Modules-In-Process** prima di impegnarsi.
- **NCC Group Cryptography Services**: practice storica (ex iSEC Partners); audit pubblici su Cloudflare TLS 1.3, Zcash, Let's Encrypt. Partecipa NCSC ACSC.
- **Kudelski Security** (Svizzera): integra ML-KEM/ML-DSA/LMS nel secure enclave KSE, founding member della Linux Foundation PQCA.
- **Trail of Bits**: cryptography practice con track record recente (audit del crypto stdlib di Go per Google inclusa ML-KEM, 2024–2025); rilasciate librerie Rust SLH-DSA e Go ML-DSA; sviluppato **LLVM intrinsics constant-time** (`__builtin_ct_select`).
- **SandboxAQ** (spin-out Alphabet): più un partner di crypto-agility/inventory (AQtive Guard, Sandwich) che un audit lab tradizionale; utile per il framework di agilità, meno per il code-level crypto review.

La combinazione tipica multi-vendor ottimale per il progetto è **Cryspen** (FV sulle librerie ML-DSA/SLH-DSA) + **Quarkslab o Fraunhofer AISEC** (side-channel/fault con riconoscimento ANSSI/BSI) + **NCC Group o Trail of Bits** (layer protocollo e integrazione blockchain).

### 3.2 Cosa esigere nell'SoW crypto

1. **Constant-time** su NTT, Barrett/Montgomery reduction, rejection sampling, moltiplicazione polinomiale: nessun branch o memory access secret-dependent. Gli LLVM intrinsics di Trail of Bits e le prove hax/F* di Cryspen sono lo state of the art.
2. **Side-channel**: timing, power (SPA/DPA), EM, cache (Flush+Reload, Prime+Probe). FIPS 204 non obbliga SCA resistance, ma **EUCC AVA_VAN.4/.5 e CSPN ANSSI sì**.
3. **Conformità FIPS 203/204/205** validata con **ACVP vectors** e KAT; allineamento CAVP/CMVP; verifica della domain separation SHAKE-128/256 e del contesto (FIPS 204 §5.4).
4. **Rejection sampling quality**: `SampleInBall` di ML-DSA; bound di terminazione.
5. **RNG sources**: NIST SP 800-90A/B/C; DRBG; hedged signing che aggiunge entropia per-firma. Evitare `OsRng` da solo (per documentazione libcrux): stratificare un DRBG.
6. **Hybrid mode**: nessun downgrade, combiner autenticato, binding delle due firme per prevenire stripping. ENISA ed ETSI raccomandano PQ/T ibrido.
7. **Crypto-agility**: identificatore algoritmo, parameter set, key format versionati nella envelope di firma blockchain; registry di verificatori effettivamente swappable; test di dispatch.
8. **Parameter sets**: ML-DSA-65 (categoria NIST 3) raccomandato NCSC/BSI per uso generale, firma ~3309 byte; ML-DSA-87 (categoria 5) per archival high-assurance; ML-DSA-44 solo per uso low-security dove lo spazio è critico.
9. **Deterministic vs hedged signing**: entrambi permessi da FIPS 204. Il deterministic è semplice ma vulnerabile a differential fault analysis (stesso nonce, due firme, input stesso = leak della chiave). Per un signer blockchain esposto a fault-capable adversary, **hedged è raccomandato**.
10. **Fault attacks**: countermeasures includono computazione ridondante, verifica della firma prima del rilascio, Keccak mascherato (Impeccable Keccak di Fraunhofer).

### 3.3 Librerie: preferenza degli auditor

La preferenza quasi universale è **non scrivere crypto custom**. La scelta pragmatica, per un L1 Rust archival-grade:

| Libreria | Linguaggio | ML-DSA | SLH-DSA | Assurance |
|---|---|---|---|---|
| **libcrux (Cryspen)** | Rust puro | ✓ (portable + AVX2) | — | **Formalmente verificato** via hax/F* |
| RustCrypto `fips204` / `ml-dsa` / `slh-dsa` | Rust puro | ✓ | ✓ (slh-dsa by Trail of Bits) | Peer-reviewed, non FV |
| AWS-LC PQ | C | ✓ | ✓ | FIPS 140-3 validato |
| liboqs (PQCA) | C | ✓ | ✓ | KAT continuo, non FV |
| PQClean | C | ✓ | ✓ | Reference, no SCA hardening |
| pqcrypto-rust | Rust (FFI a PQClean) | ✓ | ✓ | Eredita il comportamento C |

**Raccomandazione operativa**: libcrux come primary signer ML-DSA; RustCrypto `slh-dsa` o AWS-LC per SLH-DSA archival. Questa combinazione massimizza la revisione pubblica e minimizza il volume di codice custom da far auditare.

### 3.4 Impatto operativo delle dimensioni delle firme

ML-DSA-44: pk 1312 B / sig ~2420 B. ML-DSA-65: **pk 1952 B / sig ~3309 B**. ML-DSA-87: pk 2592 B / sig ~4627 B. SLH-DSA-128s: **sig ~7856 B**; 128f: ~17 KB. SLH-DSA-256s: **sig ~29 KB**; 256f: ~49 KB. Le firme ML-DSA-65 sono ~50× Ed25519 (64 B): il modello di throughput del consensus, la banda mempool, e la crescita di state vanno rimodellati. **SLH-DSA va riservato alle firme anchor** (record di evidenza notary, checkpoint) e mai a firma per-transaction.

### 3.5 Archival 20+ anni: perché hash-based vince

Le firme lattice-based (ML-DSA) hanno track record di sicurezza più breve di quelle hash-based. Per orizzonti multi-decennali, **hash-based preferito** perché la sicurezza si riduce a proprietà generiche delle hash function (preimage/collision), indebolite dal quantum solo per Grover (√n).

Schemi praticabili: **SLH-DSA** (FIPS 205, stateless, ideale per blockchain dove lo state management è impossibile); **XMSS/XMSSMT** (RFC 8391, stateful, firme più piccole, NIST SP 800-208); **LMS/HSS** (RFC 8554, stateful, preferito da CNSA 2.0 per firmware signing).

**Framework normativo europeo** per la preservazione notarile:
- **ETSI TS 119 511 v1.2.1 (ottobre 2025)**: policy e security per long-term preservation di firme digitali sotto eIDAS Art. 34(2)/40.
- **ETSI TS 119 512 v1.1.1**: protocolli di preservazione.
- **RFC 4998 / RFC 6283** — Evidence Record Syntax (ERS): time-stamp chaining, hash-tree renewal.
- **BSI TR-03125 (TR-ESOR) v1.3**: riferimento tedesco; architettura M.1 ArchiSafe / M.2 Cryptographic / M.3 ArchiSig; pienamente compatibile con ETSI TS 119 511/512. **Obbligo di algorithm-agility**: re-signing/re-timestamping periodico da algoritmi in **ETSI TS 119 312** e **SOG-IS ACM**.
- **ECCG Agreed Cryptographic Mechanisms v2.0 (maggio 2025)**: **ammette ufficialmente ML-KEM, ML-DSA, SLH-DSA e PQ/T ibrido** per EUCC.

---

## 4. Audit di protocollo e consenso BFT

### 4.1 Specifica formale come prerequisito

Firm come **Informal Systems** e **Runtime Verification** rifiuteranno o declasseranno un engagement che non parta da specifica formale. I formati accettati sono:

- **TLA+** (Lamport) con TLC o **Apalache** (model checker simbolico SMT-based, scala dove TLC esplode) o TLAPS; usato su Tendermint/IBC/Light Client, DiemBFT.
- **Quint** (Informal Systems): sintassi moderna tipata sopra la logica TLA+, eseguibile, backend Apalache/TLC. Già usato su Malachite (Tendermint in Rust), Sui Mysticeti, Solana Alpenglow Votor, ZKsync ChonkyBFT, Neutron DEX migration.
- **Ivy**, **Coq** (usato da Runtime Verification su Casper FFG per la Ethereum Foundation), **Lean 4** (Celestia, ZK circuits), **Isabelle/HOL** (CBC Casper LayerX, seL4).
- **K framework** (tecnologia proprietaria di Runtime Verification): KEVM, semantics IELE Cardano, deposit contract ETH2.
- **Stateright** per Rust-native model checking; **Kani** BMC su MIR per proof property-level in Rust.

Per un nuovo BFT è raccomandato **Quint** come pragmatic sweet spot: sintassi familiare, testabile, comunity Informal reattiva, riusabile dall'auditor.

### 4.2 Proprietà da provare

**Safety** (agreement): nessun validator onesto committa valori conflittuali alla stessa altezza. **Validity**: il valore committato è stato proposto da qualche validator (versione forte: da uno onesto). **Termination/Liveness**: ogni validator onesto eventualmente committa. **Accountable safety**: le violazioni producono evidenza crittografica che identifica ≥⅓ dello stake colpevole (Casper FFG, Tendermint).

**Fault bound**: `f < n/3` sotto synchrony parziale (DLS 1988); FLP impedisce determinismo sotto asynchrony totale. Il timing model standard è partial synchrony con GST ignoto: safety sempre preservata, liveness solo post-GST.

**Famiglie di protocollo**: PBFT (O(n²) stato stabile, O(n³) view change); Tendermint (lock-based, non responsive, richiede attesa Δ); HotStuff (lineare con threshold sig, 3-chain commit rule, responsive); Jolteon/DiemBFT/AptosBFT (2-chain HotStuff, view change quadratico); Ditto (Jolteon + fallback asincrono); **Narwhal+Bullshark/Tusk** (DAG mempool + consensus; usato da Sui); **Mysticeti** (Sui, 2024, uncertified DAG, commit ogni round, 390ms latency/640ms finality); **HotStuff-2** (2023, 2-phase responsive lineare); **Alpenglow/Votor** (prossimo Solana).

### 4.3 Classi di finding tipiche nel consensus

View-change bug (lock non trasferiti, HighQC non propagato, TC validation mancante); mancata emissione di evidenza di equivocation; race condition nella riconfigurazione (snapshot stake off-by-one — esattamente il bug Solana 2022); weak subjectivity window debole nei checkpoint; **long-range attack** con vecchie chiavi validator su storia alternativa, mitigato da weak subjectivity, key-evolving sig, finality gadget; **nothing-at-stake**, mitigato da slashing; **stake grinding** (bias della randomness withholding blocchi — VDF, BLS aggregation, DKG-beacon); **time manipulation** con clock skew per attaccare slashing DB (es. attestation future-dated surround-vote); **MEV a livello consensus** (leader che censura/riordina/propone condizionale), mitigato da proposer-builder separation; stallo sotto asynchrony (HotStuff/DiemBFT vulnerabile se avversario ritarda leader designato — VABA/Ditto fallback).

### 4.4 Finding P2P/libp2p

**Eclipse**: sybil che circondano la vittima, mitigato da GossipSub v1.1 mesh quota D_out, opportunistic grafting, flood publishing dalla source (specifica ufficiale libp2p; audit pubblico Least Authority su GossipSub v1.1, leastauthority.com). **Sybil**: mitigato da IP-colocation penalty P7, signed peer records, topic stake-gated. **DoS amplification**: validare length prefix, max-size, rate limit per peer. **Peer-score bypass** (P1–P7): attaccante accumula score da actor onesto e poi censura via hairpin-drop — mitigato da flood publish + adaptive gossip. **DHT/Kademlia poisoning**: S/Kademlia disjoint path, signed records. **Circuit Relay v2 abuse**: unbounded reservation, mitigato da round-robin load balancing. **Transport security**: Noise, QUIC/TLS 1.3 — replay 0-RTT, downgrade, curve confusion. **Unbounded queue per peer**: bound obbligatorio + drop policy. **Protocol-negotiation downgrade**: signed peer records, pin protocol list.

### 4.5 Esempi reali

**Solana outages** (helius.dev/blog/solana-outages-complete-history): Sep 2021 memory overflow da bot spam (17h halt); Jan/Apr/May 2022 congestion CU/mint NFT; Jun 2022 clock drift; **Sep 2022 duplicate-block fork-choice bug da hot-spare validator (8,5h outage)**; Feb 2023 oversized block saturates Turbine; Feb 2024 infinite JIT recompile loop. Ognuno di questi è un case study di classe di finding.

**Tendermint/Cosmos SDK**: Informal Systems cattura l'**Amnesia attack** (due commit conflittuali) con formal work Quint+Apalache; advisory pubblici su github.com/cosmos/cosmos-sdk/security (Dragonberry IAVL/ICA).

**ETH2 Casper FFG**: Runtime Verification formalizzata in K+EVM ha trovato bug del compiler Vyper (runtimeverification.com); Gasper in Coq da Alturki.

**Polkadot GRANDPA**: audit Web3 Foundation + Runtime Verification, parti in Isabelle/HOL.

### 4.6 Vendor per protocol/consensus audit

**Informal Systems** (Canada, primo riferimento per BFT e Cosmos-family, publicazioni su github.com/informalsystems/audits, stack Quint+Apalache+Atomkraft); **Runtime Verification** (Illinois, K framework, Casper/IELE/KEVM); **Certora** (Israele, Prover SMT-based, si sta estendendo oltre Solidity verso Move/Rust); **ChainSecurity** (Zurigo, ora PwC, forte accademia); **Galois** (formal methods DARPA-grade, Cryptol/SAW); **Trail of Bits** (capability protocol); **Least Authority** (P2P/GossipSub).

---

## 5. Audit di infrastruttura e operations

### 5.1 Scope

Il perimetro è ampio: **HSM** (Thales Luna Network HSM FIPS 140-3 L3, Entrust nShield con CodeSafe per esecuzione in-HSM, YubiHSM 2, AWS CloudHSM, SoftHSM solo per dev — **mai** mainnet key); API PKCS#11 via crate `cryptoki`. **Separazione hot/cold/warm**: cold (withdrawal/operator, air-gapped, Shamir-split, in safe), hot (block/attestation signing, su HSM con anti-slashing DB), warm (fee wallet, relayer, rotabile). **Threshold signatures/DVT**: FROST per ed25519/secp256k1; GG18/GG20/CMP/DKLs per ECDSA; **Obol Charon** (middleware IBFT+DKG) e **SSV Network** (layer IBFT proprio tra operator) sono già in produzione Lido dal 2024.

**Remote signer**: **Web3Signer** (Consensys, docs.web3signer.consensys.io) con PostgreSQL slashing-protection DB, standard **EIP-3076** per interchange slashing history tra client. **Secure-Signer di Puffer Finance** per DB EIP-3076 in enclave SGX. **Cubist CubeSigner** per anti-slasher HSM-backed globalmente enforced — pertinente per restaking/AVS. Audit obbligati sul signer: sicurezza del DB pruning, race su import/export, watermark min-slot, resistenza a clock skew, HA failover senza split-brain.

**OS hardening**: CIS Benchmarks Linux/Docker/Kubernetes; STIG per targeting DoD-grade; **gVisor** o **Kata Containers** per sandbox dei RPC; **seccomp-BPF**, AppArmor/SELinux, systemd sandboxing (`ProtectSystem=strict`, `NoNewPrivileges`, `PrivateDevices`). **Secrets**: HashiCorp Vault con Shamir-unseal, AWS/GCP/Azure KMS, SOPS/age/sealed-secrets per GitOps.

**SIEM e signed log**: Splunk/Elastic/Datadog/Loki; append-only signato via `systemd-journald` FSS, Sigstore Rekor per artifact build, auditd su remote syslog. Regole di detection su signer-API auth failure, rate attestazioni anomalo, clock drift, config-file change, nuovi processi nel signer container.

**Supply chain**: **SLSA v1.1 Build Track L1–L3** (L4 deprecato); Sigstore Cosign/Fulcio/Rekor (keyless signing via OIDC GitHub); SBOM CycloneDX/SPDX (Syft, cargo-sbom, cargo-cyclonedx); in-toto/DSSE attestation; admission controller Sigstore Policy Controller o Kyverno/OPA Gatekeeper ("no provenance, no deploy").

**Time sync**: NTP è spoofable — usare **NTS (RFC 8915)** o **Roughtime**; almeno 4 sorgenti, alert su step change e drift >pochi secondi (critico per slashing DB safety).

### 5.2 Metodologie

**OWASP ASVS** L1–L3 per API RPC; **NIST SP 800-53** (AC, AU, CM, IA, SC, SI) e **800-171**; **NIST SSDF SP 800-218** come overlay SLSA; **CIS Controls v8**; **PTES** (pre-engagement, intel, threat model, vulnerability analysis, exploitation, post-exploitation, reporting); **MITRE ATT&CK** per mapping detection; **red team** objective-based ("steal validator key", "halt chain"); **purple team** iterativo; **tabletop** su scenari (signer compromesso, slashing, halt, CVE firmware HSM).

### 5.3 Vendor

**Bishop Fox** (red team US), **Praetorian** (red team cloud/K8s), **Trail of Bits** (infra+Rust+key management), **NCC Group** (infra+crypto+protocollo), **Kudelski** (crypto engineering/HSM), **Cure53** (Berlino, AppSec+browser+protocollo, audit numerosi client Ethereum), **Leviathan**, **Doyensec**, **Atredis** (hardware/embedded/firmware), **Least Authority** (P2P), **SRLabs**/**IOActive** (hardware/firmware/HSM).

---

## 6. Selezione vendor, RFP e contratti

### 6.1 Come scegliere

I criteri decisivi sono: **track record nel dominio esatto** (un'agenzia DeFi non va bene per consensus audit BFT); **referenze verificabili** con ex-cliente dello stesso tipo di progetto (chiamate di 30 minuti con CTO di progetti audited); **expertise sullo stack** (Rust per il codice, formal methods per consensus, side-channel per crypto); **seniority individuale** del lead named in contratto; **qualità dei report pubblici**; **availability** (i tier-1 hanno code di 3–6 mesi — prenotare ora per settembre/ottobre). **Red flag**: rifiuto di fornire referenze, turn-over annunciato del lead, pricing al 30% sotto mercato, NDA che vieta di citare l'audit, disponibilità immediata "senza motivo", report di esempio con finding solo stilistici.

### 6.2 RFP — struttura minima

Sezioni: **Scope** (repo URL, commit hash, file list, LOC, linguaggi, moduli in/out-of-scope); **Background** (protocollo overview, whitepaper, architettura, threat model, audit precedenti); **Timeline** (kickoff, code freeze, draft, remediation, retest); **Deliverables** (finding preliminari, draft report, final report PDF firmato, fix-review memo, attestation letter); **Pricing model** (fixed-fee vs T&M, day rate $2–5k senior, stima totale); **Evaluation criteria** (expertise, team seniority, references, methodology, tooling, reporting quality, availability, prezzo).

### 6.3 Contratti — clausole chiave

**NDA** mutuale, pre-signed dal vendor, 2–5 anni, carve-out per conoscenza generale e metodologia. **Findings ownership**: cliente possiede report e finding; auditor mantiene diritti su metodologia anonimizzata e pubblicazione redatta post-embargo. **Right to publish**: auditor pubblica report finale redatto post-fix (norma tier-1 — repo github.com/trailofbits/publications ne è esempio), soggetto a **embargo 30–90 giorni** post-fix o post-mainnet. **Liability cap**: 1×–2× fee pagata è la norma tier-1 (Trail of Bits, OpenZeppelin, Consensys Diligence); alcuni clienti negoziano cap assoluti $1–5M; carve-out su gross negligence, willful misconduct, IP indemnity, breach di confidentiality. **Payment**: **milestone 30/40/30** è standard (30% kickoff, 40% draft, 30% final/retest); alternativa 50/50 o billing mensile per engagement lunghi. **Fixed-fee** preferito a scope chiuso; **T&M** solo per research-heavy o formal verification profonda.

### 6.4 Costi 2025–2026

L1 di media complessità: code audit **$150–500k**, crypto audit **$100–250k** (premium se PQ custom), consensus audit con FV **$150–400k**, infra audit **$80–200k**. Totale multi-vendor per L1 **$500k–$2M+**. Il progetto dovrebbe prevedere **10–20% del round di funding** su security (20% se si vuole doppio audit su consensus/crypto).

Esempio breakdown realistico per un L1 post-quantum EIC-funded (Fase 8):

| Voce | Budget |
|---|---|
| Code audit (Zellic o Trail of Bits) | €180k |
| Crypto audit ibrido (Cryspen FV + Quarkslab SCA) | €220k |
| Consensus audit con FV Quint (Informal Systems) | €180k |
| Infra audit (Cure53 o Trail of Bits) | €120k |
| Bug bounty seed Immunefi/Cantina | €80k |
| Meta-reviewer consolidation | €40k |
| Retest envelope | €60k |
| Contingency 15% | €130k |
| **Totale** | **~€1,01M** |

Versione premium con doppio-audit su consensus e crypto: **€1,5–2M**.

---

## 7. Gestione del processo: dal kickoff al final report

### 7.1 Kickoff (60–90 min)

Agenda: intro team; confermazione scope (commit hash esatto, file list, LOC); walkthrough architetturale del dev team (30–45 min); threat model review; canali di comunicazione (Slack/Discord condiviso, weekly sync cadence); path di escalation critici; handover di documentazione e test; timeline (draft date, retest window); severity rubric concordata.

### 7.2 Ritmo

**Weekly sync** 30–60 min con stato, finding preliminari, blocker, code question. Daily async su Slack per engagement critici. Norma OpenZeppelin/ToB: communication collaborativa con team cliente.

### 7.3 Disclosure real-time vs batch

**Critical/High**: disclosure immediata entro 24h con mitigazione proposta, per patching parallelo. **Medium/Low/Informational**: batched nel draft report. Dedaub: disclosure gratuita se trovato in scoping phase.

### 7.4 Severity rubric

- **CVSS 3.1** (NVD standard): None/Low/Medium/High/Critical su 0–10.
- **CVSS 4.0** (rilasciato nov 2023, supportato ufficialmente da NVD dal 2024): aggiunge Threat+Environmental+Supplemental, introduce Attack Requirements (AT), affina User Interaction (Passive/Active), rimuove Scope, aggiunge Automatable/Recovery/Value Density/Provider Urgency. Referenza: first.org/cvss/v4.0/specification-document.
- **Immunefi Vulnerability Severity Classification System v2.3**: rubric Web3-specifica impact-driven (non vector-based), scale separate per Smart Contract / Blockchain-DLT / Websites-Apps, include temporary freezing, griefing, MEV, protocol insolvency, unauthorized minting. Master list: immunefi.com/severity-classification-systems.

Per un L1 PQ la combinazione operativa è **CVSS 4.0 per documentazione enterprise/EU + Immunefi v2.3 per il bug bounty program**.

### 7.5 Draft report e contenzioso

**Review window** 1–2 settimane: il cliente risponde per ogni finding con accettazione, fix proposto, o rebuttal tecnico con giustificazione. L'auditor accetta downgrade o mantiene severity con rationale scritto. Ogni finding nel report finale ha campo "client response" inline.

### 7.6 Retest

**2–4 settimane** dopo il draft, scope = verifica dei fix sui finding in-scope; il codice nuovo introdotto in remediation viene revisionato best-effort salvo engagement separato. Ogni finding riceve status **Resolved / Partially Resolved / Unresolved / Risk Accepted** (esempio: il report ToB per Drift mostra il formato).

### 7.7 Criteri "audit complete"

**Zero Critical, zero High**, Medium documentato/accettato con risk memo firmato, Low e Informational tracked in backlog. Il report finale cita **sia il commit pre-audit sia il commit post-fix**, sempre hash-pinned, mai `master`.

### 7.8 Risk acceptance memo

Documento breve firmato dal CTO/Security Officer del cliente: finding, decisione di non-fix, giustificazione business, controlli compensativi, data di review. Allegato in appendice al final report e referenziato nel risk register SOC 2/ISO.

### 7.9 Comunicazione durante l'audit

Regola: **trasparenza con investor e team, silenzio pubblico fino a fix deployati**. Update interni settimanali a board/investor; community update solo a milestone (kickoff announcement, final report publish). **Mai** pubblicare finding non-patchati su testnet pubblico — questo è il ponte per il FUD e per l'exploit opportunistico. Se una Critical emerge mid-audit con testnet live, procedura coordinated disclosure: patch pronta → hard fork testnet coordinato con validator core → post-mortem pubblico a fix deployato.

### 7.10 Pubblicazione

Final report pubblicato **30–90 giorni post-fix/post-mainnet**: PDF firmato PGP dell'auditor, lista finding con severity/CVSS/Immunefi, status, fix raccomandato, appendice metodologica. Pubblicare su repo GitHub dedicato del progetto (es. `github.com/<progetto>/audits`), sito aziendale, e aggregatori (Immunefi pubblica report dei protocol partner).

---

## 8. Coordinazione multi-audit: la vera sfida della Fase 8

### 8.1 Sequenziamento

Lo standard operativo per un L1 con 4 audit tipi, su ~18 settimane:

1. **Settimane 1–4**: specification/whitepaper review + formalizzazione Quint/TLA+.
2. **Settimane 4–12**: **code audit** + **crypto audit** in parallelo.
3. **Settimane 8–14**: **consensus audit** (inizia quando crypto ha sbiancato le primitive).
4. **Settimane 12–16**: **infrastructure audit** (dopo che il codice è stabile in staging).
5. **Settimane 14–18**: **final pentest** (RPC, networking, DoS).
6. **In parallelo throughout**: formal verification delle invarianti critiche.

### 8.2 Coverage matrix

Costruire una matrice **modulo × auditor**: righe = componenti (networking, consensus, VM, state, crypto primitives, RPC/API, client SDK, bridge, token/staking contract); colonne = vendor. Identificare celle vuote (gap), singola coverage, doppia (su modulo critical). Framework come **L1AAF di Hacken** e **core L1/L2 di Coinspect** organizzano esplicitamente questa matrice.

Esempio di matrice per il progetto:

| Modulo | Code audit | Crypto audit | Consensus audit | Infra audit |
|---|---|---|---|---|
| ML-DSA signer | Zellic (integrazione) | Cryspen (FV) + Quarkslab (SCA) | — | Cure53 (HSM/key) |
| SLH-DSA archival | Zellic | Trail of Bits | — | Cure53 |
| BFT consensus | Zellic | — | Informal Systems (Quint) | — |
| libp2p layer | Zellic | — | Informal Systems (messaggi) | Cure53 (DoS/network) |
| Crypto-agility envelope | Zellic | Cryspen | Informal Systems (dispatch) | — |
| Validator ops/HSM | — | — | — | Cure53 + Bishop Fox red-team |
| CI/CD, SLSA | Zellic (build) | — | — | Cure53 |

Ogni riga deve avere ≥1 cella coperta; ogni modulo **Critical-path** deve avere ≥2 vendor indipendenti.

### 8.3 Condivisione finding tra auditor

Default gli NDA impediscono la condivisione. Negoziare **tri-party amendment o NDA umbrella** al kickoff così i finding si condividono per evitare duplicazione e permettere meta-review. Alternativa: cliente come information broker con sharing sanitizzato — più lento.

### 8.4 Meta-review

Assumere un **meta-reviewer indipendente** (senior consultant o uno dei vendor con separato mandato) per consolidare i finding cross-vendor, deduplicare, riconciliare severity discrepancies, produrre **risk register unificato**. Questo step trova il bug che tutti hanno mancato perché ciascuno assumeva fosse coperto da un altro — è l'anti-pattern più pericoloso dell'approccio multi-vendor. Budget €30–60k, 2 settimane di effort.

### 8.5 Tempistica relativa alle fasi di testnet

Phase 8 pubblico dovrebbe idealmente girare **con bug-bounty attivo e finding Critical/High già patchati** sul testnet. Ciò significa: audit parte prima del testnet pubblico (preview interno/devnet); testnet pubblico coincide con remediation/retest; bounty live dal primo giorno del pubblico; mainnet solo dopo "audit complete" + 30 giorni di testnet pulito + report finali pubblicati.

---

## 9. Remediation, bug bounty, assicurazione, compliance

### 9.1 Remediation standards

Ogni fix: **un commit per finding** con riferimento all'ID finding; **regression test obbligatoria** (unit + property + fuzz seed se applicabile); **peer review** da dev diverso dall'autore del fix; **independent validation** (non lo stesso che ha scritto il fix). Tutto tracciato in issue tracker con link al commit e al finding.

### 9.2 Bug bounty

**Immunefi** (leader, $162M+ disponibile, $110M+ payout storico) ha pagato $10M a satya0x per Wormhole, $6M per Aurora, $2,2M Polygon; LayerZero program è fino a $15M (10% del value-at-risk, cap $15M, minimo $250k); MakerDAO $10M dal 2022; **Usual su Sherlock $16M** (marzo 2026, il più grande mai lanciato). **Safe Harbor framework** (SEAL/Immunefi, frameworks.securityalliance.org/safe-harbor) — adozione in 20+ protocol inclusi Uniswap, Lido, zkSync, Balancer — permette whitehat rescue durante exploit attivi con reward 10% dei fondi salvati (cap 60% del max critical), fondi restituiti in 6h Immunefi/72h SEAL. **È protezione civile, non criminale** — va comunicato chiaro.

**Cantina** (Spearbit, cantina.xyz) ospita Coinbase $5M (luglio 2025, il più grande CEX bounty per Base L2). **Code4rena** per contest time-boxed. **Sherlock** combina contest + coverage post-exploit fino a $500k standard. **HackenProof** alternative con 200+ programs.

**Timing**: lancio bounty **dopo audit, prima mainnet**. **Budget bounty**: 10–25% dell'audit spend come pool iniziale, con critical payout scalato al value-at-risk (regola Immunefi: 10% di TVL at risk capped).

### 9.3 Insurance

**Nexus Mutual** (>$6B protetti dal 2019, UK DAO): Smart Contract Cover, Protocol Cover, Custody Cover. Non copre phishing, user error, oracle esterni. **Sherlock**: coverage fino a $10M post-audit con partnership Nexus Mutual (25% excess). **Cyber liability tradizionale** (AIG, Chubb, Beazley, Coalition, At-Bay): audit recente (12 mesi) + bug bounty attivo quasi sempre richiesto per underwriting. Premium riducibile 10–30% con tier-1 auditor report + FV + remediation demonstrata. Critical non risolto = coverage void.

### 9.4 Compliance overlay

**SOC 2 Type II** (AICPA): CC6.1, CC6.6, CC7.1 richiedono pentest evidence; osservazione 6–12 mesi. **ISO/IEC 27001**: Annex A 8.8 (vulnerability mgmt), A 8.29 (security testing in development), A 5.25 (security event assessment) implicitamente richiedono pentest. Un pentest singolo può soddisfare entrambi se scoped correttamente. **ISO/IEC 27701** per privacy/GDPR. **FedRAMP** per US federal (pentest annuale da 3PAO). Gli audit smart contract **non sostituiscono** SOC 2/ISO 27001 — sono scope diversi (on-chain vs corporate/SDLC/key mgmt). Per il progetto: audit blockchain + SOC 2 o ISO 27001 sul controllo organizzativo + pentest RPC/web + bounty continuo = coverage completa. OpenZeppelin stessa è SOC 2 Type 2 certified.

---

## 10. Landscape certificativo UE per un notary PQ

### 10.1 EUCC

Base legale: **Commission Implementing Regulation (EU) 2024/482** (27 febbraio 2024, applicabile 27 febbraio 2025); amendment **(EU) 2024/3144** (dicembre 2024); secondo amendment dicembre 2025 per ICT product series e assurance continuity. Basato su **ISO/IEC 15408/18045** Common Criteria. Due livelli: **Substantial** (AVA_VAN.1–.2, CAB accreditato) e **High** (AVA_VAN.3–.5, autorizzazione NCCA). Ruoli: **ENISA** drafting + SotA + registry; **NCCAs** (BSI Germania, ANSSI Francia, **OCSI/AgID Italia**); CAB/ITSEF accreditati ISO/IEC 17065/17025.

**PQC in EUCC**: **ECCG Agreed Cryptographic Mechanisms v2.0** (aprile/maggio 2025) ammette esplicitamente ML-KEM, ML-DSA, SLH-DSA, e raccomanda PQ/T hybrid. Certificazione EUCC con algoritmi PQ è ora path operativo. Sotto **NIS2**, gli Stati membri possono **richiedere** EUCC-certified ICT product per essential/important entities.

### 10.2 eIDAS 2.0

**Regolamento (UE) 2024/1183**, pubblicato 30 aprile 2024, in vigore 20 maggio 2024. Amplia i Qualified Trust Services per includere **archiviazione elettronica qualificata (Art. 45j)**, **electronic ledgers**, remote signature management, attestazione qualificata di attributi, **EU Digital Identity Wallet** (Stati membri devono offrirne uno entro fine 2026). **Qualified preservation (QPRES)** sotto Art. 34(2) e 40, implementing acts CIR (EU) 2025/1946, riferimento tecnico **ETSI TS 119 511/512**. **Audit biennale obbligatorio** da CAB accreditati (Reg. (EC) 765/2008), report al supervisory body nazionale. Sette implementing regulation formalizzati nel Official Journal del 30 luglio 2025. **Trusted List**: format passa da XAdES BES a XAdES-BASELINE-B (EN 319 132-1), TLv5 → TLv6 (ETSI TS 119 612 v2.3.1). Deadline compliance eIDAS 2 per QTSP esistenti: **settembre 2026**.

### 10.3 ETSI stack per il notary

**EN 319 401** policy generali TSP; **EN 319 403** conformity assessment; **EN 319 411-1/-2** certificate-issuing TSP; **EN 319 421** time-stamping TSP; **EN 319 422** protocolli time-stamp; **TS 119 511 v1.2.1** preservation; **TS 119 512 v1.1.1** preservation protocol; **TR 119 494** blockchain e DLT in TSP framework; **TS 119 312** cryptographic suites (da verificare vs ECCG ACM v2.0); **TS 119 461 v2.1.1** identity proofing.

### 10.4 NIS 2 e DORA

**NIS 2 — Dir. (UE) 2022/2555**: trasposizione 17 ottobre 2024 (diversi Stati in ritardo). Include digital infrastructure, trust services, digital providers; un L1 come notary può ricadere in "digital providers" o "trust services". Art. 21 misure di risk management; Art. 24 autorizza Member States a richiedere EUCC-certified product.

**DORA — Reg. (UE) 2022/2554**: applicato dal **17 gennaio 2025**. Scope: entità finanziarie + ICT third-party critical. Art. 24–27 resilience testing; Art. 26–27 richiedono **TLPT (Threat-Led Penetration Testing) ogni 3 anni** per entità significative (~120 banche ECB, ~50 assicuratori, CCP, trading venue). **Commission Delegated Regulation (EU) 2025/1190** (RTS TLPT, effettivo 8 luglio 2025) specifica scope, selezione tester, metodologia sei-fasi (preparation, TI, red-team, closure, purple-teaming, attestation), basata su **TIBER-EU**. I third-party ICT (inclusa l'infrastruttura PQ-notary) sono contractualmente coinvolti nei TLPT dei clienti (Art. 30(3)(d)). Prima notifica TLPT attese 2026, primo ciclo completo 2027.

### 10.5 Framework nazionali

**Germania (BSI)**: TR-03125 (TR-ESOR) v1.3 preservation; TR-03181 (Cryptographic Service Provider); TR-02102 series cryptographic mechanisms (annually updated, PQ presente nelle revisioni recenti — verificare corrente). Report quantum-computer; commissionato Fraunhofer AISEC per laser-fault XMSS.

**Francia (ANSSI)**: RGS; Guide de sélection d'algorithmes cryptographiques (2024 update con PQ/T hybrid); **CSPN** con lab CESTI (Quarkslab, Synacktiv, Amossys); NCCA per EUCC.

**Italia (AgID/OCSI)**: **OCSI** è NCCA italiana per CC/EUCC; **AgID** supervisiona trust services qualificati e conservazione sostitutiva (Linee guida sulla conservazione dei documenti informatici); registro Conservatori accreditati AgID — direttamente rilevante per MVP italiano.

**UK (NCSC)**: PQC Migration Guidance; ACSC scheme; target migration 2035.

### 10.6 FIPS 140-3 / CMVP per HSM

FIPS 140-3 effective settembre 2020; FIPS 140-2 ritirato settembre 2026 per certification lifecycle. HSM con ML-KEM/ML-DSA support in CMVP: Thales Luna, Entrust nShield, Utimaco, Marvell LiquidSecurity, AWS CloudHSM, Google Cloud HSM — status cambia settimanalmente, verificare la lista CMVP al momento di procurement. **Doppio path per notary UE**: FIPS 140-3 L3+ (per interop US + general assurance) **più** EUCC AVA_VAN.4/5 o ANSSI "Qualification Renforcée" per HSM come **QSCD/QSealCD** sotto eIDAS 2. Protection Profile pertinente: **CEN EN 419 221-5**.

### 10.7 Roadmap certificativa raccomandata

| Stage | Target | Auditor tipico |
|---|---|---|
| 1. Crypto library | libcrux ML-DSA + RustCrypto/AWS-LC SLH-DSA | Cryspen + Trail of Bits |
| 2. HSM/signer | FIPS 140-3 L3 + EN 419 221-5 PP | HSM vendor certification |
| 3. Node software | EUCC Substantial (AVA_VAN.2) → High | Quarkslab CESTI o OCSI-ITSEF italiano |
| 4. Preservation service | ETSI TS 119 511/512 + BSI TR-03125 conformity | TÜViT, DEKRA, LSTI, Bureau Veritas Italia |
| 5. TSP framework | EN 319 401/403/411/421 per eIDAS 2 QTSP listing | Stesso CAB accreditato |
| 6. DORA (se client FS) | TLPT per RTS 2025/1190 | NCC / Trail of Bits / Quarkslab red-team |
| 7. Ongoing | NIS2 reporting; CRA; ECCG ACM v2.0 maintenance | Internal + surveillance |

### 10.8 EIC Accelerator — copertura costi audit

**Work Programme 2026**: grant fino €2,5M (70% dei costi eligible + 25% indirect flat-rate) per TRL 6–8; equity fino €10M (STEP ScaleUp anche superiore) per TRL 9. **Esplicitamente eligible**: "testing required to meet regulatory and standardisation requirements" — **audit esterni e certificazione sono coperti come "other direct costs"**. Per il progetto: EUCC, crypto audit (PQShield/Cryspen/Quarkslab/NCC), CSPN ANSSI, BSI TR-03125 conformity, TSP audit pre-operational biennial — tutti inclusi nel 70% reimbursed envelope a TRL 6–8. Post-market recurring (TLPT annuale DORA, penetration test annuale, TR-ESOR surveillance) sta fuori dal grant, va finanziato con equity.

**Vincolo critico**: il grant **non** reimburse spese pre-award. La schedulazione degli audit va dopo la firma del Grant Agreement (salvo Fast Track). Subcontratti esterni (audit) richiedono tendering best-value e dichiarazione nel budget breakdown.

---

## 11. Risk register — i dieci modi con cui gli audit vanno male

1. **Scope creep**: codice aggiunto dopo freeze; auditor sfora o droppa coverage. Mitigazione: freeze enforced, change-order scritto, budget contingency 15–25%.
2. **Auditor mismatch**: DeFi-team su consensus audit (o viceversa). Mitigazione: capability check esplicito in RFP, reference call con progetti L1 simili.
3. **Insufficient preparation**: auditor spende 30–50% del tempo su code hygiene invece di vulnerability hunting. Il singolo fallimento più costoso.
4. **Timeline compression**: 10 settimane di lavoro squeezed in 5 per hittare launch; audit diventa performativo.
5. **No retest budget**: fix introducono regression e nessuno ri-revisiona. Pre-budget 2–4 settimane fix review come parte obbligatoria, non opzionale.
6. **Findings hoarded**: multipli vendor trovano lo stesso bug, o peggio ciascuno assume che altri coprano un'area. Coverage matrix + meta-reviewer + umbrella NDA.
7. **Auditor turnover**: lead senior se ne va mid-engagement. Contract con named lead + backup + knowledge transfer documentato.
8. **Missing threat model**: audit parte senza trust boundaries concordate. Threat model workshop in settimana 1.
9. **Over-reliance su audit singolo**: un report ≠ sicurezza. Multi-vendor + bounty + monitoring + re-audit periodico.
10. **Acceptance acritica di "informational"**: combinazione di finding low forma critical. Meta-review con attack chaining.

---

## 12. Template e deliverable concreti

### 12.1 Pre-audit checklist sintetica

Una checklist dedicata, compilabile dal team, in una sola pagina: toolchain pinnata e signed tag pronto; `clippy`/`fmt` CI verde; `cargo-audit`, `cargo-deny`, `cargo-vet`, `cargo-geiger`, MIRI, Kani, cargo-fuzz — tutti girati con log archiviati; fuzz corpus ≥24 CPU-hour per target, committato; test coverage riportato (>80% target); README, ARCHITECTURE.md, THREAT-MODEL.md, SPEC (Quint), KNOWN-ISSUES.md presenti; build riproducibile Nix/Docker; SBOM generato; security.txt pubblicato; bug bounty program **draft pronto** ma non ancora live. Riferimenti: learn.openzeppelin.com/security-audits/readiness-guide, quantstamp.com/audit-readiness-guide, appsec.guide (Trail of Bits).

### 12.2 RFP outline

*1. Background del progetto (2 pp)* — protocollo, status, raise, mainnet target. *2. Scope* — repo, commit, moduli in/out, LOC per modulo. *3. Obiettivi di audit* — finding attesi, severity rubric. *4. Deliverables* — preliminary findings, draft, final, retest, attestation. *5. Timeline* — kickoff, code freeze (date), draft, remediation, retest. *6. Vendor requirements* — expertise, references, seniority, language. *7. Pricing model* — fixed-fee preferito; T&M se applicabile. *8. Clausole* — NDA, IP, liability, embargo. *9. Evaluation criteria* — ponderate. *10. Timeline RFP* — Q&A, bid, selection. *11. Appendici* — architettura, threat model, repo access.

### 12.3 Severity rubric (Immunefi v2.3 come base + CVSS 4.0 per documentazione)

**Critical**: signing-key exposure; forgery di firma; consensus halt da singolo attaccante; perdita diretta fondi utenti; double-signing senza slashing evidence. Payout: massimo tier, 10% VaR cap €1M+ in bounty.
**High**: validator crash exploitable, slashing di validator onesti, MEV significativa, upgrade governance malicious.
**Medium**: degradazione liveness adversariale, info leak non-critico, griefing bounded.
**Low**: defense-in-depth.
**Informational**: hygiene e documentazione.

### 12.4 Disclosure policy (in linea con RFC 9116)

`/.well-known/security.txt` con Contact (security@<progetto>), Expires (<12 mesi), Encryption (PGP key URL), Policy (URL a /security.md), Preferred-Languages: it, en. Policy page: SLA triage 24h, fix target 30/60/90 giorni per Critical/High/Medium, embargo standard 90 giorni, safe harbor (da SEAL framework), no-hack-no-pay rule, KYC richiesto per payout ≥$10k.

### 12.5 Risk acceptance memo template

Una pagina: finding ID, auditor, severity, descrizione, decisione (*accept / defer / mitigate*), giustificazione business, controlli compensativi, owner, data review, firma CTO + Security Officer, allegato per SOC 2 risk register.

---

## 13. Piano d'azione Phase 8 — aprile–giugno 2026

### Aprile 2026 (entro 30/4)

**Finalizzare preparazione interna**. Completare THREAT-MODEL.md, ARCHITECTURE.md, SPEC in Quint. CI verde su clippy/fmt/cargo-audit/cargo-deny/cargo-vet/cargo-geiger/MIRI/Kani. Fuzz target committati per: serialization codec, consensus message handler, ML-DSA sign/verify envelope, libp2p gossipsub handler, state transition; ogni target >24 CPU-hour seed corpus. SBOM CycloneDX generato. Build riproducibile Nix. Signed tag `audit-v1.0.0-rc1`. Red team dry-run interno (2 settimane) con mini-threat-model e pentest self-administered.

**Avviare procurement vendor in parallelo**. RFP draft circolato a 6 vendor shortlist:

- **Code audit**: Zellic (primo), Trail of Bits (secondo), Sigma Prime (backup). RFP invio entro 15/4.
- **Crypto audit**: Cryspen (FV libcrux layer) + Quarkslab (SCA e CSPN prep). Considerare NCC Group come alternativa Cryspen. RFP invio entro 15/4.
- **Consensus audit**: Informal Systems (primo, Quint native), Runtime Verification (secondo). RFP invio entro 15/4.
- **Infra audit**: Cure53 (primo per integrazione europea), Trail of Bits (secondo), Bishop Fox (red team dedicato). RFP invio entro 20/4.

Call referenze 3 progetti L1 per ciascun primo scelto. Termine firma contratti: **10 maggio**.

### Maggio 2026

**Kickoff parallelo** settimana 20–24 maggio: crypto audit (Cryspen + Quarkslab) e code audit (Zellic) partono insieme; consensus audit (Informal Systems) parte 2 settimane dopo (attesa dei preliminary crypto finding).

**Testnet pubblico live** il 25 maggio, **senza pubblicare audit engagement** (no FUD pre-remediation). Bug bounty **draft pronto** su Immunefi o Cantina, **non** live.

**Meta-reviewer** contrattualizzato (budget €40k, effort 2 settimane, deliverable fine luglio).

**Umbrella NDA** firmato dai 4 vendor per permettere cross-sharing dei finding.

### Giugno 2026

**Weekly sync multipli**: lunedì 30m consensus, martedì 30m crypto, mercoledì 30m code, giovedì 30m infra (parte in giugno-metà). Venerdì 60m **cross-vendor sync** coordinato dal meta-reviewer.

**Settimana 8–10 di audit**: preliminary findings flow iniziano. Qualunque **Critical** → coordinated patch in 72h, hard-fork coordinato su testnet se impatta state.

**Fine giugno**: draft report da code + crypto auditor attesi. Inizio remediation. Infra audit parte 25 giugno (codice stabile dopo fix crypto).

### Luglio–agosto 2026 (outlook)

**Remediation window** 3–4 settimane con fix, regression test, peer review. **Retest** seguito immediatamente. **Consolidation meta-review** da meta-reviewer. **Bug bounty live** su Immunefi tier Primacy-of-Impact a inizio agosto. **Final report publication** 30 giorni post-remediation, entro metà settembre.

**Certificazione**: parallelamente, contattare OCSI Italia + Quarkslab CESTI per pre-assessment EUCC Substantial del node software; TÜViT/LSTI per pre-assessment TS 119 511/512; AgID per briefing su registrazione Conservatore accreditato (se il notary è MVP italiano-domiciled).

### Budget consolidato Fase 8

| Voce | Budget |
|---|---|
| Code audit (Zellic) | €180k |
| Crypto audit (Cryspen + Quarkslab) | €220k |
| Consensus audit (Informal Systems) | €180k |
| Infra audit (Cure53 + red team Bishop Fox) | €150k |
| Meta-reviewer | €40k |
| Retest envelope | €60k |
| Bug bounty seed | €80k |
| Contingency 15% | €135k |
| **Totale Fase 8** | **~€1,05M** |

Di cui ~€735k (70%) potenzialmente reimbursable sotto EIC Accelerator grant component, a condizione che il Grant Agreement sia firmato prima della spesa.

---

## Conclusioni e key takeaway

**L'audit non è un check-gate, è la spina dorsale operativa della Fase 8.** Per un L1 post-quantum con archival 20+ anni, quattro dimensioni — codice, crypto, consensus, infra — devono essere auditate da vendor distinti, con expertise autoritativa verificabile, su una specifica formale e una codebase che arriva già "clean" al kickoff.

La **scarsità globale di auditor PQ qualificati** (una decina di firm al mondo) implica che **Cryspen + Quarkslab + NCC/Trail of Bits** vanno bloccati **ora**, mesi prima del kickoff; le code d'attesa tier-1 sono 3–6 mesi. Lo stesso vale per Informal Systems sul consensus.

La **differenziazione competitiva europea** del progetto passa per l'**allineamento EUCC + eIDAS 2.0 + TR-ESOR** — non come orpello compliance ma come design input: scegliere libcrux per ML-DSA, usare SLH-DSA solo archival, pianificare re-signing periodico per TR-ESOR, costruire crypto-agility envelope da zero. L'**ECCG ACM v2.0** di maggio 2025 apre ufficialmente la porta EUCC a PQ, ed è un vantaggio tattico che pochi competitor globali sfrutteranno prima del 2027.

La **gestione multi-audit è il vero differenziatore operativo**: coverage matrix, umbrella NDA, meta-reviewer, cross-vendor sync settimanale. Senza questi, quattro audit eccellenti producono quattro silos e un gap che sarà scoperto dal primo whitehat di Immunefi o — peggio — dal primo blackhat in mainnet.

Il **budget €1–1,5M** non è alto per un L1 serio; è **disciplinare**. È il costo di non farsi exploitare per €50M nel primo anno di mainnet. Una porzione significativa è reimbursable sotto EIC grant se scheduled correttamente post-Grant Agreement.

**La regola d'oro**: gli audit trovano quello che il team ha cercato; il bug bounty trova quello che nessuno ha cercato; il monitoring runtime trova quello che è già in corso. Servono tutti e tre. Phase 8 è il momento in cui si costruisce questa catena permanente, non un evento singolo che si chiude con la firma del final report.
