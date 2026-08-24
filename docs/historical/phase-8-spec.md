# Architettura a prova di futuro per una blockchain post-quantistica ventennale

**Una blockchain pensata per durare oltre vent'anni deve trattare ogni primitiva crittografica, ogni protocollo di rete e ogni regola di consenso come *sostituibili via governance*, non come invarianti di codice.** È questa la tesi centrale che emerge dall'analisi delle quattro aree richieste: libreria P2P, set dinamico di validatori, secondo algoritmo PQ, e strategia di onboarding dei validatori indipendenti. La scelta dominante, trasversale a tutte le aree, è spostare il *lock-in* dal livello wire-format al livello registro governato — rendendo ogni suite crittografica, ogni verifier, ogni parametro di consenso un'entità versionata, registrata on-chain, e deprecabile con timelock.

Nel contesto della Fase 8 (public testnet + audit, aprile 2026), le raccomandazioni qui formulate mirano a tre orizzonti: **5 anni** (mainnet stabile con ML-DSA-65 primario + SLH-DSA secondario, libp2p+QUIC ibrido PQ, set di 64→256 validatori); **10 anni** (aggregazione STARK delle firme, VRF post-quantistica, secondo algoritmo on-ramp NIST, set di 1024+ validatori); **20+ anni** (overlay archivistica hash-based, rotazione di famiglie algoritmiche, governance del registro verifier come meccanismo di sopravvivenza primario). Il costo ingegneristico è reale, ma l'alternativa — un hard fork traumatico a metà vita utile della catena — è incompatibile con il requisito di notariato archivistico.

---

## Area 1 — Livello P2P gossip: sostituire i tunnel SSH

### Panorama e opzioni

Il sostituto dei tunnel SSH attualmente in uso deve soddisfare tre requisiti non negoziabili: **handshake ibrido post-quantistico** negoziabile (agilità), **interoperabilità multi-client** (decentralizzazione), **throughput sufficiente per firme PQ 10-40× più grandi delle classiche** (performance). Il dibattito vero è **rust-libp2p con fork interno vs stack QUIC custom**.

**rust-libp2p** è il candidato naturale: alimenta Polkadot/Substrate, i client consensus di Ethereum (Lighthouse, Prysm, Teku, Nimbus), Filecoin e IPFS. La sua virtù principale è **multistream-select**, il meccanismo di negoziazione di protocollo per stringa (`/noise`, `/tls/1.0.0`, `/meshsub/1.2.0`) che costituisce *esattamente* il gancio di agilità crittografica necessario. Ogni primitiva è dietro un identificatore stabile; aggiungere `/tls/1.3-mlkem768/1.0.0` è una modifica di spec di una riga, coesistente con le versioni precedenti. Il prezzo da pagare è la **versione 0.x permanente** (semver non stabilizzata, churn API a ogni minor release), un debito di manutenzione che va assorbito con un fork interno pinned e import a livello di sotto-crate (`libp2p-core`, `libp2p-noise`, `libp2p-quic`, `libp2p-gossipsub`, `libp2p-kad`) piuttosto che tramite la crate omnibus.

Gli stack custom (Solana Turbine + QUIC, Aptos aptos-network con Noise IK su TCP, Sui anemo, Tendermint MConn, devp2p/RLPx) massimizzano il controllo ma impongono anni di hardening proprio — e Tendermint MConn è diventato il caso studio canonico di **cosa non fare**: handshake Station-to-Station proprietario, PEX vulnerabile ad address-book poisoning, peer-churn cronico. Per una catena ventennale il costo di mantenimento di uno stack custom è proibitivo; il beneficio di performance è marginale se si usa QUIC sotto libp2p.

### Trasporto e handshake PQ ibrido: stato aprile 2026

Il quadro degli standard TLS 1.3 ibridi è ormai operativo:
- **draft-ietf-tls-hybrid-design-16** (settembre 2025) approvato IESG per RFC Informational
- **draft-ietf-tls-ecdhe-mlkem-04** (febbraio 2026) fissa i codepoint `X25519MLKEM768` (0x11EC), `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`
- **FIPS 203 (ML-KEM)** finale da agosto 2024

Il deployment reale è sorprendente: a metà settembre 2025 **circa il 43% delle connessioni TLS umane a Cloudflare usavano già X25519MLKEM768**. Chrome desktop/Android, Firefox 132+ (145+ Android), AWS s2n-tls/s2n-quic, Google GFE, BoringSSL, rustls, OpenSSL 3.5, wolfSSL, Go `crypto/tls`, coreTLS Apple — tutti in produzione. In ambito QUIC: quinn (Rust) eredita via rustls; quiche (Cloudflare) è già PQ-ibrido in produzione; msquic ha flag sperimentali su Windows Server 2025; s2n-quic gira PQ da anni.

**PQNoise** (eprint 2022/539) e varianti Hybrid-Noise esistono in codice di ricerca (`clatter` Rust, `nyquist` Go) ma non sono standardizzate IETF. Per l'interoperabilità e l'agilità, TLS 1.3 ibrido batte Noise-PQ DIY.

L'overhead è **circa 1,2 KB aggiuntivi nella ClientHello** per X25519MLKEM768. Attenzione al **tldr.fail**: la ClientHello può eccedere un singolo datagramma UDP in QUIC Initial; va testato con MTU reali di rete.

### Gossip: GossipSub v1.2 + piano dati stake-weighted

Per un set validatori 5–100+ la combinazione vincente è **GossipSub v1.2 per messaggi di consenso** (include IDONTWANT per sopprimere duplicati di payload grandi — **critico con firme PQ di 2-16 KB**) combinato con **un piano dati Turbine-style stake-weighted con erasure coding Reed-Solomon** se i blocchi superano ~100 KB (scenario probabile con firme lattice/hash non aggregate). GossipSub v1.1 è già battle-tested su centinaia di migliaia di nodi Ethereum CL; il peer scoring (time-in-mesh, first-delivery, colocation factor, behavioural penalty) è l'antidoto Sybil più maturo in produzione.

Plumtree/HyParView resta elegante ma meno battle-tested in contesti avversariali; HotStuff lineare crea collo di bottiglia sul leader; Narwhal/Bullshark è eccellente per separare mempool da ordering ma overhead eccessivo sotto 100 validatori.

### Discovery, anti-eclipse, NAT

La discovery deve essere **stratificata, mai monocultura**: (1) bootstrap hardcoded firmato, ruotato via governance, 8-16 nodi su operatori diversi; (2) **ENR-over-DNS con DNSSEC** (EIP-1459) come fallback resiliente a firewall restrittivi; (3) discv5 + Kademlia DHT per discovery ambientale; (4) **registro validatori on-chain** come sorgente autoritativa con binding crittografico PeerId ↔ validator pubkey; (5) GossipSub PX per churn del mesh.

Anti-eclipse: vincolare node ID ai pubkey on-chain dei validatori (identità stake-weighted), enforcement diversità **ASN + /24** nei peer slot (massimo N peer per ASN via MaxMind), ancoraggio ibrido con ≥3 connessioni persistenti scelte out-of-band (pattern "sentry" di Cosmos), rate-limit su insert dell'address book (lezione MConn). Il reputation score deve essere **bounded e memory-limited** — score illimitato = compounding di fiducia = rischio di centralizzazione.

NAT traversal: **DCUtR + circuit-relay-v2 di libp2p rilevanti solo per light client**, non per validatori (tipicamente in datacenter con IP pubblico). Il pattern a tre reti separate di Aptos (validator privata 6180, VFN fidato 6181, pubblica 6182) riduce il blast radius e va replicato.

### Raccomandazioni Area 1

1. **rust-libp2p vendored**, con fork interno, import a sotto-crate, staff dedicato per upstream patches
2. **QUIC primario + TCP/TLS 1.3 fallback**, TLS 1.3 uniforme come security core — rende l'ibrido PQ banale
3. **X25519MLKEM768 come default negoziato oggi**, hook di agilità per suite future (SecP384r1MLKEM1024, KEM post-lattice)
4. **Autenticazione dual-sig**: Ed25519 + ML-DSA-65 nell'ENR/peer record durante la transizione, drop del classico su timelock governato
5. **GossipSub v1.2** per consenso + piano dati Turbine-style per blocchi grandi
6. **Tre reti separate** (validator/VFN/pubblica) + architettura sentry per validatori dietro NAT/VPN

**Lock-in da evitare:** dipendenza da rustls/quinn senza flag di fallback; scoring GossipSub coi soli default; assumere che multiaddr resti stabile per 20 anni (storicamente ha subito riscritture: `/wss` handling).

**Standard da monitorare 2026–2030:** pubblicazione RFC per draft-ietf-tls-hybrid-design, draft-ietf-tls-ecdhe-mlkem, draft-ietf-tls-key-share-prediction (elimina il round-trip extra dell'ibrido durante transizioni), RFC 9881 (ML-DSA in X.509) già pubblicata, draft-ietf-lamps-kyber-certificates, HQC FIPS (~2027) come KEM backup code-based, CNSA 2.0 deadlines USA 2027–2033, PANDAS/DAS per data availability sampling, QUIC multipath.

---

## Area 2 — Set dinamico di validatori on-chain

### Modelli di rotazione e confini di epoca

Le cinque famiglie di reference sono chiare e ciascuna ha un messaggio preciso. Ethereum beacon chain usa epoche da 32 slot (6,4 min) con coda di attivazione/uscita rate-limitata dal **churn limit** (`max(4, active/65536)` attivazioni per epoca, EIP-7514 cap a 8); MIN_VALIDATOR_WITHDRAWABILITY_DELAY = 256 epoche (~27h). Cosmos Hub aggiorna il set a ogni `EndBlock` (top 180 per stake). Polkadot usa **era da 24h + 6 session da 4h**, con elezione Phragmén/Phragmms offline per circa 297 validatori attivi, minimizzando la varianza di stake per validatore. Sui ha epoche ~24h con protocollo EpochChange Mysticeti; Aptos ha epoche ~2h con `reconfiguration::reconfigure()` che emette `NewEpochEvent`.

Il trade-off della lunghezza di epoca è netto: epoche brevi riducono la finestra di corruzione avversariale ma moltiplicano l'overhead; epoche lunghe danno all'avversario 24 ore con una chiave compromessa. **Epoca = 1 ora, regolabile via governance con floor minimo 15 minuti (≥ 4× tempo di finalità)** è il punto dolce per una catena PQ, combinata con **ValidatorTransaction per reconfig d'emergenza istantanea** (pattern Aptos AIP-64).

### Periodi di bonding/unbonding e security model

Il periodo di unbonding deve essere **≥ periodo di weak subjectivity** affinché uno stake storico catturato non possa ritirarsi prima che l'evidenza di slashing sia pubblicata. Cosmos 21 giorni, Polkadot 28 giorni, Ethereum ~27h post-Shapella (più ~36 giorni di correlation window per validatori slashati). **21 giorni con leva di governance solo verso l'alto** (non verso il basso) + **withdrawal parziali immediate delle ricompense** (pattern Shapella) è l'impostazione consigliata. I checkpoint weak-subjectivity vanno pubblicati settimanalmente da team client distinti, firmati con **chiavi PQ distinte**.

### Slashing evolvibile: il pattern chiave

La progettazione più importante di questa area è il **registro pluggable di verifier di evidenze**. Le offese core (equivocation 5%, surround/double-vote 5%, downtime persistente 0,01% + jail) restano hardcoded perché sono invarianti di safety. Ma la governance deve poter **registrare nuovi verifier** tramite moduli Move/WASM (pattern Aptos) con timelock di 30 giorni e supermaggioranza 66%: `evidence_type_id → verifier_contract`. Così nuove condizioni — non-attestazione di data availability, aggregazione PQ scorretta, bias RANDAO, prove di censura MEV — si aggiungono **senza hard fork**.

Il **correlation penalty di Ethereum** (moltiplicatore 3, finestra 36 giorni, cap 100% a ≥33,4% slashati simultaneamente) è l'arma anti-collusione più efficace in produzione e va adottata integralmente.

### Selezione del proposer: il problema PQ

Qui la crittografia post-quantistica apre un vero buco. I VRF standard (EC-VRF Ed25519-based) sono rotti da Shor. Le alternative reali:

1. **RANDAO + VDF hash-based + SHA3 weighted sortition** per v1 (2026-2028): non è secret-leader (perdita rispetto ad Algorand) ma è PQ-safe oggi e senza dipendenze esotiche. Questa è la strada imboccata dalla Lean Roadmap di Ethereum.
2. **PQ-VRF** (lattice- o Poseidon2-tree-based) in v2 (2028-2030) quando NIST/IETF standardizzeranno — IRTF CFRG non ha ancora pubblicato draft ma è tracciato.

**Architetturalmente**: esporre la selezione del proposer come modulo swappable dal giorno uno, interfaccia stabile, migrazione via governance quando la PQ-VRF sarà matura.

### Interazione PQ signature ↔ consensus: il vincolo dominante

Le dimensioni sono implacabili e dettano la scelta architetturale:

| Scheme | Public key | Signature | Aggregation nativa |
|---|---|---|---|
| Ed25519 | 32 B | 64 B | no |
| BLS12-381 | 48 B | 96 B | **sì, illimitata** |
| ML-DSA-65 (L3) | 1,952 B | 3,309 B | **no** |
| ML-DSA-87 (L5) | 2,592 B | 4,627 B | no |
| FN-DSA-512 (Falcon) | 897 B | ~666 B | no |
| SLH-DSA-SHAKE-128s | 32 B | 7,856 B | no |
| SLH-DSA-SHAKE-192s | 48 B | 16,224 B | no |
| SLH-DSA-SHAKE-256s | 64 B | 29,792 B | no |

Ethereum oggi aggrega via BLS 1M+ validatori in 96 B per slot. **Sostituendo naive con ML-DSA-65: 3,3 GB per slot — impossibile.** Le opzioni reali sono tre: (a) limitare il comitato per epoca (200–500 validatori, tipico Tendermint), (b) aggregazione SNARK/STARK (strada `leanSig`+`leanMultisig` di Ethereum: prova che N firme hash-based sono valide in uno STARK, comprimendo a ~125 KB indipendentemente da N, ~250× compressione per 10k firme), (c) aggregazione parziale lattice-based (ricerca, ~40–60% risparmio, non asintotico).

**Traiettoria raccomandata:** **64 validatori al genesis → 256 in anno 2 → 1024 in anno 5** dopo che l'infrastruttura di aggregazione STARK matura. Comitato per epoca 256 con verifica PQ-sig naive è fattibile oggi (CPU moderne AVX-512: ~100 µs/sig → ~25 ms crypto puro per comitato 256, accettabile).

Precompile essenziali: `verify_ml_dsa`, `verify_slh_dsa`, `verify_falcon`, `poseidon2_hash`, `stark_verify` — indirizzi stabili, modello di costo calibrato su hardware misurato.

### Raccomandazioni Area 2

- **Epoca 1h** regolabile, churn attivazione `max(4, active/256)/epoca`, churn uscita `max(4, active/32)/epoca`, turnover massimo 25%/epoca
- **Modalità ibrida di eligibility**: whitelist (Fase 8-9) → ibrido (Fase 10) → permissionless (entro 18 mesi post-mainnet), unico parametro `eligibility_mode` governato
- **Unbonding 21 giorni**, solo allungabile via governance
- **Slashing a due livelli**: offese core hardcoded (equivocation 5%, downtime 0,01% + jail) + registro verifier pluggable con timelock 30 giorni e supermaggioranza 66%; correlation penalty Ethereum-style
- **Ricompense**: ibrido `α × (1/N) + (1−α) × (stake/totale)` con α = 0,3–0,5 come parametro governato, per spingere stake verso validatori sotto-staked (principio Polkadot)
- **Soft-cap del voting power**: `min(stake_effettivo, 2× stake_mediano)` — lo stake eccedente resta slashable ma non ottiene potere proporzionale
- **Delegated PoS + flag self-stake-only opt-in**; *non* enshrinare LSD nel protocollo base
- **RANDAO + VDF hash-based** v1, migrazione a PQ-VRF via governance v2
- **Reconfig pattern Sui/Aptos**: `ValidatorTransaction::Reconfig` emette `NewEpochEvent`, stato + validator-set Merkle root inclusi nel commit di boundary

**Lock-in da evitare:** hardcoding di ML-DSA a livello opcode; aggregazione STARK legata a uno specifico zkVM senza versioning del proof format; parametri di slashing/unbonding immutabili (brittle su 20 anni); assunzioni BLS12-381 nel consenso base.

**Standard da monitorare:** Ethereum Lean roadmap (leanSig, leanMultisig, leanVM — target mainnet ~2029), 3SF (3-slot finality), Aptos AIP-79 async DKG, Polkadot bags-list, DVT (SSV, Obol), threshold lattice signatures (del Pino et al. 2025), aggregazione PQ-sig su IACR ePrint.

---

## Area 3 — Secondo algoritmo PQ e framework di agilità crittografica

### Stato NIST ad aprile 2026

I quattro pilastri:
- **FIPS 203 (ML-KEM)**, **204 (ML-DSA)**, **205 (SLH-DSA)** — finali da agosto 2024
- **FIPS 206 (FN-DSA/Falcon)**: **non ancora finale.** Draft sottomesso per approvazione interna il 28 agosto 2025, IPD preview alla 6th PQC Standardization Conference (24-26 settembre 2025). Review pubblica ~12 mesi, **FIPS 206 finale atteso fine 2026 o inizio 2027**. Cambiamenti IPD: hedged signing preferito al randomized, modalità External-μ/HashFN-DSA, modifiche da eprint 2024/1769, variante fixed-point ancora in discussione post-IPD
- **On-ramp Round 2** (annunciato 24 ottobre 2024): 14 candidati (HAWK, CROSS, LESS, SQIsign, FAEST, Mirath, PERK, RYDE, SDitH, MAYO, QR-UOV, SNOVA, UOV). **Round 3 down-select atteso fine 2026; finalizzazione on-ramp 2027–2028; FIPS 2028–2029.** NIST ha esplicitamente dato priorità a una firma **non-lattice general-purpose**
- **HQC** selezionato come secondo KEM (code-based) a marzo 2025; draft ~2026, FIPS ~2027

### Il verdetto: SLH-DSA-SHAKE-192s come secondo algoritmo

La scelta del secondo algoritmo va subordinata a un criterio chiaro: **diversità di famiglia matematica rispetto al primario**. ML-DSA è basato su MLWE/MSIS (lattice). Il secondo algoritmo deve basarsi su **ipotesi in una classe di problemi diversa** per sopravvivere a breakthrough di crittanalisi nel singolo family.

La tabella comparativa è dirimente:

| Criterio | FN-DSA (Falcon) | SLH-DSA (SPHINCS+) |
|---|---|---|
| NIST finale? | **No** (FIPS 206 fine 2026/inizio 2027) | **Sì** (agosto 2024) |
| Diversità vs ML-DSA | Stessa famiglia (lattice/NTRU) | **Famiglia diversa (hash)** |
| Sicurezza implementativa | FP aritmetica, side-channel, HSM certificati nascenti | Integer/hash puro, costant-time facile, HSM certificati disponibili |
| Determinismo firma | Non-deterministico, riproducibilità FP a rischio | Deterministico (anche hedged) |
| Dimensione firma | **~666 B / 1280 B — migliore** | Grande (7,8 KB → 29,8 KB) — peggiore |
| Conservatività long-term | NTRU/lattice — stesso rischio ML-DSA | **Massimamente conservativa** — rompibile solo se SHA-2/SHAKE rompibili |

**FN-DSA duplica la singola assunzione che preoccupa di più (lattice strutturati). SLH-DSA è la scelta di defense-in-depth corretta.** La storia recente — SIKE rotta in un'ora su laptop a luglio 2022, Rainbow rotta in un weekend nel 2022 — dimostra che anche famiglie apparentemente solide collassano rapidamente. Hash-based è l'unica famiglia che ha 45+ anni di studio (Lamport 1979, Merkle 1989, XMSS 2011) senza alcuna struttura algebrica sfruttabile da algoritmi Shor-like.

Raccomandazioni di parametro:
- **Fallback consensus-layer: SLH-DSA-SHAKE-192s** (16,224 B firma, pk 48 B, Categoria 3 ~AES-192), abbinato a ML-DSA-65 primario. Variante "s" (slow sign, small sig) perché i validatori verificano molte volte
- **Opzione utente via AA: SLH-DSA-SHAKE-128s** (7,856 B firma, Cat 1) per account a basso valore; vietare varianti "f" di default per bloat
- **Overlay archivistico/notary root: SLH-DSA-SHAKE-256s** (29,792 B, Cat 5) — firmato raramente, margine massimo

FN-DSA va **rivalutato Q4 2027** come terzo algoritmo opzionale bandwidth-optimized quando FIPS 206 sarà finale e la variante fixed-point standardizzata.

### Pattern di agilità crittografica: wire format TLV

Il wire format dovrebbe essere:

```
signature_envelope := <version:u8><algo_id:varint>
                      <sig_len:varint><signature_bytes>
                      [<aux_len:varint><aux>]
public_key_envelope := <version:u8><algo_id:varint>
                       <pk_len:varint><pk_bytes>
```

- **`algo_id` da registro doppio**: multicodec upstream (github.com/multiformats/multicodec) per interop tooling off-chain + registro on-chain per dispatch del verifier contract. Registrare nuovi codepoint per ML-DSA-44/65/87, SLH-DSA-SHAKE-128s/192s/256s, FN-DSA-512/1024
- **`aux` campo** per contesto algoritmo-specifico (context string SLH-DSA, flag pre-hash FN-DSA, sub-firme composite)
- **Ibrido parallelo** come wrapper codepoint: `algo_id = HYBRID_PARALLEL`, poi due envelope annidati
- **Canonicalizzazione**: deterministic CBOR (RFC 8949 §4.2) o JCS (RFC 8785), hash con SHAKE256-256; entrambe le firme coprono lo stesso digest

Il pattern **parallel hybrid** (non-composite) è preferibile all'approccio IETF composite (`draft-ietf-lamps-pq-composite-sigs-16`) per una catena decentralizzata: composite lega due algoritmi in un OID unico, ogni aggiornamento richiede nuovo OID e re-issuance delle chiavi, danneggiando l'agilità. Parallel si adatta naturalmente agli envelope TLV/multicodec e permette per-account scelta.

### Pattern on-chain: registro verifier governato

Il meccanismo architetturale critico è **`algo_id → verifier_address`** come smart contract governato, mai rimuovibile, deprecabile via flag `deprecated:bool`. Le voci storiche restano eternamente verificabili; la deprecazione blocca solo nuove firme con quell'algoritmo. Questo è **il fulcro dell'agilità a 20+ anni**: permette di aggiungere verifier per algoritmi on-ramp vincitori 2028-2029 o successori ancora non nati senza toccare il consenso base.

Ogni account dichiara il proprio verifier contract via **account abstraction** (pattern ERC-4337/Aptos native AA/Solana precompile registry): un'istituzione può preferire SLH-DSA-192s per compliance archivistica, un utente retail ML-DSA-44 per gas economico, un account high-value dual ML-DSA + SLH-DSA. Il modello di gas deve prezzare il lavoro del verifier in modo che SLH-DSA sia razionale ma non gratuito.

### Consenso vs application layer

Separazione netta:
- **Consenso** (firme validator/blocchi): superficie minima, primario ML-DSA-65/87 + fallback SLH-DSA-192s esplicitamente documentato. Astratto dietro interfaccia `Signer`/`Verifier`, swap = una modifica enum + dispatch table
- **Application** (transazioni utente): envelope TLV completo, dispatch precompile, registro verifier governato. AA permette scelta per-account

### Migrazione e orizzonte 20+ anni

Pattern di migrazione a quattro fasi:
1. **Fork A (ora)**: introdurre registro verifier, envelope TLV, precompile SLH-DSA. ML-DSA resta default
2. **Fork A+6 mesi**: conti sistema ad alto valore (bridge, treasury, governance) obbligati all'ibrido parallelo (ML-DSA + SLH-DSA)
3. **Fork A+12 mesi**: account AA possono opt-in all'ibrido; fee market riflette costo extra
4. **Contingency fork pre-pianificato**: se ML-DSA viene indebolito, governance flippa primario → SLH-DSA in un'epoca, perché verifier e chiavi sono già on-chain

**Archival overlay**: firma batch SLH-DSA-256s sulla Merkle root ogni epoca, pubblicata via timestamping RFC 3161 a anchor esterni (altre catene, TSA pubbliche). Rinnovo per RFC 4998 ogni 5 anni (ri-hash con hash più forte + re-timestamp). Allineamento a **ETSI TS 119 512** e **BSI TR-03125/TR-ESOR** per preservation service qualificati. Uso di **SHAKE-256** come hash Merkle primario (margine long-term più forte tra gli standard NIST, allineato a SLH-DSA-SHAKE).

### Lock-in da evitare

- ❌ Hardcoding di ML-DSA a livello opcode/precompile-ID senza registry
- ❌ Composite ML-DSA IETF (OID unico) — ricompositing è migrazione costosa
- ❌ Assumere che un'aggregazione BLS-like arriverà in PQ; pianificare aggregazione SNARK o blocchi più grandi
- ❌ FN-DSA prima del FIPS 206 finale e fixed-point — determinismo FP può perseguitare la verifica storica nel 2046
- ❌ XMSS/LMS stateful per account utente (backup distruggono chiavi)
- ❌ Hash canonico pinnato a SHA-256 per decadi
- ❌ Registro verifier mutabile da multisig piccolo — viola decentralizzazione

### Standard da monitorare 2026–2030

| Anno | Evento | Azione |
|---|---|---|
| Fine 2026/inizio 2027 | FIPS 206 (FN-DSA) finale | Valutare FN-DSA come opzione bandwidth-optimized |
| 2026 | draft-ietf-lamps-pq-composite-sigs → RFC | Review per interop X.509/eIDAS |
| 2026 | NIST IR 8547 finale (PQC transition) | Allineare deprecation calendar |
| Fine 2026 | NIST on-ramp Round 3 down-select | Watch non-lattice matury |
| 2027 | HQC FIPS finale | Valutare per eventuali feature di cifratura |
| 2027–2028 | Vincitori on-ramp annunciati | Pianificare terzo algoritmo (code/MQ/MPCitH) |
| 2028–2029 | FIPS on-ramp vincitori | Valutare come terzo algoritmo |
| 2029 | CNSA 2.0 deadline USA per ML-KEM/ML-DSA | Segnale regolamentare |
| 2030 | NIST deprecation RSA/ECC federale | No residui classical-only |
| 2029–2030 | Ethereum L1 PQ-complete | Studio leanXMSS + leanVM come reference |

---

## Area 4 — Strategia validatori indipendenti

### Milestone Fase 8: 5 validatori per 7 giorni

Il piano concreto per il milestone richiede approccio **closed cohort ad alto contatto**, non permissionless. Le lezioni di Aptos AIT1 (100 selezionati su 30.000 domande), Cosmos Game of Stakes (slashing troppo aggressivo all'inizio), Celestia Mocha (non-incentivato → onboarding lento) convergono sullo stesso pattern.

**Reclutamento (T−30 a T+7):**

*T−30 a T−21 (apertura candidature):* Pubblicare pagina candidato validator con spec hardware, runbook, installer one-shot, link Discord, KYC-lite (identità + giurisdizione + regione + classe hosting). **Target ~25 candidature, selezione 8–12 operatori** (slack per churn, 5 concorrenti attivi su 7 giorni). Reclutamento da: Cosmos validator Discord, Polkadot 1KV, EthStaker, Rocket Pool, Celestia cohort, Aptos/Sui operators, comunità PQC (Open Quantum Safe).

*T−21 a T−14:* Accordi firmati, token testnet, materiali genesis. **Call di onboarding individuali** da 30 minuti (modello Near Pagoda).

*T−14 a T−7 (dry run):* Soft-launch su chain-id transient; gate all'80% di operatori sincronizzati; altrimenti reset.

*T0 (finestra milestone aperta):* Chain-id finalizzato; 7 giorni decorrono dal primo blocco con ≥5 esterni firmanti. Dashboard observer pubblica, copertura Discord 24/7 a 3 turni, war-room video bridge.

*T+7 (chiusura):* Criteri successo: 5+ operatori con ≥95% uptime, ≥4 giurisdizioni, ≥3 classi hosting, zero incidenti safety. Post-mortem pubblico stile Aptos AIT.

**Design incentivi:** ricompensa flat per operator riuscito (es. 5.000 token testnet redimibili 1:1 per allocazione mainnet, **lockup 12 mesi**, **carve-out US** = solo riconoscimento non-token); bonus top-quartile 1.000; bonus diversità giurisdizionale 500 per regioni sotto-rappresentate (Africa, Sud America, Oceania).

**Pitfall tipici:** DDoS durante finestra milestone (pre-organizzare mitigazione Cloudflare Spectrum + BGP blackhole); client monoculture (priorità secondo client in Fase 9); permissionless prematuro; drift geo-concentration (check giornaliero); slashing troppo aggressivo (downtime a 0,01% in Fase 8, ratchet solo a mainnet); ambiguità reward (review legale pre-pubblicazione).

### Requisiti hardware: low barrier con overhead PQ

L'overhead delle firme PQ è il fattore dominante nei requisiti. Le dimensioni crescono di 10× (Falcon), 40× (ML-DSA), fino a 600× (SPHINCS+) rispetto a ECDSA/EdDSA. Un blocco da 1 MB ECDSA che ospita ~7.600 tx ospita solo ~400 tx con SPHINCS+. Per ML-DSA il fattore è ~2,5-10 MB equivalente per stesso count tx. Verifica ML-DSA è **più veloce** di ECDSA al L5 (0,14 ms vs 0,88 ms su ARM laptop), Falcon verifica rapidissima, SPHINCS+ CPU-heavy (limitare a eventi infrequenti: checkpoint, rotazione chiavi).

**Spec minima consigliata (decentralization-first, home staking fattibile):**
- **CPU:** 8 core moderni (AMD Zen 4+ / Intel 12th+ / Apple M-series / ARM Neoverse-N2); AES-NI + AVX2 required; SHA extensions fortemente preferite
- **RAM:** 32 GB ECC raccomandati, 16 GB minimo
- **Storage:** 2 TB NVMe SSD enterprise; crescita ~1 TB/anno a 5 anni per footprint PQ; snapshot/state-sync first-class
- **Rete:** 200 Mbps simmetrica sustained, unmetered o cap ≥10 TB/mese; 1 Gbps se serve anche RPC
- **Power:** UPS + generator 4h o dual-grid colo; SLA 99,9%
- **Remote signer obbligatorio:** tmkms-style o Horcrux threshold

Attenzione cloud TOS: AWS, GCP, Azure permessi; **Hetzner, DigitalOcean bannano o restringono** nodi crypto; Latitude.sh, OVH dedicated, Vultr bare-metal, Hivelocity, Equinix Metal friendly.

### Diversificazione geografica e giurisdizionale

Il crollo Hetzner 2022 (~1.000 nodi Solana offline in ore, ~40% validatori/20% stake all'epoca) e l'outage AWS US-EAST-1 ottobre 2025 (Coinbase, Base, Infura, Robinhood simultaneamente giù) sono casi studio canonici. Ethernodes misura AWS ~28% dei nodi Ethereum execution, Hetzner ~15-16%; la concentrazione cross-chain su AWS/Hetzner/OVH/GCP/Oracle va dal 55% all'80% in molte catene PoS.

**Geografico ≠ giurisdizionale**: tre operatori su AWS Frankfurt, AWS Ohio, AWS Singapore sono geograficamente diversi ma condividono l'avversario USA (CLOUD Act).

| Dimensione | Fase 8 (milestone) | Mainnet Y1 | Y5+ |
|---|---|---|---|
| Giurisdizioni distinte | ≥4 | ≥10 | ≥25 |
| Regioni geografiche (continenti) | ≥3 | ≥5 | tutti e 6 abitati |
| Classi hosting (bare/home/cloud/colo) | ≥3 | ≥4 | ≥4 |
| Max stake per operatore | ≤20% | ≤10% | ≤3% |
| Max stake per cloud/ASN | ≤40% | ≤25% | ≤15% |
| Nakamoto coefficient (stake) target | n/a | ≥10 | ≥30 |
| Top-client share | n/a | ≤66% | ≤33% |

Leve di incentivazione: slot riservati per regione (pattern Aptos AIT); programma di delegazione che auto-nomina regioni sotto-rappresentate (backend Polkadot 1KV); bonus slashing-uncorrelated (ASN diversi, provider diversi, client version diverso); cap effettivo soft sullo stake; bounty diversità client co-finanziati con secondo team.

### Modello economico e sostenibilità long-term

Yield attuali (aprile 2026): Ethereum ~2,9-3,5% nominale / ~2,5-3% reale; Cosmos Hub 14-21% / 1-7% reale; Polkadot 11-14,7% / ~4-7%; Near ~4,9% / ~2,7%; Solana ~6,5-7% / ~1,5-2%; Aptos ~7,3% / ~2%; Sui ~2-3% / ~1%. La "trappola Cosmos" — 20% nominale che netta ~2% reale — va evitata: **target real yield 3-5%**.

**Parametri economici concreti raccomandati:**
- Inflazione genesi 8% Y1, decrescita lineare 0,5 pp/anno fino a floor 1% in Y15 (totale ~70-75% supply genesis in 20 anni)
- Split issuance: 80% validator+delegator, 10% treasury public goods, 10% fondo diversità infrastruttura (grant giurisdizioni/client sotto-rappresentati)
- Commissione: floor 3%, ceiling 25%, default 7% (floor anti-race-to-zero che escluderebbe piccoli operatori)
- Split fee: 70% validator/delegator, 20% treasury, 10% burn (regolabile governance)
- Slashing: 0,01-0,1% downtime (lento, pardonable), 5% double-sign (veloce, non-pardonable)
- Unbonding 21 giorni
- Min self-bond equivalente ~$5.000-10.000 a mainnet
- **Buffer di agilità crittografica**: ≥5% del treasury annuo earmarked per future migrazioni PQ (ogni ~10 anni)

**Crossover fee-primacy target Y8-Y12**: punto in cui revenue da fee raggiunge/supera issuance. Tracking pubblico trimestrale. Target revenue per validator solo mainnet Y1: **$30k-$60k/anno** per coprire colo bare-metal $10-20k/anno + tempo operatore + contingenza.

**Evitare restaking nel protocollo base**: la caduta TVL di EigenLayer da $25B peak a ~$7B dopo il lancio slashing 2025 illustra che pooled security aggiunge superficie di slashing correlato. Se AVS-style services emergono, confinarli a layer applicativo con cap per-AVS e slashing isolato.

### Quadro regolamentare: posizione consigliata

**EU MiCA** (in vigore CASP dal 30 dicembre 2024): CASP autorizzati saliti da ~15 a decine a Q1 2026 (Germania 18, NL 14). **Esenzione "pure validation"**: MiCA target servizi "fully decentralized" per esclusione, test stretto. **Un validator che partecipa solo al consenso e non custodisce asset utente è generalmente fuori scope CASP**; un validator che markets delegazione/staking a retail UE quasi certamente in scope. Capital floor se CASP: €50k advisory / €125k exchange / €150k custody. Multe ESMA/NCA >€540M da implementazione; Francia €62M su singola piattaforma.

**USA** — Kraken 2023 ($30M + stop staking USA), Coinbase litigation in corso, **maggio 2025 statement SEC staff** chiarisce che "protocol staking activities" possono stare fuori da securities laws se amministrative/tecniche più che imprenditoriali. Posizione più sicura: no pooling con management discrezionale, no promessa di yield, commissioni disclosed, no "slashing protection" come servizio promesso. FinCEN 2019 generalmente esclude pure validator da money transmitter; MTL statali variabili.

**Asia:** Giappone (JFSA) — CASP registrati, staking spesso regolato; Singapore (MAS) — staking retail ristretto dal 2023; Hong Kong (SFC) — 2024 permette piattaforme licenziate con condizioni.

**Checklist regolamentare:**
1. Non promettere yield a retail; no pooling con rebalancing discrezionale a livello protocollo
2. Pubblicare **validator legal FAQ** che distingue pure validation da staking-as-a-service
3. Sanctions screening su operatori cohort incentivato (pattern Aptos)
4. **US-participant carve-out**: partecipazione sì, token reward no fino a mainnet + lockup
5. Guidance operatore EU: template self-assessment esposizione CASP
6. Watchlist regolamentare: 6 paesi MiCA transitional, UK FCA, output US Crypto Task Force

### Agilità crittografica a livello validator

Sette affordance richieste:

1. **Identità validator algorithm-agnostic**: record on-chain stabile `{validatorID, activeAlgorithm, activePubkey, rotationEpoch}`, aggiornabile via messaggio firmato validato sotto vecchio o nuovo scheme durante dual-signing window
2. **Dual-signing windows** a migrazione algoritmo: epoca di transizione con firma sotto entrambi; ≥2/3 stake deve aver ruotato prima del cutover; timelock
3. **Rotazione chiave online** senza downtime: hot-swap remote signer (tmkms atomic switch o Horcrux threshold shard-by-shard)
4. **Firme algorithm-versioned nel wire format**: ogni firma porta algo_id esplicito; vietata reinterpretazione silente
5. **Break-glass d'emergenza**: fast-track governance (timelock 48h invece di 7 giorni) per migrazione a scheme backup pre-registrato. **Pre-registrare ≥2 scheme backup PQ** in ogni major release
6. **Diversità client = leva di agilità** — due implementazioni indipendenti riducono il rischio di bug-forzata
7. **DKG/resharing DVT**: se si usa DVT, selezionare DKG con migration path PQ documentato

### Lock-in da evitare

Single-algorithm, single-client, single-cloud (cap max 40% pre-mainnet, 25% post), single-jurisdiction, restaking base-layer, governance-token-centric (solo on-chain senza signaling off-chain = plutocrazia), doc-platform SaaS (docs in repo client + static site generator), KYC-vendor, indexer/explorer unico (finanziare minimo 2 explorer indipendenti).

### Standard e programmi da monitorare

NIST PQC additional rounds, IETF PQ TLS/hybrid-KEM/PQ CMS, Open Quantum Safe (liboqs), MiCA secondary legislation (Commission Delegated Regulations 2025/303, 304, 306, 414, 416, 1142), SEC Crypto Task Force, EigenLayer post-aprile-2025 slashing data, Polkadot 1KV backend (w3f/1k-validators-be), Ethereum EIP-7251 MAX_EFFECTIVE_BALANCE, DVT maturity (SSV mainnet 30k+ validatori, Obol cluster), dashboard Nakamoto (Chainspect, Nakaflow, EDI), DORA (operatori CASP-classificati).

---

## Sintesi trasversale e priorità per la Fase 8

### Effetti di interazione critici

Il vincolo dominante che attraversa tutte e quattro le aree è **l'incompatibilità tra aggregazione BLS e firme PQ**. Non esiste oggi un equivalente post-quantistico dell'aggregazione illimitata di BLS12-381. Questo ha tre conseguenze a cascata: (1) limita il comitato per epoca a ~200-500 validatori con verifica naive fino a che l'aggregazione STARK non matura (~2029 per Ethereum Lean); (2) amplifica 10-600× la larghezza di banda P2P, forzando l'uso di GossipSub v1.2 con IDONTWANT e potenzialmente Turbine-style erasure coding; (3) aumenta i requisiti RAM/storage/bandwidth dei validatori, toccando il principio di decentralizzazione (se le spec hardware salgono troppo, si escludono home stakers).

Il secondo effetto di interazione importante è che **le VRF classiche sono PQ-broken**, quindi la selezione secret-leader (Algorand, Cardano) non è disponibile nel breve periodo. Si deve accettare una selezione non-secret (RANDAO + VDF) con conseguente maggior rischio di DoS mirato sul proposer, mitigato da architettura a sentry e comitati piuttosto piccoli.

Il terzo effetto riguarda **l'archival a 20+ anni**: anche se ML-DSA fosse compromesso nel 2040, la chain deve restare verificabile. Questo impone la strategia dell'overlay hash-based (SLH-DSA-256s firma la Merkle root di epoca, timestamp RFC 3161 a anchor esterni, rinnovo RFC 4998 ogni 5 anni) e vieta qualsiasi scelta di hash primario diversa da SHAKE-256.

### Lock-in risk register

I rischi di lock-in più gravi, ordinati per impatto:

1. **Hardcoding di primitive crittografiche a livello wire-format/opcode** — violazione diretta dell'agilità, migrazione richiederebbe hard fork
2. **Aggregazione STARK legata a zkVM specifico senza proof-format versioning** — ricostruire verifier richiederebbe mesi
3. **Composite signatures IETF (OID unico PQ+T)** — ricompositing è migrazione costosa
4. **FN-DSA pre-FIPS 206 finale** — determinismo FP perseguita verifica storica
5. **Slashing/unbonding immutabili** — brittle su 20 anni, togliere la leva di governance è tradimento del principio #1
6. **Base-layer restaking** — contagion slashing, vedi caduta EigenLayer
7. **Multiaddr/protocollo wire pinnato senza versioning** — riscritture storiche esistono
8. **Dipendenza da upstream unico** (rust-libp2p senza fork) — 0.x semver churn
9. **Cloud/jurisdiction monoculture** — outage AWS ottobre 2025, Hetzner 2022
10. **Single-client lock-in** — bug implementativi diventano bug di consenso

### Action items prioritari per Fase 8

**Immediati (entro chiusura audit Fase 8):**
1. Sostituire tunnel SSH con libp2p-TLS 1.3 su TCP, X25519 classico + flag hybrid X25519MLKEM768, parallel-transport con SSH per 2 settimane testnet
2. Attivare ibrido PQ di default, listener QUIC, test frammentazione ClientHello
3. Architettura tre reti (validator privata/VFN/pubblica) + pattern sentry
4. Piano reclutamento closed cohort 8-12 operatori per milestone 5-validatori-7-giorni, lockup 12 mesi su reward, carve-out US
5. Pubblicare validator legal FAQ distinguendo pure validation da SaaS
6. Registro verifier on-chain in architettura: `algo_id → verifier_contract` con `deprecated:bool`
7. Envelope TLV multicodec-prefixed per firme e chiavi pubbliche; registrare codepoint multicodec upstream per ML-DSA, SLH-DSA
8. Precompile stabili: `verify_ml_dsa`, `verify_slh_dsa`, `poseidon2_hash`, `stark_verify`

**Entro mainnet (Fase 9-10):**
9. Introdurre SLH-DSA-SHAKE-192s come verifier secondario attivo; hot/conti sistema obbligati all'ibrido parallelo ML-DSA + SLH-DSA
10. GossipSub v1.2 con peer scoring calibrato per 64-256 validatori
11. Identità validator algorithm-agnostic con rotazione chiave online
12. ≥2 scheme PQ backup pre-registrati in ogni release
13. Finanziamento secondo client team
14. Correlation penalty Ethereum-style (moltiplicatore 3, finestra 36 giorni)
15. Registro evidenze slashing pluggable con timelock 30 giorni e supermaggioranza 66%

**Medio termine (anno 1-3):**
16. Archival overlay: batch SLH-DSA-256s su Merkle root per epoca, RFC 3161 timestamping a anchor esterni
17. Transizione a eligibility permissionless entro 18 mesi post-mainnet
18. Scaling comitato a 256 validatori
19. Diversity targets ≥10 giurisdizioni, ≥5 regioni, NC(stake) ≥10
20. Valutazione FN-DSA Q4 2027 come terzo algoritmo opzionale bandwidth-optimized (post-FIPS 206 finale)

**Lungo termine (anno 3-10):**
21. Aggregazione STARK leanSig/leanMultisig-style; scaling comitato a 1024
22. Migrazione a PQ-VRF una volta standardizzata IETF/NIST
23. Valutazione vincitori on-ramp NIST 2028-2029 come terzo algoritmo (preferibilmente non-lattice: MAYO, CROSS, FAEST, SQIsign)
24. Fee-primacy crossover Y8-Y12
25. Diversity targets Y5+: ≥25 giurisdizioni, tutti i continenti abitati, NC(stake) ≥30, top-client ≤33%

### Chiusura: il principio di sopravvivenza

La lezione trasversale è semplice da enunciare e difficile da eseguire: **ogni scelta crittografica e di consenso deve essere dietro un'interfaccia versionata governata on-chain, mai nel wire format**. Il registro verifier, il registro validator, il registro dei parametri di consenso, il registro degli evidence-verifier per slashing — sono tutti la stessa idea applicata a domini diversi. La blockchain non sopravvive perché sceglie bene oggi; sopravvive perché si tiene il diritto di cambiare idea dopo.

Le blockchain che hanno sbagliato in questo — Ethereum con i suoi nove hard fork, Cosmos con la frammentazione SDK — hanno pagato in legittimità e frizione comunitaria. Quelle che stanno andando meglio (Tezos, Aptos, Sui) hanno scelto governance on-chain aggressiva dal giorno uno. Per una catena che mira a 20+ anni di notariato archivistico, questa non è una scelta di stile: è la condizione necessaria di esistenza.

ML-DSA-65 + SLH-DSA-SHAKE-192s + libp2p/QUIC ibrido PQ + set validatori governato + registro verifier on-chain + overlay archivistico hash-based non è la configurazione "ottimale" per le metriche di oggi. È la configurazione che **permette a quelle metriche di cambiare** senza riscrivere il contratto sociale della rete. È questa, e non la performance grezza, la vera misura dell'infrastruttura di fiducia a lungo termine.