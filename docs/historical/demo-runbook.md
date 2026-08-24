# Viper Chain — Demo Runbook

Guida passo-passo per eseguire una demo live davanti a un investitore o partner.

Data: 2026-04-17 (initial) · 2026-04-25 (banner update for viper-pq-1 launch)

> **Aggiornamento 2026-04-25**: la chain dimostrata gira ora su `viper-pq-1` (lanciata 2026-04-25, ADR-053). Il flusso e gli endpoint restano gli stessi documentati sotto (notarize/verify/explorer su `https://pqchain.agwswebconsulting.it/`); l'unica differenza visibile è il `chain_id` nelle ricevute (`viper-pq-1` invece del precedente `viper-mainnet-1` / `viper-devnet-2`). Le SDK 0.2.0 (npm `@v1p3r4llbl4ck/sdk@0.2.0` + PyPI `viper-pqchain==0.2.0`, pubblicate 2026-04-25) sono già allineate al nuovo chain_id come default.

---

## Pre-requisiti

- La devnet deve essere attiva (verificare che `pqchain.agwswebconsulting.it` risponda)
- Avere un PDF o documento qualsiasi sul dispositivo (per la demo notarizzazione)
- Browser aggiornato (Chrome, Firefox, Safari)

---

## Demo Script (5 minuti totali)

### Passo 1 — Dashboard (30 secondi)

Apri `https://pqchain.agwswebconsulting.it`

Mostra:
- "Guardate: la chain e live, sta producendo blocchi in tempo reale"
- Indica il CHAIN HEIGHT che sale
- Indica LIVE verde in alto a destra
- "Questa infrastruttura gira su 3 nodi indipendenti con consenso distribuito"

### Passo 2 — Notarizzazione live (60 secondi)

Clicca "Notarize" nella navbar.

1. "Ora vi mostro come si certifica un documento"
2. Trascina un PDF nella drop area (o clicca per selezionare)
3. "Il documento non lascia mai il vostro dispositivo — viene calcolata solo un'impronta digitale nel browser"
4. Clicca "Notarize document"
5. Mostra il risultato: attestation ID, transaction hash
6. "Questo documento e ora certificato sulla nostra infrastruttura. Nessuno puo modificarlo retroattivamente, nemmeno noi"

### Passo 3 — Verifica (30 secondi)

Clicca "Verify" nella navbar.

1. Copia l'attestation ID dal passo precedente
2. Incollalo nel campo di verifica
3. "Chiunque con questo ID puo verificare che il documento esiste — in qualsiasi momento, da qualsiasi parte del mondo"
4. Mostra i dettagli: data, issuer, status

### Passo 4 — API Documentation (60 secondi)

Clicca "API Docs" nella navbar (o vai a `/docs`).

1. "Tutto quello che avete visto si integra via API REST standard"
2. Mostra la Swagger UI con le categorie: Credentials, Proofs, Chain, System
3. Clicca su `GET /api/health` → "Try it out" → Execute
4. Mostra la risposta JSON live
5. "Un'integrazione richiede una POST HTTP — come qualsiasi altro servizio cloud"

### Passo 5 — Explorer (60 secondi)

Clicca "Explorer" nella navbar.

1. Mostra i blocchi che scorrono in tempo reale
2. Clicca su un blocco per vedere i dettagli
3. "Ogni blocco e firmato dai validatori con crittografia resistente al quantum computing"
4. Se c'e la transazione della notarizzazione, cliccala e mostra i dettagli

### Chiusura (30 secondi)

Torna alla Dashboard.

"Quello che avete visto e un'infrastruttura di certificazione digitale che:
- certifica documenti in modo permanente
- e resistente alla minaccia del quantum computing
- si integra via API come qualsiasi SaaS
- e operativa oggi su una rete di test"

---

## Domande frequenti durante la demo

**"Quanto costa una notarizzazione?"**
> "Il modello e pay-per-use: da 50 centesimi a 5 euro per attestazione, con abbonamenti mensili per studi e aziende."

**"Quanto tempo ci vuole per la certificazione?"**
> "La notarizzazione e quasi istantanea — il tempo del prossimo blocco, circa 1-2 secondi."

**"I dati del documento sono sulla blockchain?"**
> "No. Solo l'impronta digitale (hash) del documento va on-chain. Il documento originale resta sul vostro dispositivo o nei vostri sistemi. Nessun dato sensibile e esposto."

**"Cosa succede se i server vanno giu?"**
> "L'infrastruttura e distribuita su nodi indipendenti. Anche se un nodo va offline, gli altri continuano a operare. I dati sono replicati e immutabili."

**"E se un dipendente modifica un documento dopo la notarizzazione?"**
> "L'hash non corrispondera piu. La verifica mostrera immediatamente che il documento e stato alterato."

**"Come si integra con i nostri sistemi?"**
> "Una chiamata API REST. POST per certificare, GET per verificare. Abbiamo SDK in TypeScript e Python, e una documentazione Swagger interattiva che avete appena visto."

---

## API Quick Reference per la demo

### Verificare che la chain sia attiva

```
GET /api/health
```

Risposta:
```json
{
  "status": "ok",
  "chain_height": 4066,
  "node_id": "producer-1",
  "uptime_seconds": 120
}
```

### Notarizzare un documento (via API)

```
POST /api/notarize
Content-Type: application/json

{
  "document_hash": "<sha256 del documento in hex>",
  "filename": "contratto.pdf",
  "mime_type": "application/pdf"
}
```

### Verificare un'attestazione (via API)

```
GET /api/verify/<attestation_id>
```

### Emettere una credenziale (via API)

```
POST /api/credentials/issue
Content-Type: application/json

{
  "issuer_address": "<indirizzo hex dell'emittente>",
  "subject": "<identificativo del soggetto>",
  "credential_type": "diploma",
  "content_hash": "<hash del contenuto>",
  "schema_id": "university-diploma-v1"
}
```

### Ancorare una prova documentale (via API)

```
POST /api/proofs/anchor
Content-Type: application/json

{
  "owner_address": "<indirizzo hex del proprietario>",
  "claim_type": "notarization",
  "document_hash": "<hash del documento>",
  "proof_hash": "<hash della prova>"
}
```

### Consultare lo stato della chain

```
GET /v1/status
```

### Consultare un blocco

```
GET /v1/blocks/<height>
```

### Consultare un account

```
GET /v1/accounts/<address_hex>
```

---

## Troubleshooting durante la demo

| Problema | Soluzione rapida |
|----------|-----------------|
| Dashboard mostra OFFLINE | Verificare che pqcd sia attivo: `systemctl status pqcd` sul producer |
| Notarizzazione fallisce | Il notary backend potrebbe essere giu: `systemctl status viper-notary` |
| Explorer non carica | Cache browser — Ctrl+Shift+R per hard refresh |
| API /docs non risponde | Il binario pqcd potrebbe non avere gli endpoint nuovi — verificare la versione deployata |
| "502 Bad Gateway" | nginx non riesce a raggiungere il backend — verificare che pqcd e viper-notary siano attivi |
