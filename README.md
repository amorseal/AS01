# Amor Seal Recovery Tool

This repository is the public recovery package for `AS01`, the phrase-encrypted letter format used by Amor Seal Heirloom letters.

The promise it backs is simple:

> If you have the opening phrase and the Bitcoin transaction data, you can open the letter with only this code, even if Amor Seal no longer exists.

This package contains:

- `SPEC.md` — the protocol specification, written from the frozen `src/lib/as01/*` engine
- `recover.html` — a static browser tool that runs locally
- `cli/recover.mjs` — a Node CLI recovery tool
- `fixtures/` — throwaway example payload and raw witness data
- `VERIFY.md` — how to verify the claim independently

## Quick start

### Browser

1. Open `recover.html` in a browser.
2. Choose one input mode:
   - `AS01 payload`
   - `Raw transaction JSON / witness JSON`
   - `Bitcoin txid`
3. Paste the 6-word phrase.
4. Click `Open letter`.

`AS01 payload` and `Raw transaction JSON / witness JSON` work fully offline.

`Bitcoin txid` mode makes public read-only `GET` requests to public Bitcoin APIs. If you want fully offline verification, fetch the raw transaction JSON yourself and use raw JSON mode instead.

### CLI

Recover from a payload:

```bash
node cli/recover.mjs \
  --payload-file fixtures/example-payload.txt \
  --phrase-file fixtures/example-phrase.txt
```

Recover from raw witness transaction JSON:

```bash
node cli/recover.mjs \
  --raw-tx-file fixtures/example-raw-tx.json \
  --phrase-file fixtures/example-phrase.txt
```

Use the bundled example verification:

```bash
npm run verify:roundtrip
```

## Plain-language explanation

An Amor Seal Heirloom letter is not stored in readable form on-chain. The on-chain bytes contain an `AS01` encrypted envelope. The 6-word opening phrase derives the decryption key locally. This package reads the on-chain bytes, derives the same key, and decrypts the letter locally.

Nothing here needs an Amor Seal account, database, private key, or API.

## What this package does not contain

- no private keys
- no inscriber keys
- no `.env`
- no database
- no Stripe code
- no server code
- no customer letters
- no customer phrases

## License

Apache-2.0.

Apache-2.0 was chosen because the static browser package includes a bundled Brotli decoder whose upstream code is Apache-2.0 licensed. See `NOTICE.md`.
