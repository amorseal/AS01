# Verification Guide

This guide is for a skeptical reviewer who wants to confirm the core claim:

> A letter can be recovered from phrase + on-chain bytes using only public code.

## 1. Verify the package is local-only in offline modes

Open `recover.html` and inspect the code:

- `AS01 payload` mode never needs network access
- `Raw transaction JSON / witness JSON` mode never needs network access
- only `Bitcoin txid` mode performs public read-only `GET` requests

The browser tool does not call `amorseal.com`.

## 2. Verify the deterministic fixture round-trip

Run:

```bash
npm run verify:roundtrip
```

That script checks three paths using the bundled example fixture:

1. direct payload decryption through the standalone Node library
2. raw transaction JSON decryption through the standalone Node library
3. raw transaction JSON decryption through the standalone CLI

The expected plaintext is:

```text
This is a test letter for AS01 verification
```

If all three match exactly, the public package can recover a real `AS01` envelope without any Amor Seal runtime dependency.

## 3. Verify the browser tool yourself

1. Open `recover.html`
2. Choose `Raw transaction JSON / witness JSON`
3. Paste the contents of `fixtures/example-raw-tx.json`
4. Paste the phrase from `fixtures/example-phrase.txt`
5. Click `Open letter`

The browser should display:

```text
This is a test letter for AS01 verification
```

## 4. Verify the letter bytes are really the bytes used by the tool

Check `fixtures/example-raw-tx.json`.

Its witness stack contains:

- a signature placeholder
- a witness script containing the `amorseal` marker
- the embedded `AS01` payload
- a control block placeholder

The recovery code extracts the `AS01` envelope from those witness bytes, not from any server-side lookup.

## 5. Verify the txid mode boundary

`txid` mode is convenience, not trust.

If you distrust public APIs, fetch raw transaction JSON yourself from a block explorer or your own Bitcoin node, save it to disk, and use raw JSON mode. The decryption result should match.

## 6. Verify offline use

Disconnect the machine from the network and use either:

- `AS01 payload` mode, or
- `Raw transaction JSON / witness JSON` mode

The browser tool should still recover the letter because AES-GCM, PBKDF2, parsing, and Brotli decompression all run locally.

## 7. Verify no secrets shipped

Run:

```bash
npm run verify:secret-scan
```

The scan checks for common secret markers and should return a clean result.
