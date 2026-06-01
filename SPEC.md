# AS01 Protocol Specification

This document specifies the `AS01` recovery format implemented by the frozen Amor Seal engine in `src/lib/as01/*`.

The goal is narrow and explicit: define the format well enough that an independent developer can build a reader and decryptor from scratch.

## 1. Overview

`AS01` is the encrypted letter envelope used for permanent Amor Seal letters. The recovery promise is:

> If you have the opening phrase and the on-chain bytes, you can recover the plaintext without Amor Seal servers.

The frozen engine identifies the profile as:

- magic: `AS01`
- version: `0x01`
- profile name: `brotli+aes-256-gcm+pbkdf2-hmac-sha256`

Source:

- `src/lib/as01/as01Constants.ts:1-21`

### Threat model

`AS01` is designed so that:

- the plaintext is never required from an Amor Seal server during recovery
- the decryption key is derived from the opening phrase
- the authenticated ciphertext can be stored publicly, including on-chain
- a wrong phrase fails authentication instead of producing garbled output

What it is **not**:

- not a Bitcoin wallet format
- not a signing or inscription spec
- not a server API contract

## 2. Scope

This specification covers:

- the encrypted `AS01` envelope bytes
- the witness-marker wrapper used to embed the envelope in Bitcoin witness data
- phrase normalization and key derivation
- decryption and decompression

This specification does **not** cover:

- wallet management
- commit / reveal funding
- broadcasting Bitcoin transactions
- server persistence
- payment flows
- phrase handoff UX

## 3. Opening phrase format

### 3.1 Normative format

The opening phrase is six words.

Source:

- `src/lib/as01/as01OpeningPhraseHandoff.ts:3-4`

The phrase words are drawn from the BIP39 English wordlist.

Source:

- `src/lib/as01/as01OpeningPhraseHandoff.ts:1`
- `src/lib/as01/as01OpeningPhraseHandoff.ts:56-70`

### 3.2 Generation model

Phrase generation consumes 9 random bytes = 72 bits, then splits the first 66 bits into six 11-bit word indices.

Source:

- `src/lib/as01/as01OpeningPhraseHandoff.ts:73-90`

### 3.3 Normalization before key derivation

Before PBKDF2:

1. normalize to Unicode NFC
2. trim outer whitespace
3. collapse internal whitespace runs to a single ASCII space
4. lowercase

Source:

- `src/lib/as01/as01Kdf.ts:10-25`

The recovery implementation should follow this normalization exactly.

## 4. Plaintext normalization

Before encryption:

1. replace `\r\n` and bare `\r` with `\n`
2. normalize to Unicode NFC
3. reject all-whitespace plaintext
4. UTF-8 encode

Source:

- `src/lib/as01/normalizePlaintext.ts:3-18`

## 5. Envelope structure

`AS01` wraps the encrypted content in a binary envelope.

Source:

- `src/lib/as01/as01Envelope.ts:17-18`
- `src/lib/as01/as01Envelope.ts:24-64`
- `src/lib/as01/as01Envelope.ts:66-150`

### 5.1 Byte layout

The envelope layout is:

| Offset | Length | Meaning |
| --- | ---: | --- |
| 0 | 4 | ASCII magic `AS01` |
| 4 | 1 | version byte (`0x01`) |
| 5 | 1 | algorithm tag (`0x01`) |
| 6 | 1 | KDF tag (`0x01`) |
| 7 | 1 | compression tag (`0x00` none, `0x01` Brotli) |
| 8 | 1 | salt length |
| 9 | 1 | nonce length |
| 10 | 4 | ciphertext length, unsigned big-endian |
| 14 | `saltLength` | salt |
| ... | `nonceLength` | nonce |
| ... | `ciphertextLength` | ciphertext |
| ... | 16 | AES-GCM auth tag |

### 5.2 Fixed values for v1

For v1:

- version = `0x01`
- algorithm tag = `0x01`
- KDF tag = `0x01`
- salt length = `16`
- nonce length = `12`
- auth tag length = `16`

Source:

- `src/lib/as01/as01Constants.ts:1-16`
- `src/lib/as01/as01Envelope.ts:45-55`
- `src/lib/as01/as01Envelope.ts:83-118`

### 5.3 Compression tags

The parser accepts:

- `0x00` = no compression
- `0x01` = Brotli

Source:

- `src/lib/as01/as01Constants.ts:6-8`
- `src/lib/as01/as01Envelope.ts:19-22`

The permanent sealing path `sealAs01Message(...)` compresses before encryption and therefore emits Brotli-compressed payloads.

Source:

- `src/lib/as01/as01Seal.ts:13-27`
- `src/lib/as01/as01Compression.ts:13-27`

## 6. Encryption scheme

The frozen engine uses:

- KDF: `PBKDF2-HMAC-SHA256`
- iterations: `600000`
- derived key length: `32` bytes
- cipher: `AES-256-GCM`
- nonce length: `12` bytes
- auth tag length: `16` bytes

Source:

- `src/lib/as01/as01Constants.ts:9-16`
- `src/lib/as01/as01Kdf.ts:27-45`
- `src/lib/as01/as01Crypto.ts:10-33`
- `src/lib/as01/as01Crypto.ts:35-69`

### 6.1 KDF details

PBKDF2 input:

- password = normalized phrase UTF-8 bytes
- salt = envelope salt bytes
- iterations = `600000`
- hash = `SHA-256`
- output length = `32` bytes

Source:

- `src/lib/as01/as01Kdf.ts:35-45`

### 6.2 Cipher details

AES-GCM input:

- key = 32-byte PBKDF2 output
- IV/nonce = envelope nonce bytes
- plaintext = compressed plaintext bytes

The ciphertext and the 16-byte auth tag are stored separately in the envelope.

Source:

- `src/lib/as01/as01Crypto.ts:17-31`

During decryption, the auth tag must be supplied to AES-GCM. Any failure is treated as phrase-or-payload failure.

Source:

- `src/lib/as01/as01Crypto.ts:50-69`

## 7. Compression

`AS01` uses Brotli with deterministic parameters:

- mode = text
- quality = `5`
- lgwin = `22`

Source:

- `src/lib/as01/as01Constants.ts:18-19`
- `src/lib/as01/as01Compression.ts:13-20`

This matters for deterministic reference vectors and for re-implementing the sealing side. Recovery only needs Brotli decompression.

## 8. Bitcoin witness wrapper

The encrypted `AS01` envelope is what needs to be recovered. When embedded into witness data, the frozen engine’s witness wrapper is:

```text
OP_FALSE
OP_IF
PUSH "amorseal"
PUSH 0x01
PUSH <as01-envelope-bytes>
OP_ENDIF
PUSH <32-byte x-only pubkey OR 33-byte compressed pubkey>
OP_CHECKSIG
```

Source:

- `src/lib/as01/as01WitnessEnvelope.ts:30-68`
- `src/lib/as01/as01WitnessEnvelope.ts:80-109`

### 8.1 Marker details

- marker text = ASCII `amorseal`
- witness marker version = `0x01`

Source:

- `src/lib/as01/as01WitnessEnvelope.ts:8-10`
- `src/lib/as01/as01WitnessEnvelope.ts:41-48`

### 8.2 Reader tolerance

The recovery reader in the frozen engine is intentionally tolerant. It can recover from:

- separate witness items containing `amorseal`, then optional version byte, then payload
- inline witness items or script bytes that contain the marker and payload
- raw transaction JSON shapes exposing witness arrays through:
  - `txinwitness`
  - `witness`
  - `witnessItems`
  - `witness_items`
  - nested `vin[]`

Source:

- `src/lib/as01/as01WitnessExtraction.ts:21-56`
- `src/lib/as01/as01WitnessExtraction.ts:58-101`
- `src/lib/as01/as01WitnessExtraction.ts:104-161`

## 9. Decryption procedure

Given `phrase + on-chain bytes`, recovery proceeds as follows:

1. Extract witness items from a raw transaction JSON object, or accept the raw `AS01` payload directly.
2. Search for the `amorseal` marker and/or embedded `AS01` magic.
3. Slice out one exact `AS01` envelope by reading the header lengths.
4. Validate magic, version, algorithm tags, and lengths.
5. Normalize the phrase.
6. Derive the 32-byte key with PBKDF2-HMAC-SHA256.
7. AES-256-GCM decrypt `ciphertext + authTag` using the envelope nonce.
8. If `compressionTag == 0x01`, Brotli-decompress the decrypted bytes.
9. UTF-8 decode the resulting plaintext bytes.

Source:

- `src/lib/as01/as01RawTxRecovery.ts:6-35`
- `src/lib/as01/as01Seal.ts:54-76`
- `src/lib/as01/as01WitnessExtraction.ts:136-161`

## 10. Versioning

Version signaling exists in two places:

- the `AS01` envelope version byte at offset `4`
- the witness-marker version byte pushed after `amorseal`

Current values:

- envelope version = `0x01`
- witness marker version = `0x01`

Source:

- `src/lib/as01/as01Constants.ts:1-2`
- `src/lib/as01/as01WitnessEnvelope.ts:43-45`
- `src/lib/as01/as01WitnessEnvelope.ts:88-89`

Future versions should:

- use a different envelope version and/or algorithm tag set
- preserve fail-closed parsing on unknown values

The current parser rejects unsupported versions and unsupported algorithm tags.

Source:

- `src/lib/as01/as01Envelope.ts:77-100`

## 11. Public txid fetch boundary

The frozen engine’s read-only txid recovery path uses public `GET` fetches only. The default providers are:

- Blockstream: `https://blockstream.info/api/tx/{txid}`
- Blockchair: `https://api.blockchair.com/bitcoin/dashboards/transaction/{txid}`

Source:

- `src/lib/as01/as01TxFetch.ts:10-21`
- `src/lib/as01/as01TxFetch.ts:45-96`

These providers are convenience only. They are not part of the cryptographic trust model. A skeptical user can always fetch raw transaction JSON elsewhere and use raw JSON mode.

## 12. Intentionally out of scope

This specification deliberately excludes:

- how to fund or broadcast commit/reveal transactions
- how to select Taproot keys
- how the sender receives the opening phrase
- any Amor Seal server persistence model
- any email, Stripe, database, or admin workflow

Those concerns are not needed to recover a letter from phrase + on-chain data.
