<div align="center">

# AS01

### The Amor Seal envelope format for permanent, phrase-encrypted letters on Bitcoin.

*A letter you write today, sealed so that it can be opened on a chosen day — years from now — by the one person who holds the phrase. Encrypted before it ever leaves the writer's hands. Written permanently onto the Bitcoin timechain. Recoverable forever, with this code alone, even if Amor Seal no longer exists.*

</div>

---

## What AS01 is

AS01 is the envelope format that Amor Seal designed to seal a private letter onto Bitcoin so that it is at once **permanent**, **private**, and **recoverable without us**.

Most ways of "storing something forever" quietly depend on a company staying alive — a server, an account, a database, a login. AS01 was built to break that dependency. An AS01 letter is encrypted with a key derived from a six-word opening phrase, compressed, wrapped in a self-describing envelope, and inscribed into the witness data of a Bitcoin transaction. From that moment the letter lives on the timechain, not on our servers. We cannot read it. We cannot change it. We cannot lose it for you. And if Amor Seal disappears tomorrow, the letter is still there, and this repository is still all anyone needs to open it.

**This repository is that guarantee, made real.** It is the complete, public, independently runnable package for opening any AS01 letter. It is the proof that "recoverable forever" is not a marketing line — it is a property of the format.

## The promise it backs

> If you hold the opening phrase and the Bitcoin transaction, you can open the letter with only the code in this repository — on any machine, offline, with no account, no server, and no permission from anyone, for as long as Bitcoin exists.

## How an AS01 letter works

The writer's letter is never stored in readable form on-chain. The journey is:

1. **Encrypt** — the letter is encrypted on the writer's side with AES-256-GCM. The key is derived from the six-word opening phrase using PBKDF2-HMAC-SHA256 (600,000 iterations). The phrase is the only key; it is never stored with us.
2. **Compress** — the plaintext is Brotli-compressed before encryption so a long letter fits efficiently on-chain.
3. **Wrap** — the ciphertext is placed inside the AS01 envelope: a versioned, self-describing structure marked with the `AS01` magic bytes, so any reader can recognize and parse it without external instructions.
4. **Inscribe** — the envelope is written into the witness of a Bitcoin transaction using the standard inscription envelope mechanism, marked with the `amorseal` tag. Once confirmed, it is permanent.

To open it, this package walks the same path in reverse: read the on-chain bytes, find the AS01 envelope, derive the key from the phrase, decrypt, decompress, and return the original letter — entirely on your own device.

The full byte-level format, cipher parameters, and key derivation are documented in **[`SPEC.md`](SPEC.md)**, written directly from the production sealing engine. Anyone can implement an independent reader from that document alone — this code is simply the reference implementation.

## What's in this repository

| File | What it is |
|------|------------|
| **[`SPEC.md`](SPEC.md)** | The complete AS01 format specification — envelope structure, cipher, key derivation, byte layout |
| **[`recover.html`](recover.html)** | A single-file recovery tool that runs entirely in your browser, no server |
| **[`cli/recover.mjs`](cli/recover.mjs)** | A command-line recovery tool for Node.js |
| **[`fixtures/`](fixtures/)** | A throwaway example letter, phrase, and witness data so you can prove the tool works |
| **[`VERIFY.md`](VERIFY.md)** | How a skeptic can independently verify the whole promise, end to end |

## Open your letter

You need two things: your **six-word opening phrase** and your **Bitcoin transaction** (the transaction id, or its raw data).

### In your browser — the simplest way

1. Download this repository, or just the file `recover.html`.
2. Open `recover.html` in any browser. (It runs locally. You can disconnect from the internet first if you wish.)
3. Choose how you'll provide the letter:
   - **AS01 payload** — if you already have the raw envelope
   - **Raw transaction JSON / witness JSON** — fully offline, if you've fetched the transaction yourself
   - **Bitcoin transaction id** — the tool fetches the transaction for you from public Bitcoin explorers
4. Enter your six-word phrase.
5. Click **Open letter**.

The **AS01 payload** and **raw transaction JSON** modes work with no internet connection at all. The **transaction id** mode makes read-only requests to public Bitcoin APIs to fetch the transaction; if you'd rather stay fully offline, fetch the raw transaction yourself and use raw JSON mode.

### On the command line

Recover from a raw AS01 payload:

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

Run the bundled round-trip proof:

```bash
npm run verify:roundtrip
```

## Why you can trust this without trusting us

The strength of an AS01 letter is in the phrase, never in secrecy. The format is fully published, the algorithm is standard and auditable, and the code here is the same decryption path used in production — extracted to run alone. A locked box whose blueprints are public but still cannot be opened without the key is a stronger box than one that only seems safe because no one has seen inside it.

That is why everything is open. You do not have to take our word that your letter is recoverable. You can read the spec, run the tool, and prove it yourself — today, and in twenty years. See **[`VERIFY.md`](VERIFY.md)** for the step-by-step proof.

## What this repository deliberately does **not** contain

Opening a letter requires only the public format and your private phrase. So nothing private is here, and nothing private ever will be:

- No private keys or inscriber keys
- No `.env`, secrets, or API credentials
- No database, server code, or business logic
- No Stripe or payment code
- No customer letters
- No customer phrases

Your phrase is yours alone. We never have it, and this code never needs it from anyone but you.

## License

**Apache-2.0.**

The browser tool bundles a Brotli decompressor so it can run with no dependencies; that upstream component is Apache-2.0 licensed, so this package adopts the same license to remain fully compatible and properly attributed. Attribution is preserved in [`NOTICE.md`](NOTICE.md). Apache-2.0 is a permissive license: you are free to use, study, copy, modify, and redistribute this code, including to build your own independent reader for the AS01 format.

---

<div align="center">

*Amor Seal — a letter for every kind of time.*

</div>
