# Identity PQ primitives (`src/identity/`)

Byte-level primitives for moving an identity's `accountPublicKey` and portal keys onto the
X-Wing KEM from `src/pq/`. Every consumer must compute these bytes identically, so the logic
lives in this package and nowhere else.

## Scope

**In:** the identity public-key blob codec; identity PQ seed derivation; portal PQ seed
derivation; the onchain checksum helper; pinned test vectors.

**Out:** rotation orchestration, recovery shard formats, keystore re-encryption, anything
app-side. This module is pure functions over bytes: no storage, no network, no chain.

## Module layout

```
src/identity/
  config.ts     tags + labels (frozen constants)
  codec.ts      accountPublicKey encode/decode
  derive.ts     seed derivations + checksum
  index.ts      barrel
  __tests__/    vectors.test.ts, codec.test.ts, derive.test.ts
```

Exported as the `./identity` subpath (same pattern as `./pq`); the root barrel re-exports by name.

## config.ts: frozen constants

```ts
// Tag prefixed to the PQ-format accountPublicKey onchain blob. ASCII, 7 bytes.
// Cannot be confused with the legacy format: RSA SPKI DER always begins 0x30 0x82.
export const IDENTITY_PQ_TAG = "FVPQID1";

// HKDF domain-separation labels. Siblings of the existing
// 'MASTER_KEY' / 'SIGNING_KEY' / 'AGENT_KEY' labels, same unversioned style
// (versioning lives in the blob tag).
export const HKDF_INFO_IDENTITY_PQ = "PQ_IDENTITY_KEY";
export const HKDF_INFO_PORTAL_PQ   = "PQ_PORTAL_KEY";

export const XWING_PUBLIC_KEY_LEN = 1216;
export const SEED_LEN = 32;

// Input-shape pins for the strict validators in derive.ts:
// ag2Hash = base64 of a 32-byte argon2id hash;
// ownerSecret = base64pad export of the portal's 64-byte ed25519 secret.
export const AG2_HASH_DECODED_LEN = 32;
export const OWNER_SECRET_DECODED_LEN = 64;
```

## codec.ts: the accountPublicKey blob

Only the **public** key changes format. `accountPrivateKey` stays byte-for-byte untouched, so
the codec deliberately has no private-key container.

```ts
// [ "FVPQID1" (7B) | X-Wing public key (1216B) ], total exactly 1223 bytes.
export const encodeIdentityPublicKey: (xwingPublicKey: Uint8Array) => Uint8Array;

export type DecodedIdentityPublicKey =
  | { format: "pq";  publicKey: Uint8Array }   // tag present, length exactly 1223
  | { format: "rsa"; spki: Uint8Array };       // begins 0x30, legacy SPKI DER

export const decodeIdentityPublicKey: (bytes: Uint8Array) => DecodedIdentityPublicKey;
```

Strictness (same validator discipline as `src/pq/`):

- Tag present but length ≠ 7+1216 → throw (no truncated or padded blobs).
- No tag and first byte ≠ 0x30 → throw (an unknown format is an error, never a guess).
- Decode is total: every valid legacy blob and every valid PQ blob has exactly one parse.
- `IDENTITY_PQ_TAG` carries a version digit; a future format takes `FVPQID2`.

## derive.ts: seeds and checksum

### Identity seed: byte-matches the existing derivation family

Login keys are derived as `hkdf-sha256(ikm, salt, info, 32)` (via `futoin-hkdf` in the app), where:

> ⚠ **The IKM is the UTF-8 bytes of the base64 `ag2Hash` STRING** (`Buffer.from(ag2Hash)`),
> **not** the decoded hash bytes. A clean-room implementation that base64-decodes first derives
> a *different key* and bricks the account. The cross-implementation vector enforces this.

```ts
// hkdf-sha256( ikm = utf8(ag2HashBase64), salt, info = "PQ_IDENTITY_KEY", len = 32 )
export const deriveIdentityPqSeed: (ag2Hash: string, salt: Uint8Array) => Uint8Array;

// deriveIdentityPqSeed → generatePqKeyPair(seed)  (deterministic, KAT-tested)
export const deriveIdentityPqKeyPair: (ag2Hash: string, salt: Uint8Array) => Promise<PqKeyPairBytes>;
```

The seed is a **sibling** of `masterKey` (same ikm/salt, different info), not derived *from*
`masterKey`, which is an unexportable WebCrypto AES key.

### Portal seed: new derivation, no legacy to match

Root: the portal's `ownerSecret` (exported ed25519 UCAN secret, base64pad, decodes to 64 bytes,
per-portal, owner-held). IKM is the **decoded bytes**, salt is **the portal address** (an
`ownerSecret` duplicated across portals by clone, backup-restore or migration still derives
distinct keys), info is the label.

```ts
// hkdf-sha256( ikm = base64decode(ownerSecret),
//              salt = utf8(lowercase(portalAddress)),
//              info = "PQ_PORTAL_KEY", len = 32 )
export const derivePortalPqSeed: (ownerSecretBase64: string, portalAddress: string) => Uint8Array;
```

⚠ The salt is the **lowercased** address string's UTF-8 bytes. EVM addresses circulate in
checksummed and lowercase forms; without normalization the same portal would derive different
keys per casing. The pinned vector uses a mixed-case address to enforce this.

### Input validation: garbage must throw, never derive

`js-base64.toUint8Array` never throws, so without validation an empty or malformed input would
silently derive a fixed, publicly computable key. Both derive functions therefore validate:

- Base64 inputs decode **strictly**: standard alphabet, padded, round-trips byte-identically,
  and decodes to the pinned length (`ag2Hash` → 32, `ownerSecret` → 64). Validation only: the
  identity IKM remains the *string* bytes.
- `portalAddress` must match `/^0x[0-9a-fA-F]{40}$/`.
- Identity `salt` must be non-empty, but its length is deliberately **not** pinned: salts are
  created at 24 bytes, but the chain read-back path does not guarantee a fixed width, and
  rejecting a real stored salt would orphan the account.

### Checksum: the derivation-drift guard

```ts
// True iff the derived public key matches the onchain blob. A mismatch means STOP:
// derivation drift or a non-deterministic wallet. Decrypt nothing.
export const matchesOnchainIdentityKey: (
  derivedPublicKey: Uint8Array,
  onchainAccountPublicKey: Uint8Array
) => boolean;
```

`decodeIdentityPublicKey` stays strict; `matchesOnchainIdentityKey` catches its throw and
returns `false`. It also serves as rotation detection: `decode(...).format === "rsa"` means not
rotated.

## Test vectors and tests

1. **Cross-implementation vector:** fixed `ag2Hash` + `salt` → expected 32-byte seed, where the
   expected bytes come from `futoin-hkdf` with the app's exact call shape, not from this
   library. The `MASTER_KEY`-label output for the same inputs is asserted too, proving
   equivalence for the whole derivation family, not just the new label.
2. **Chained vector:** that seed → `generatePqKeyPair` → expected public key (chains onto the
   `src/pq/` KATs).
3. **Codec:** round-trips; rejects truncated/oversized tagged blobs; classifies a real SPKI
   sample as `rsa`; throws on garbage.
4. **Freeze tests:** literal assertions on `IDENTITY_PQ_TAG`, both info labels, and lengths, so
   renaming any frozen constant turns CI red.

`npm run capture:vectors` (`scripts/capture-vectors.mjs`) recomputes every pinned value with
`futoin-hkdf` and Node's `crypto.hkdfSync` and fails on any mismatch. The vector test alone
cannot falsify the string-IKM assumption (both HKDFs are correct RFC 5869); only a recompute
with the app's own library can.

## Frozen invariants

| Invariant | Value | Where used |
|---|---|---|
| Sign-in message text | unchanged from the app | signature → ag2Hash |
| Argon2id parameters | unchanged from the app | ag2Hash |
| HKDF family | SHA-256, 32-byte output | all derived keys |
| IKM convention (identity family) | UTF-8 bytes of base64 `ag2Hash` string | all identity-family labels |
| Labels | `MASTER_KEY`, `SIGNING_KEY`, `AGENT_KEY`, `PQ_IDENTITY_KEY` | domain separation |
| Portal IKM convention | decoded `ownerSecret` bytes (64), salt = utf8(lowercase(portalAddress)), `PQ_PORTAL_KEY` | portal seeds |
| Blob tag | `FVPQID1` (7 ASCII bytes) | accountPublicKey format |
