# sign_auth — Project Context

## What This Project Is

A Kotlin/Gradle project (`com.symbolscope.signauth`) that provides PGP utilities and a Ktor HTTP service. The service acts as a signed-message relay: it verifies incoming PGP-signed messages against a local GnuPG keyring, forwards the plaintext payload to a configurable upstream endpoint, and returns the upstream response signed and encrypted back to the original sender.

## Build & Test

```bash
./gradlew test          # run all tests (10 passing)
./gradlew compileKotlin # compile check
./gradlew run           # not yet configured — see Main.kt
```

All tests pass. Only pre-existing Bouncy Castle deprecation warnings remain (no errors).

## Key Files

| File | Purpose |
|------|---------|
| `src/main/kotlin/pgp/PGP.kt` | `KeyStore` interface, `PGP` class (high-level ops), `PGPUtils` object (low-level BC ops) |
| `src/main/kotlin/pgp/GnuPGKeyStore.kt` | `KeyStore` impl backed by local `gpg` binary |
| `src/main/kotlin/pgp/dataclasses.kt` | Domain data classes incl. `VerifiedDecryption`, `CleartextMessage` |
| `src/main/kotlin/pgp/Keyserver.kt` | HTTP keyserver client (keys.openpgp.org VKS API) |
| `src/main/kotlin/pgp/Serializer.kt` | Jackson-based JSON serializer |
| `src/main/kotlin/Main.kt` | Ktor CIO server (the runnable application) |
| `src/test/kotlin/pgp/PGPTest.kt` | Unit tests + `MemoryKeyStore` test double |
| `src/test/kotlin/pgp/TestData.kt` | Test keys and signatures (passphrase: `"i doubt that"`) |

## Architecture

### `KeyStore` interface (`PGP.kt`)
```
store(PGPPublicKey)   store(PGPSecretKey)
get(keyId: Long)      getSecret(keyId: Long)
getUser(userId)       getSecret(userId)   ← default: via getUser
userOwnsKey(userId, keyId)
```
Implementations: `MemoryKeyStore` (tests only, in PGPTest.kt), `GnuPGKeyStore` (production).

### `PGP` class — high-level, keystore-aware
- `isValid(SignedReource)` — detached signature verification
- `sign(Signable, passphrase)` — detached signature creation
- `encrypt(plaintext, recipientUserId)` — AES-256 + ZIP, armored
- `decrypt(armored, passphrase)` — auto-locates key via session packet
- `encryptAndSign(plaintext, recipientUserId, signerUserId, passphrase)` — one-pass signed+encrypted
- `decryptAndVerify(armored, passphrase)` → `VerifiedDecryption` — full pipeline

### `PGPUtils` object — low-level Bouncy Castle wrappers
All the above plus:
- `generate(id, passphrase, strength=2048)` → `PGPSecretKeyRing` — generates `RSA_GENERAL` keys (capable of both signing and encryption; key flags advertise all four capabilities)
- `findDecryptingKeyId(ciphertext)` — peeks at session key packets, returns key ID
- `parseCleartextSigned(armoredMessage)` → `CleartextMessage` — parses `-----BEGIN PGP SIGNED MESSAGE-----` blocks via `ArmoredInputStream`
- `verifyCleartext(message, publicKey)` — RFC 4880 §7 canonical verification (line-by-line with CRLF)
- `signPublicKey(toSign, secretKey, passphrase)` — key certification
- `userEmail(userId)` — extracts email from a PGP user ID string

### `GnuPGKeyStore`
Shells out to `gpg --batch --yes [--homedir <dir>] [extraArgs...]`.
- `store` → `gpg --import` (pipes armored key to stdin)
- `get` → `gpg --armor --export 0x<16-hex-keyid>`
- `getSecret` → `gpg --armor --export-secret-keys 0x<16-hex-keyid>` (exports still-encrypted; BC decrypts on use)
- `getUser` → `gpg --list-keys --with-colons` + `--list-secret-keys --with-colons`, parses colon-format output
- Key IDs are formatted as `"%016X".format(keyId)` (always 16 hex chars, handles negative Long)
- Stderr is drained on a daemon thread to prevent deadlock

### Ktor Service (`Main.kt`)

**Environment variables:**
| Var | Default | Description |
|-----|---------|-------------|
| `SERVER_KEY_USER_ID` | required | GnuPG user ID of server's key |
| `SERVER_KEY_PASSPHRASE` | `""` | Key passphrase (empty = unprotected) |
| `UPSTREAM_URL` | required | URL for `POST text/plain` forwarding |
| `GNUPG_HOMEDIR` | `~/.gnupg` | Override GPG homedir |
| `PORT` | `8080` | Listen port |

**Endpoints:**
- `GET /key` — returns server's ASCII-armored public key (`text/plain`)
- `POST /message` — accepts `text/plain` containing either:
  - `-----BEGIN PGP MESSAGE-----` (encrypted, optionally signed inside)
  - `-----BEGIN PGP SIGNED MESSAGE-----` (cleartext signed)

  Pipeline: decrypt if needed → verify signature → 404 if unknown/invalid signer → forward plaintext to upstream → sign+encrypt response to sender → return armored response.

**CIO disambiguation:** Both `ktor-client-cio` and `ktor-server-cio` export an object named `CIO`. Import with aliases:
```kotlin
import io.ktor.client.engine.cio.CIO as ClientCIO
import io.ktor.server.cio.CIO as ServerCIO
```

## Important Design Decisions

1. **`RSA_GENERAL` not `RSA_SIGN`** — `generate()` uses `PGPPublicKey.RSA_GENERAL` so the same key can both sign and encrypt. Bouncy Castle's `BcPublicKeyKeyEncryptionMethodGenerator` rejects `RSA_SIGN` keys at runtime. Key flags include `ENCRYPT_COMMS | ENCRYPT_STORAGE`.

2. **Single-key keyring assumption** — `MemoryKeyStore` and the Ktor service assume one primary key per user ID. The service picks `user.publicKeyIds.first()` as the encryption key.

3. **GnuPGKeyStore passphrase flow** — GPG exports secret key material still encrypted. BC's `extractPrivateKey(secretKey, passphrase)` decrypts it on use. The server passphrase is therefore provided at runtime, not at export time.

4. **No keyserver lookups** — The service never fetches new keys. `GnuPGKeyStore` has no keyserver integration; `Keyserver.kt` is a standalone client for other uses.

5. **Blocking I/O on `Dispatchers.IO`** — All `GnuPGKeyStore` calls (which shell out to `gpg`) are wrapped in `withContext(Dispatchers.IO)` in the Ktor route handlers.

6. **Cleartext canonicalization** — `verifyCleartext` feeds each line (trimmed of trailing whitespace) followed by `\r\n` to the signature verifier, matching RFC 4880 §7. The `CleartextMessage.body` property normalizes `\r\n → \n` for the upstream payload.

7. **`VerifiedDecryption.signatureValid`** is `false` both when the signing key is absent from the keyring AND when verification fails. The service treats both as 404.

## Known Limitations / Potential Next Steps

- **No `Runnable` Gradle task** — `Main.kt` has a `main()` but no `application` plugin is configured in `build.gradle.kts`. Add `id("application")` and `application { mainClass.set("com.symbolscope.signauth.MainKt") }` to run with `./gradlew run`.
- **Single primary key per user** — `GnuPGKeyStore` only tracks the primary secret key; subkeys are included in `publicKeyIds` but `onlineSecretKey` is always the primary. If a key ring has an encryption subkey separate from the signing key, `getSecret(userId)` returns the primary (signing) key, which may not be usable for decryption.
- **GPG agent dependency** — On GnuPG 2.x, `--export-secret-keys` may require the gpg-agent. For non-interactive environments, pass `extraArgs = listOf("--pinentry-mode", "loopback")` to `GnuPGKeyStore`.
- **No `application` plugin or fat-jar** — the project has no packaging task configured.
- **`@Deprecated` BC APIs** — `PGPPublicKey.RSA_SIGN/RSA_GENERAL`, `BcPGPKeyPair(Int, ...)`, `PGPSignatureGenerator(PGPContentSignerBuilder)`, and `PGPSignature.keyID` are all deprecated by newer BC APIs but still functional.

## Dependencies

```
bcpg-jdk18on:1.83           Bouncy Castle PGP
ktor:2.3.13                 Client (CIO) + Server (CIO, StatusPages)
jackson-module-kotlin:2.16.1
jackson-datatype-jsr310:2.16.1
kotlin-test-junit5, junit-jupiter-engine:5.8.1
```
