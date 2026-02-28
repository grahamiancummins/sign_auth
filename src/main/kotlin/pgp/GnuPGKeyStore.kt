package com.symbolscope.signauth.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * A [KeyStore] backed by the local GnuPG keyring, delegating to the `gpg` binary via
 * system calls. The [homedir] parameter overrides `--homedir` (defaults to the user's
 * standard `~/.gnupg` if null).
 *
 * Notes:
 * - Secret-key export (`getSecret`) exports the key material still encrypted; the
 *   caller must supply their passphrase when using the key (e.g. via [PGPUtils.extractPrivateKey]).
 * - On GnuPG 2.x the gpg-agent must be running for secret-key operations; pass
 *   `--pinentry-mode loopback` in [extraArgs] if you need non-interactive mode.
 */
class  GnuPGKeyStore(
    val homedir: String? = null,
    private val extraArgs: List<String> = emptyList()
) : KeyStore {

    // ── Process helpers ────────────────────────────────────────────────────

    private fun buildArgs(vararg args: String): List<String> = buildList {
        add("gpg")
        add("--batch")
        add("--yes")
        if (homedir != null) { add("--homedir"); add(homedir) }
        addAll(extraArgs)
        addAll(args)
    }

    private fun run(args: List<String>, stdin: ByteArray? = null): RunResult {
        val pb = ProcessBuilder(args)
        val process = pb.start()

        // Write stdin and close so gpg doesn't block waiting for more input.
        process.outputStream.use { if (stdin != null) it.write(stdin) }

        // Drain stderr on a background thread to prevent deadlock.
        val stderrBytes = mutableListOf<Byte>()
        val stderrThread = Thread {
            stderrBytes.addAll(process.errorStream.readBytes().toList())
        }.also { it.isDaemon = true; it.start() }

        val stdout = process.inputStream.readBytes().toString(Charsets.UTF_8)
        val exit = process.waitFor()
        stderrThread.join()

        return RunResult(exit, stdout, String(stderrBytes.toByteArray(), Charsets.UTF_8))
    }

    private data class RunResult(val exit: Int, val stdout: String, val stderr: String)

    // ── KeyStore implementation ─────────────────────────────────────────────

    override fun store(key: PGPPublicKey) {
        val baos = ByteArrayOutputStream()
        ArmoredOutputStream(baos).use { key.encode(it) }
        run(buildArgs("--import"), baos.toByteArray())
    }

    override fun store(key: PGPSecretKey) {
        val baos = ByteArrayOutputStream()
        ArmoredOutputStream(baos).use { key.encode(it) }
        run(buildArgs("--import"), baos.toByteArray())
    }

    override fun get(keyId: Long): PGPPublicKey? {
        val hex = "%016X".format(keyId)
        val result = run(buildArgs("--armor", "--export", "0x$hex"))
        if (!result.stdout.contains("BEGIN PGP")) return null
        val key = runCatching { PGPUtils.publicKeyFromArmoredString(result.stdout) }.getOrNull() ?: return null
        if (key.keyIdentifier.keyId != keyId) {
            throw Exception("Key lookup error")
        }
        return key
    }

    override fun getSecret(keyId: Long): PGPSecretKey? {
        val hex = "%016X".format(keyId)
        val result = run(buildArgs("--armor", "--export-secret-keys", "0x$hex"))
        if (!result.stdout.contains("BEGIN PGP")) return null
        val key = runCatching {
            val ins = PGPUtil.getDecoderStream(
                ByteArrayInputStream(result.stdout.toByteArray(Charsets.US_ASCII))
            )
            val ring = PGPSecretKeyRing(ins, PGPUtils.fingerprintCalculator)
            // Return the specific subkey if the requested ID belongs to one;
            // fall back to the primary key (e.g. when the subkey ID wasn't found).
            ring.getSecretKey(keyId) ?: ring.secretKey
        }.getOrNull() ?: return null
        if (key.keyIdentifier.keyId != keyId) {
            throw Exception("Key lookup error")
        }
        return key
    }

    override fun getUser(userId: String): User? {
        val pubResult = run(buildArgs("--list-keys", "--with-colons", userId))
        if (pubResult.exit != 0 || pubResult.stdout.isBlank()) return null

        val secResult = run(buildArgs("--list-secret-keys", "--with-colons", userId))

        return parseColonOutput(userId, pubResult.stdout, secResult.stdout)
    }

    // ── Colon-format parser ─────────────────────────────────────────────────

    /**
     * Parses `gpg --list-keys --with-colons` / `--list-secret-keys --with-colons` output
     * into a [User].
     *
     * Relevant record types:
     * - `pub` / `sub` — public primary key / subkey
     * - `sec` / `ssb` — secret primary key / subkey
     *
     * Field layout (0-indexed): `type:validity:bits:algo:keyid:created:expires:...`
     */
    private fun parseColonOutput(userId: String, pubOutput: String, secOutput: String): User? {
        fun keyIdsFrom(output: String): List<Long> =
            output.lines()
                .filter { it.startsWith("pub:") || it.startsWith("sub:") ||
                          it.startsWith("sec:") || it.startsWith("ssb:") }
                .mapNotNull { line ->
                    line.split(":").getOrNull(4)
                        ?.takeIf { it.isNotBlank() }
                        ?.toLongOrNull(16)
                }

        val publicKeyIds = keyIdsFrom(pubOutput).toSet()
        if (publicKeyIds.isEmpty()) return null

        val primarySecretKeyId = secOutput.lines()
            .firstOrNull { it.startsWith("sec:") }
            ?.split(":")?.getOrNull(4)
            ?.takeIf { it.isNotBlank() }
            ?.toLongOrNull(16)

        return User(userId, publicKeyIds, primarySecretKeyId)
    }
}
