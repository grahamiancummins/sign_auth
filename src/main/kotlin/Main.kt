package com.symbolscope.signauth

import com.symbolscope.signauth.pgp.*
import io.ktor.client.*
import io.ktor.client.engine.cio.CIO as ClientCIO
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.cio.CIO as ServerCIO
import io.ktor.server.engine.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Sign-auth service.
 *
 * Configuration via environment variables:
 *   SERVER_KEY_USER_ID   — user ID (e.g. "server@example.com") of the server's GnuPG key  [required]
 *   SERVER_KEY_PASSPHRASE— passphrase for that key (leave empty for unprotected keys)       [default: ""]
 *   UPSTREAM_URL         — URL to forward verified message payloads to via HTTP POST         [required]
 *   GNUPG_HOMEDIR        — override GnuPG home directory                                    [default: ~/.gnupg]
 *   PORT                 — TCP port to listen on                                             [default: 8080]
 *
 * Endpoints:
 *   GET  /key      — returns the server's ASCII-armored public key (text/plain)
 *   POST /message  — accepts an ASCII-armored signed message (text/plain), optionally
 *                    encrypted to the server's key.  Returns 404 if the signature cannot
 *                    be verified against a key already in the local GnuPG keyring.
 *                    On success, forwards the plaintext payload to UPSTREAM_URL and returns
 *                    the upstream response signed with the server key and encrypted to the
 *                    sender's key.
 */
fun main() {
    val serverKeyUserId = requireEnv("SERVER_KEY_USER_ID")
    val serverKeyPassphrase = System.getenv("SERVER_KEY_PASSPHRASE") ?: ""
    val upstreamUrl = requireEnv("UPSTREAM_URL")
    val gnupgHomedir = System.getenv("GNUPG_HOMEDIR")
    val port = System.getenv("PORT")?.toIntOrNull() ?: 8080

    val keyStore = GnuPGKeyStore(gnupgHomedir)
    val pgp = PGP(keyStore)
    val httpClient = HttpClient(ClientCIO)

    embeddedServer(ServerCIO, port = port) {
        install(StatusPages) {
            exception<Throwable> { call, cause ->
                call.application.log.error("Unhandled error", cause)
                call.respond(HttpStatusCode.InternalServerError)
            }
        }

        routing {
            get("/key") {
                val serverPublicKey = withContext(Dispatchers.IO) {
                    val user = keyStore.getUser(serverKeyUserId)
                        ?: error("Server key '$serverKeyUserId' not found in keyring")
                    keyStore.get(user.publicKeyIds.first())
                        ?: error("Server public key not found")
                }
                call.respondText(PGPUtils.publicKeyToArmoredString(serverPublicKey), ContentType.Text.Plain)
            }

            post("/message") {
                val armoredBody = call.receiveText()

                // ── Step 1: decrypt (if necessary) and verify signature ─────────────
                var wasEncrypted = false
                val decryption: VerifiedDecryption = when {
                    armoredBody.trimStart().startsWith("-----BEGIN PGP MESSAGE-----") -> {
                        wasEncrypted = true
                        // Encrypted (and possibly signed) message — delegate to PGP class.
                        // The server's secret key is located automatically by inspecting the
                        // session key packets in the message.
                        withContext(Dispatchers.IO) {
                            pgp.decryptAndVerify(armoredBody, serverKeyPassphrase)
                        }
                    }

                    armoredBody.trimStart().startsWith("-----BEGIN PGP SIGNED MESSAGE-----") -> {
                        // Cleartext signed message — parse, then look up the sender's key.
                        val msg = PGPUtils.parseCleartextSigned(armoredBody)
                        @Suppress("DEPRECATION")
                        val senderKey = withContext(Dispatchers.IO) { keyStore.get(msg.signature.keyID) }
                        val valid = senderKey != null && PGPUtils.verifyCleartext(msg, senderKey)
                        @Suppress("DEPRECATION")
                        VerifiedDecryption(msg.body, msg.signature.keyID, valid)
                    }

                    else -> {
                        call.respond(HttpStatusCode.BadRequest, "Unrecognized PGP message format")
                        return@post
                    }
                }

                // ── Step 2: reject unknown / invalid signers ────────────────────────
                if (!decryption.signatureValid) {
                    call.respond(HttpStatusCode.Forbidden, "Signature verification failed")
                    return@post
                }

                val senderKeyId = decryption.signedByKeyId!!   // non-null when signatureValid
                val senderPublicKey = withContext(Dispatchers.IO) { keyStore.get(senderKeyId) }
                if (senderPublicKey == null) {
                    call.respond(HttpStatusCode.NotFound)
                    return@post
                }

                // ── Step 3: forward plaintext payload to upstream ───────────────────
                val upstreamResponse = httpClient.post(upstreamUrl) {
                    contentType(ContentType.Text.Plain)
                    setBody(decryption.plaintext)
                }
                val upstreamText = upstreamResponse.bodyAsText()

                // ── Step 4: sign with server key, encrypt to sender if request was encrypted
                val serverSecretKey = withContext(Dispatchers.IO) {
                    keyStore.getSecret(serverKeyUserId)
                        ?: error("Server secret key '$serverKeyUserId' not found")
                }
                val armoredResponse = withContext(Dispatchers.IO) {
                    if (wasEncrypted)
                        PGPUtils.encryptAndSign(upstreamText, senderPublicKey, serverSecretKey, serverKeyPassphrase)
                    else
                        PGPUtils.cleartextSign(upstreamText, serverSecretKey, serverKeyPassphrase)
                }

                call.respondText(armoredResponse, ContentType.Text.Plain)
            }
        }
    }.start(wait = true)
}

private fun requireEnv(name: String): String =
    System.getenv(name) ?: error("Environment variable $name is required")
