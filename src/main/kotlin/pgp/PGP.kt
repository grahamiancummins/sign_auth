package com.symbolscope.signauth.pgp

import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.BCPGOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PGPDigestCalculator
import org.bouncycastle.openpgp.operator.bc.*
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import java.io.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.lang.IllegalArgumentException
import java.math.BigInteger
import java.security.SecureRandom
import java.security.Security
import java.security.SignatureException
import java.util.*


/**
 * Consider https://codeberg.org/PGPainless/pgpainless to reduce Bouncy parameters
 */

interface KeyStore {
    fun store(key: PGPPublicKey)
    fun store(key: PGPSecretKey)
    fun get(keyId: Long): PGPPublicKey?
    fun getSecret(keyId: Long): PGPSecretKey?
    fun getUser(userId: String): User?

    fun getSecret(userId: String): PGPSecretKey? {
        val secId = getUser(userId)?.onlineSecretKey ?: return null
        return getSecret(secId)
    }

    fun userOwnsKey(userId: String, keyId: Long): Boolean =
        getUser(userId)?.publicKeyIds?.contains(keyId) == true
}

class PGP(val keyStore: KeyStore) {

    // ── Signing / verification ──────────────────────────────────────────────

    fun isValid(signed: SignedReource): Boolean {
        val sig = PGPUtils.readDetachedSignature(signed.signature)
        if (!keyStore.userOwnsKey(signed.content.signedBy, sig.keyID)) {
            return false
        }
        val key = keyStore.get(sig.keyID) ?: throw Exception("Key ${sig.keyID} not found")
        return PGPUtils.verify(sig, key, signed.content.write())
    }

    fun sign(content: Signable, passphrase: String): SignedReource {
        val key = keyStore.getSecret(content.signedBy) ?: throw Exception("no secret key found")
        return sign(content, key, passphrase)
    }

    fun sign(content: Signable, key: PGPSecretKey, passphrase: String): SignedReource {
        val sig = PGPUtils.sign(content.write(), key, passphrase)
        return SignedReource(content, PGPUtils.writeDetachedSignature(sig))
    }

    // ── Encryption / decryption ─────────────────────────────────────────────

    /**
     * Encrypt [plaintext] for [recipientUserId]. Returns an ASCII-armored PGP message.
     */
    fun encrypt(plaintext: String, recipientUserId: String): String {
        val user = keyStore.getUser(recipientUserId)
            ?: throw Exception("User $recipientUserId not found")
        val recipientKey = user.publicKeyIds.firstNotNullOfOrNull { keyStore.get(it) }
            ?: throw Exception("No public key found for $recipientUserId")
        return PGPUtils.encrypt(plaintext, recipientKey)
    }

    /**
     * Decrypt an ASCII-armored PGP message using the matching secret key found in the keystore.
     */
    fun decrypt(armored: String, passphrase: String): String {
        val keyId = PGPUtils.findDecryptingKeyId(armored)
            ?: throw Exception("No recipient key ID found in message")
        val secretKey = keyStore.getSecret(keyId)
            ?: throw Exception("No secret key for key ID $keyId in keystore")
        return PGPUtils.decrypt(armored, secretKey, passphrase)
    }

    /**
     * Encrypt [plaintext] for [recipientUserId], signing it as [signerUserId].
     * Returns an ASCII-armored, signed+encrypted PGP message block.
     */
    fun encryptAndSign(
        plaintext: String,
        recipientUserId: String,
        signerUserId: String,
        passphrase: String
    ): String {
        val recipientUser = keyStore.getUser(recipientUserId)
            ?: throw Exception("Recipient $recipientUserId not found")
        val recipientKey = recipientUser.publicKeyIds.firstNotNullOfOrNull { keyStore.get(it) }
            ?: throw Exception("No public key found for $recipientUserId")
        val signerKey = keyStore.getSecret(signerUserId)
            ?: throw Exception("No secret key for signer $signerUserId")
        return PGPUtils.encryptAndSign(plaintext, recipientKey, signerKey, passphrase)
    }

    /**
     * Decrypt and verify a signed+encrypted ASCII-armored PGP message block.
     * The matching secret key is located automatically from the keystore.
     */
    fun decryptAndVerify(armored: String, passphrase: String): VerifiedDecryption {
        val keyId = PGPUtils.findDecryptingKeyId(armored)
            ?: throw Exception("No recipient key ID found in message")
        val secretKey = keyStore.getSecret(keyId)
            ?: throw Exception("No secret key for key ID $keyId in keystore")
        return PGPUtils.decryptAndVerify(armored, secretKey, passphrase) { sigKeyId ->
            keyStore.get(sigKeyId)
        }
    }
}

object PGPUtils {
    val fingerprintCalculator = BcKeyFingerprintCalculator()
    val digestCalculator: PGPDigestCalculator = BcPGPDigestCalculatorProvider().get(PGPUtil.SHA1)
    val keyEncryptorBuilder = BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, digestCalculator)
    val signatureHashGen = PGPSignatureSubpacketGenerator().also {
        it.setKeyFlags(false, KeyFlags.SIGN_DATA or KeyFlags.CERTIFY_OTHER or
                              KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        it.setPreferredHashAlgorithms(false, intArrayOf(HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA1))
        it.setPreferredSymmetricAlgorithms(false, intArrayOf(SymmetricKeyAlgorithmTags.AES_256))
    }
    val random = SecureRandom()

    init {
        Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
    }

    const val emailRegexString = "[a-zA-Z0-9+._%\\-]{1,256}" +
            "@" +
            "[a-zA-Z0-9][a-zA-Z0-9\\-]{0,64}" +
            "(" +
            "\\." +
            "[a-zA-Z0-9][a-zA-Z0-9\\-]{0,25}" +
            ")+"


    val emailRegex = Regex(emailRegexString)
    val emailInIdRegex = Regex("<($emailRegexString)>\$")

    fun generate(
        id: String,
        passphrase: String,
        strength: Int = 2048
    ): PGPSecretKeyRing {
        val kpGen =  RSAKeyPairGenerator()
        kpGen.init(
            RSAKeyGenerationParameters(
                BigInteger.valueOf(0x10001),
                random, strength, 12
            )
        )
        val signKey: PGPKeyPair = BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpGen.generateKeyPair(), Date())

        val keyRingGen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            signKey,
            id,
            digestCalculator,
            signatureHashGen.generate(),
            null,
            BcPGPContentSignerBuilder(signKey.publicKey.algorithm, HashAlgorithmTags.SHA1),
            keyEncryptorBuilder.build(passphrase.toCharArray())
        )
        return keyRingGen.generateSecretKeyRing()
    }

    fun readDetachedSignature(sig: String): PGPSignature {
        val pgpObject = PGPUtil.getDecoderStream(ByteArrayInputStream(sig.toByteArray(Charsets.US_ASCII)))
            .use { inputStream ->
                PGPObjectFactory(inputStream, fingerprintCalculator).asSequence().firstOrNull() ?:
                throw SignatureException("Could not find signature")
            }
        return when (pgpObject) {
            is PGPSignature -> pgpObject
            is PGPSignatureList -> pgpObject.firstOrNull() ?: throw SignatureException("Could not find signature")
            else -> throw SignatureException("Could not find signature")
        }
    }

    fun writeDetachedSignature(sig: PGPSignature): String {
        val baos = ByteArrayOutputStream()
        val asc = ArmoredOutputStream(baos)
        sig.encode(asc)
        asc.close()
        return baos.toString(Charsets.US_ASCII)
    }

    fun verify(pgpSignature: PGPSignature, publicKey: PGPPublicKey, content: String): Boolean {
        pgpSignature.init(BcPGPContentVerifierBuilderProvider(), publicKey)
        DataInputStream(ByteArrayInputStream(content.toByteArray(Charsets.UTF_8))).use {
            pgpSignature.update(it.readAllBytes())
        }
        return pgpSignature.verify()
    }

    fun publicKeyFromArmoredString(key: String): PGPPublicKey {
        val ins = PGPUtil.getDecoderStream(ByteArrayInputStream(key.toByteArray(Charsets.US_ASCII)))
        val pgpPub = PGPPublicKeyRing(ins, fingerprintCalculator)
        return pgpPub.publicKey
    }

    fun publicKeyToArmoredString(key: PGPPublicKey): String {
        val baos = ByteArrayOutputStream()
        val out = ArmoredOutputStream(baos)
        key.encode(out)
        out.close()
        return String(baos.toByteArray(), Charsets.US_ASCII)
    }

    fun secretKeyFromArmoredString(key: String): PGPSecretKey {
        val ins = PGPUtil.getDecoderStream(ByteArrayInputStream(key.toByteArray(Charsets.US_ASCII)))
        val pgpSec = PGPSecretKeyRing(ins, fingerprintCalculator)
        return pgpSec.secretKey
    }

    fun secretKeyToArmoredString(key: PGPSecretKeyRing): String {
        val baos = ByteArrayOutputStream()
        val out = ArmoredOutputStream(baos)
        key.encode(out)
        out.close()
        return String(baos.toByteArray(), Charsets.US_ASCII)
    }

    fun extractPrivateKey(secretKey: PGPSecretKey, passphrase: String): PGPPrivateKey {
        val decryptor = JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(passphrase.toCharArray())
        return secretKey.extractPrivateKey(decryptor)
    }

    fun sigGenerator(secretKey: PGPSecretKey): PGPSignatureGenerator = PGPSignatureGenerator(
        BcPGPContentSignerBuilder(secretKey.publicKey.algorithm, PGPUtil.SHA256)
    )

    fun sign(content: String, secretKey: PGPSecretKey, passphrase: String): PGPSignature {
        val privateKey = extractPrivateKey(secretKey, passphrase)
        val signatureGenerator = sigGenerator(secretKey)
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey)
        signatureGenerator.update(content.toByteArray(Charsets.UTF_8))
        return signatureGenerator.generate()
    }

    fun signPublicKey(toSign: PGPPublicKey, secretKey: PGPSecretKey, passphrase: String): PGPPublicKey {
        val privateKey = extractPrivateKey(secretKey, passphrase)
        val signatureGenerator = sigGenerator(secretKey)
        signatureGenerator.init(PGPSignature.DEFAULT_CERTIFICATION, privateKey)
        val id = toSign.getUserIDs().asSequence().firstOrNull() ?: throw Exception("No ID on target key")
        val signature = signatureGenerator.generateCertification(id, toSign)
        return PGPPublicKey.addCertification(toSign, id, signature)
    }

    fun userEmail(userId: String): String {
        val stdId = emailInIdRegex.find(userId)
        if (stdId != null) {
            return stdId.groups[1]!!.value
        }

        val bareEmail = emailRegex.matchEntire(userId)
        if (bareEmail != null) {
            return userId
        }
        throw IllegalArgumentException("No email")
    }

    // ── Encryption ──────────────────────────────────────────────────────────

    /**
     * Encrypt [plaintext] for [recipientKey]. Returns an ASCII-armored PGP message.
     */
    fun encrypt(plaintext: String, recipientKey: PGPPublicKey): String {
        val plainBytes = plaintext.toByteArray(Charsets.UTF_8)
        val baos = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(baos)

        val encGen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(random)
        )
        encGen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(recipientKey))

        val encOut = encGen.open(armoredOut, ByteArray(1 shl 16))
        val compGen = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
        val compOut = compGen.open(encOut)

        PGPLiteralDataGenerator()
            .open(compOut, PGPLiteralData.BINARY, "", plainBytes.size.toLong(), Date())
            .use { it.write(plainBytes) }

        compOut.close()
        encOut.close()
        armoredOut.close()

        return baos.toString(Charsets.US_ASCII)
    }

    /**
     * Encrypt [plaintext] for [recipientKey] and sign it with [signingKey].
     * Returns an ASCII-armored, signed+encrypted PGP message block.
     */
    fun encryptAndSign(
        plaintext: String,
        recipientKey: PGPPublicKey,
        signingKey: PGPSecretKey,
        passphrase: String
    ): String {
        val privateKey = extractPrivateKey(signingKey, passphrase)
        val plainBytes = plaintext.toByteArray(Charsets.UTF_8)
        val baos = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(baos)

        val encGen = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(random)
        )
        encGen.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(recipientKey))

        val encOut = encGen.open(armoredOut, ByteArray(1 shl 16))
        val compGen = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
        val compOut = compGen.open(encOut)

        val sigGen = sigGenerator(signingKey)
        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)
        sigGen.generateOnePassVersion(false).encode(compOut)

        PGPLiteralDataGenerator()
            .open(compOut, PGPLiteralData.BINARY, "", plainBytes.size.toLong(), Date())
            .use { litOut ->
                litOut.write(plainBytes)
                sigGen.update(plainBytes)
            }

        sigGen.generate().encode(compOut)
        compOut.close()
        encOut.close()
        armoredOut.close()

        return baos.toString(Charsets.US_ASCII)
    }

    /**
     * Sign [plaintext] with [secretKey] and return an ASCII-armored
     * `-----BEGIN PGP SIGNED MESSAGE-----` cleartext-signed block.
     * The signature is computed with canonical CRLF line endings (RFC 4880 §7),
     * matching the verification done in [verifyCleartext].
     */
    fun cleartextSign(plaintext: String, secretKey: PGPSecretKey, passphrase: String): String {
        val privateKey = extractPrivateKey(secretKey, passphrase)
        val sigGen = sigGenerator(secretKey)
        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey)

        val baos = ByteArrayOutputStream()
        val armoredOut = ArmoredOutputStream(baos)
        armoredOut.beginClearText(HashAlgorithmTags.SHA256)

        val crlf = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())
        val lines = BufferedReader(StringReader(plaintext)).readLines()
        lines.forEachIndexed { index, line ->
            val lineBytes = line.trimEnd().toByteArray(Charsets.UTF_8)
            armoredOut.write(lineBytes)
            if (index < lines.size - 1) armoredOut.write(crlf)
            sigGen.update(lineBytes)
            sigGen.update(crlf)
        }

        armoredOut.endClearText()
        val bcOut = BCPGOutputStream(armoredOut)
        sigGen.generate().encode(bcOut)
        bcOut.close()
        armoredOut.close()

        return baos.toString(Charsets.US_ASCII)
    }

    // ── Cleartext signed messages ───────────────────────────────────────────

    /**
     * A parsed `-----BEGIN PGP SIGNED MESSAGE-----` block.
     *
     * [bodyBytes] are the bytes read directly from [ArmoredInputStream] during the
     * cleartext phase — these are already canonicalized (trailing whitespace stripped
     * per line) and are used only for forwarding the payload.  Signature verification
     * is performed line-by-line with canonical CRLF endings as required by RFC 4880.
     */
    data class CleartextMessage(val bodyBytes: ByteArray, val signature: PGPSignature) {
        /** Plaintext body with Unix line endings, suitable for forwarding. */
        val body: String get() = bodyBytes.toString(Charsets.UTF_8).replace("\r\n", "\n")
    }

    /**
     * Parse a `-----BEGIN PGP SIGNED MESSAGE-----` armored block into its
     * body and embedded signature.
     */
    fun parseCleartextSigned(armoredMessage: String): CleartextMessage {
        val ain = ArmoredInputStream(
            ByteArrayInputStream(armoredMessage.toByteArray(Charsets.UTF_8))
        )
        require(ain.isClearText) { "Not a cleartext signed message" }

        val bodyOut = ByteArrayOutputStream()
        var ch: Int
        while (ain.read().also { ch = it } >= 0 && ain.isClearText) {
            bodyOut.write(ch)
        }

        val sigs = PGPObjectFactory(ain, fingerprintCalculator).nextObject() as? PGPSignatureList
            ?: throw Exception("No signature found in cleartext message")

        return CleartextMessage(bodyOut.toByteArray(), sigs[0])
    }

    /**
     * Verify the signature on a parsed cleartext message.
     * Feeds each line with canonical CRLF endings (RFC 4880 §7) to the signature verifier.
     */
    fun verifyCleartext(message: CleartextMessage, publicKey: PGPPublicKey): Boolean {
        message.signature.init(BcPGPContentVerifierBuilderProvider(), publicKey)
        val crlf = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte())
        BufferedReader(InputStreamReader(ByteArrayInputStream(message.bodyBytes), Charsets.UTF_8))
            .use { reader ->
                var line: String?
                while (reader.readLine().also { line = it } != null) {
                    message.signature.update(line!!.trimEnd().toByteArray(Charsets.UTF_8))
                    message.signature.update(crlf)
                }
            }
        return message.signature.verify()
    }

    // ── Decryption ──────────────────────────────────────────────────────────

    /**
     * Returns the key ID of the first public-key-encrypted session key in [ciphertext],
     * or null if the message contains no public-key-encrypted data.
     */
    fun findDecryptingKeyId(ciphertext: String): Long? {
        val pgpStream = PGPUtil.getDecoderStream(
            ByteArrayInputStream(ciphertext.toByteArray(Charsets.US_ASCII))
        )
        val factory = PGPObjectFactory(pgpStream, fingerprintCalculator)
        var obj = factory.nextObject()
        if (obj !is PGPEncryptedDataList) obj = factory.nextObject()
        val encDataList = obj as? PGPEncryptedDataList ?: return null
        return encDataList.encryptedDataObjects.asSequence()
            .filterIsInstance<PGPPublicKeyEncryptedData>()
            .map { it.keyID }
            .firstOrNull()
    }

    /**
     * Decrypt an ASCII-armored PGP message using [secretKey].
     * Any embedded signature packets are ignored; use [decryptAndVerify] to also verify.
     */
    fun decrypt(ciphertext: String, secretKey: PGPSecretKey, passphrase: String): String {
        val privateKey = extractPrivateKey(secretKey, passphrase)
        val pgpStream = PGPUtil.getDecoderStream(
            ByteArrayInputStream(ciphertext.toByteArray(Charsets.US_ASCII))
        )
        var factory = PGPObjectFactory(pgpStream, fingerprintCalculator)

        var obj = factory.nextObject()
        if (obj !is PGPEncryptedDataList) obj = factory.nextObject()
        val encDataList = obj as? PGPEncryptedDataList
            ?: throw Exception("No encrypted data found")

        val pbe = encDataList.encryptedDataObjects.asSequence()
            .filterIsInstance<PGPPublicKeyEncryptedData>()
            .find { it.keyID == secretKey.keyID }
            ?: throw Exception("Message not encrypted for key ${secretKey.keyID}")

        val clearStream = pbe.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
        factory = PGPObjectFactory(clearStream, fingerprintCalculator)

        var next = factory.nextObject()
        if (next is PGPCompressedData) {
            factory = PGPObjectFactory(next.dataStream, fingerprintCalculator)
            next = factory.nextObject()
        }
        if (next is PGPOnePassSignatureList) {
            next = factory.nextObject()
        }

        val literalData = next as? PGPLiteralData
            ?: throw Exception("Expected literal data, got ${next?.javaClass?.name}")
        return literalData.inputStream.readBytes().toString(Charsets.UTF_8)
    }

    /**
     * Decrypt and verify a signed+encrypted ASCII-armored PGP message block.
     *
     * [publicKeyLookup] is called with the signer's key ID and should return the
     * corresponding public key, or null if it is not available (in which case
     * [VerifiedDecryption.signatureValid] will be false).
     */
    fun decryptAndVerify(
        ciphertext: String,
        secretKey: PGPSecretKey,
        passphrase: String,
        publicKeyLookup: (Long) -> PGPPublicKey?
    ): VerifiedDecryption {
        val privateKey = extractPrivateKey(secretKey, passphrase)
        val pgpStream = PGPUtil.getDecoderStream(
            ByteArrayInputStream(ciphertext.toByteArray(Charsets.US_ASCII))
        )
        var factory = PGPObjectFactory(pgpStream, fingerprintCalculator)

        var obj = factory.nextObject()
        if (obj !is PGPEncryptedDataList) obj = factory.nextObject()
        val encDataList = obj as? PGPEncryptedDataList
            ?: throw Exception("No encrypted data found")

        val pbe = encDataList.encryptedDataObjects.asSequence()
            .filterIsInstance<PGPPublicKeyEncryptedData>()
            .find { it.keyID == secretKey.keyID }
            ?: throw Exception("Message not encrypted for key ${secretKey.keyID}")

        val clearStream = pbe.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
        factory = PGPObjectFactory(clearStream, fingerprintCalculator)

        var next = factory.nextObject()
        if (next is PGPCompressedData) {
            factory = PGPObjectFactory(next.dataStream, fingerprintCalculator)
            next = factory.nextObject()
        }

        var onePassSig: PGPOnePassSignature? = null
        var signedByKeyId: Long? = null

        if (next is PGPOnePassSignatureList) {
            val ops = next[0]
            signedByKeyId = ops.keyID
            val sigPubKey = publicKeyLookup(signedByKeyId)
            if (sigPubKey != null) {
                ops.init(BcPGPContentVerifierBuilderProvider(), sigPubKey)
                onePassSig = ops
            }
            next = factory.nextObject()
        }

        val literalData = next as? PGPLiteralData
            ?: throw Exception("Expected literal data, got ${next?.javaClass?.name}")
        val plainBytes = literalData.inputStream.readBytes()
        onePassSig?.update(plainBytes)

        var sigValid = false
        val afterData = factory.nextObject()
        if (afterData is PGPSignatureList && onePassSig != null) {
            sigValid = onePassSig.verify(afterData[0])
        }

        return VerifiedDecryption(plainBytes.toString(Charsets.UTF_8), signedByKeyId, sigValid)
    }
}
