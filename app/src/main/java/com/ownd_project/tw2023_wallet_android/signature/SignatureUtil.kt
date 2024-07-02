package com.ownd_project.tw2023_wallet_android.signature

import com.fasterxml.jackson.core.json.JsonWriteFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import okhttp3.OkHttpClient
import okhttp3.Request
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequenceGenerator
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extension.subjectAlternativeName
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.X509Certificate
import java.security.spec.ECFieldFp
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import java.util.Base64
import java.util.Date
import javax.security.auth.x500.X500Principal

interface ECPrivateJwk {
    val kty: String
    val crv: String
    val x: String
    val y: String
    val d: String
}

interface ECPublicJwk {
    val kty: String
    val crv: String
    val x: String
    val y: String
}

object SignatureUtil {
    init {
        // https://developer.android.com/about/versions/12/behavior-changes-all?hl=ja#bouncy-castle
        // androidがシステムレベルで登録するBCのセキュリティプロバイダが一部の実装を削除しているため、
        // 一度そのプロバイダーの登録を削除してからdependencyで追加したライブラリのプロバイダーを直接登録し直す
        Security.removeProvider("BC");
        Security.addProvider(BouncyCastleProvider())
    }

    fun derToRaw(derSig: ByteArray): ByteArray {
        val r = BigInteger(1, derSig.copyOfRange(4, 4 + derSig[3].toInt()))
        val s = BigInteger(
            1, derSig.copyOfRange(
                6 + derSig[3].toInt(),
                6 + derSig[3].toInt() + derSig[5 + derSig[3].toInt()].toInt()
            )
        )

        val rBytes =
            r.toByteArray().let { if (it.size > 32) it.copyOfRange(1, it.size) else it }
        val sBytes =
            s.toByteArray().let { if (it.size > 32) it.copyOfRange(1, it.size) else it }

        val rLength = rBytes.size
        val sLength = sBytes.size

        val raw = ByteArray(64)

        System.arraycopy(rBytes, 0, raw, 32 - rLength, rLength)
        System.arraycopy(sBytes, 0, raw, 64 - sLength, sLength)

        return raw
    }

    fun rawToDer(signatureBytes: ByteArray): ByteArray {
        val r = BigInteger(1, signatureBytes.copyOfRange(0, signatureBytes.size / 2))
        val s =
            BigInteger(1, signatureBytes.copyOfRange(signatureBytes.size / 2, signatureBytes.size))

        val rBytes = toFixedLengthBytes(r, 32)
        val sBytes = toFixedLengthBytes(s, 32)

        val bos = ByteArrayOutputStream()
        val seqGen = DERSequenceGenerator(bos)
        seqGen.addObject(DEROctetString(rBytes))
        seqGen.addObject(DEROctetString(sBytes))
//        seqGen.addObject(DEROctetString(r.toByteArray()))
//        seqGen.addObject(DEROctetString(s.toByteArray()))
        seqGen.close()

        return bos.toByteArray()
    }

    fun toFixedLengthBytes(value: BigInteger, length: Int): ByteArray {
        val valueBytes = value.toByteArray()
        if (valueBytes.size == length) {
            return valueBytes
        }

        val result = ByteArray(length)
        if (valueBytes.size > length) {
            // バイト配列が長すぎる場合、末尾のバイトをコピー
            System.arraycopy(valueBytes, valueBytes.size - length, result, 0, length)
        } else {
            // バイト配列が短すぎる場合、左側をゼロで埋める
            System.arraycopy(valueBytes, 0, result, length - valueBytes.size, valueBytes.size)
        }

        return result
    }

    fun generateECKeyPair(jwk: ECPrivateJwk): KeyPair {
        val curveParams = ECNamedCurveTable.getParameterSpec(jwk.crv)
        val ellipticCurve = EllipticCurve(
            ECFieldFp(curveParams.curve.field.characteristic),
            curveParams.curve.a.toBigInteger(),
            curveParams.curve.b.toBigInteger()
        )
        val g = curveParams.g.normalize()
        val ecPoint = ECPoint(
            g.affineXCoord.toBigInteger(),
            g.affineYCoord.toBigInteger()
        )
        val ecSpec = ECParameterSpec(
            ellipticCurve,
            ecPoint,
            curveParams.n,
            curveParams.h.intValueExact()
        )
        val point = curveParams.curve.createPoint(
            BigInteger(1, Base64.getUrlDecoder().decode(jwk.x)),
            BigInteger(1, Base64.getUrlDecoder().decode(jwk.y))
        ).normalize()

        val publicKeySpec = ECPublicKeySpec(
            ECPoint(point.affineXCoord.toBigInteger(), point.affineYCoord.toBigInteger()),
            ecSpec
        )
        val privateKeyValue = BigInteger(1, Base64.getUrlDecoder().decode(jwk.d))
        val privateKeySpec = ECPrivateKeySpec(privateKeyValue, ecSpec)

        val keyFactory = KeyFactory.getInstance("ECDSA", "BC")
        val publicKey = keyFactory.generatePublic(publicKeySpec)
        val privateKey = keyFactory.generatePrivate(privateKeySpec)

        return KeyPair(publicKey, privateKey)
    }

    fun generateCertificate(
        keyPair: KeyPair,
        signerKeyPair: KeyPair,
        isCa: Boolean,
        subjectAlternativeNames: List<String> = emptyList()
    ): X509Certificate {
        val now = Date()
        val notBefore = Date(now.time)
        val notAfter = Date(now.time + 365 * 24 * 60 * 60 * 1000L) // 1 year validity
        val subjectDN =
            X500Principal("CN=Example CA, O=Example Company, L=City, ST=State, C=Country")

        val serialNumber = BigInteger.valueOf(now.time) // unique serial number for each certificate
        val certBuilder = JcaX509v3CertificateBuilder(
            subjectDN,
            serialNumber,
            notBefore,
            notAfter,
            subjectDN,
            keyPair.public
        )
        // CAフラグを持つ基本制約の追加
        if (isCa) {
            certBuilder.addExtension(
                Extension.basicConstraints,
                true,
                BasicConstraints(true)
            )
        }

        if (subjectAlternativeNames.isNotEmpty()) {
            val generalNames = subjectAlternativeNames.map { GeneralName(GeneralName.dNSName, it) }
            val subjectAltName = GeneralNames(generalNames.toTypedArray())
            certBuilder.addExtension(
                subjectAlternativeName, false, subjectAltName
            )
        }

        // Signing the certificate using the private key
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(signerKeyPair.private)
        val holder = certBuilder.build(signer)

        // Converting to X509Certificate
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    fun generateSelfSignedCertificate(keyPair: KeyPair): X509Certificate {
        val now = Date()
        val notBefore = Date(now.time)
        val notAfter = Date(now.time + 365 * 24 * 60 * 60 * 1000L) // 1 year validity
        val subjectDN =
            X500Principal("CN=Example CA, O=Example Company, L=City, ST=State, C=Country")

        val serialNumber = BigInteger.valueOf(now.time) // unique serial number for each certificate
//        val publicKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.public.encoded)
        val certBuilder = JcaX509v3CertificateBuilder(
            subjectDN,
            serialNumber,
            notBefore,
            notAfter,
            subjectDN,
            keyPair.public
        )

        // Signing the certificate using the private key
        val signer = JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.private)
        val holder = certBuilder.build(signer)

        // Converting to X509Certificate
        return JcaX509CertificateConverter().getCertificate(holder)
    }

    fun certificateToPem(certificate: X509Certificate): String {
        val encodedCert = Base64.getEncoder().encodeToString(certificate.encoded)
        return "-----BEGIN CERTIFICATE-----\n$encodedCert\n-----END CERTIFICATE-----"
    }

    fun decodeBase64ToX509Certificate(encodedCert: String): X509Certificate? {
        val decodedCert = Base64.getDecoder().decode(encodedCert)
        return try {
            val certFactory = CertificateFactory.getInstance("X.509")
            val certInputStream = ByteArrayInputStream(decodedCert)
            certFactory.generateCertificate(certInputStream) as X509Certificate
        } catch (e: Exception) {
            e.printStackTrace()
            null
        }
    }

    fun getX509CertificatesFromUrl(url: String): Array<X509Certificate>? {
        // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.5
        val client = OkHttpClient()
        val request = Request.Builder().url(url).build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) throw IOException("Failed to download file: $response")

            val responseBody = response.body()?.string() ?: return null
            return convertPemWithDelimitersToX509Certificates(responseBody)
        }
    }
    fun convertPemWithDelimitersToX509Certificates(pem: String): Array<X509Certificate>? {
        val pemCertificates = pem.trim().split("-----END CERTIFICATE-----")
            .filter { it.contains("-----BEGIN CERTIFICATE-----") }
            .map { it.trim() + "\n-----END CERTIFICATE-----" }
        return convertPemToX509Certificates(pemCertificates)
    }

    fun convertPemToX509Certificates(pemCertificates: List<String>): Array<X509Certificate>? {
        val certificateFactory = CertificateFactory.getInstance("X.509")
        val certificates = mutableListOf<X509Certificate>()
        pemCertificates.forEach { certPem ->
            val certBytes = Base64.getMimeDecoder().decode(
                certPem.lineSequence()
                    .filterNot { it.startsWith("-----BEGIN CERTIFICATE-----") || it.startsWith("-----END CERTIFICATE-----") }
                    .joinToString(separator = "")
            )
            val certInputStream = ByteArrayInputStream(certBytes)
            val cert = certificateFactory.generateCertificate(certInputStream) as X509Certificate
            certificates.add(cert)
        }

        return certificates.toTypedArray()
    }

    fun validateCertificateChain(
        certificates: Array<X509Certificate>,
        rootCertificate: X509Certificate
    ): Boolean {
        try {
            // 証明書ファクトリのインスタンスを作成
            val certificateFactory = CertificateFactory.getInstance("X.509", "BC")

            // 証明書リストを証明書パスに変換
            val certPath = certificateFactory.generateCertPath(certificates.toList())

            // デフォルトのKeyStoreを使用して信頼されたルート証明書をロード
            val keyStore = KeyStore.getInstance(KeyStore.getDefaultType())
            keyStore.load(null, null)
            // todo テストコードの場合だけ実行する様に制御を入れる
            keyStore.setCertificateEntry("root", rootCertificate)

            // PKIXパラメータの設定（ルートCAの検証なし）
            val pkixParams = PKIXParameters(keyStore)
            pkixParams.isRevocationEnabled = false // CRLチェックを無効化

            // 証明書パスバリデータを使用して証明書チェーンの検証
            val pathValidator = CertPathValidator.getInstance("PKIX", "BC")
            val result = pathValidator.validate(certPath, pkixParams)
            println(result)

            return true
        } catch (e: Exception) {
            e.printStackTrace()
            return false
        }
    }
//    fun sign(privateKey: PrivateKey, header: Map<String, Any>, payload: Map<String, Any>): String {
//        // sign target
//        val objectMapper = jacksonObjectMapper()
//        val h = objectMapper.writeValueAsString(header).toByteArray().toBase64Url()
//        val p =
//            objectMapper.writeValueAsString(payload).toByteArray().toBase64Url()
//        val unsignedToken = "$h.$p"
//        val dataBytes = unsignedToken.toByteArray(Charsets.UTF_8)
//
//        val signature: ByteArray = Signature.getInstance(Constants.SIGNING_ALGORITHM).run {
//            initSign(privateKey)
//            update(dataBytes)
//            sign()
//        }
//        val signatureBase64url = derToRaw(signature).toBase64Url()
//        return "$unsignedToken.$signatureBase64url"
//    }
//    fun verifySignature(certificate: X509Certificate, data: ByteArray, signature: ByteArray): Boolean {
//        try {
//            val publicKey = certificate.publicKey
//
//            // 署名アルゴリズムを指定（証明書に基づいて適切なアルゴリズムを選択する必要があります）
//            val signatureInstance = Signature.getInstance("SHA256withECDSA")
//            // val signatureInstance = Signature.getInstance("SHA256withRSA")
//
//            signatureInstance.initVerify(publicKey)
//            signatureInstance.update(data)
//            return signatureInstance.verify(signature)
//        } catch (e: Exception) {
//            e.printStackTrace()
//        }
//        return false
//    }


    fun byte2Base64Url(b: ByteArray) = b.toBase64Url()

    fun int2Base64Url(i: BigInteger) = i.toBase64Url()
}

fun ByteArray.toBase64Url() = Base64.getUrlEncoder().encodeToString(this).trimEnd('=')
fun BigInteger.toBase64Url() =
    Base64.getUrlEncoder().encodeToString(this.toByteArray()).trimEnd('=')

