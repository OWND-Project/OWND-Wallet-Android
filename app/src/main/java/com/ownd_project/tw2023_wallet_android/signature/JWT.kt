package com.ownd_project.tw2023_wallet_android.signature

import arrow.core.Either
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import com.ownd_project.tw2023_wallet_android.signature.SignatureUtil.derToRaw
import com.ownd_project.tw2023_wallet_android.signature.SignatureUtil.validateCertificateChain
import com.ownd_project.tw2023_wallet_android.utils.Constants
import com.ownd_project.tw2023_wallet_android.utils.KeyPairUtil
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.ownd_project.tw2023_wallet_android.signature.SignatureUtil.convertPemToX509Certificates
import org.jose4j.jwk.HttpsJwks
import org.jose4j.jws.AlgorithmIdentifiers
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.util.Base64

class JWT {
    companion object {

        fun sign(keyAlias: String, header: Map<String, Any>, payload: Map<String, Any>): String {
            val privateKey = KeyPairUtil.getPrivateKey(keyAlias)
            // sign target
            val objectMapper = jacksonObjectMapper()
            val h =
                SignatureUtil.byte2Base64Url(objectMapper.writeValueAsString(header).toByteArray())
            val p =
                SignatureUtil.byte2Base64Url(objectMapper.writeValueAsString(payload).toByteArray())
            val unsignedToken = "$h.$p"
            val dataBytes = unsignedToken.toByteArray(Charsets.UTF_8)

            val signature: ByteArray = Signature.getInstance(Constants.SIGNING_ALGORITHM).run {
                initSign(privateKey)
                update(dataBytes)
                sign()
            }
            val signatureBase64url = SignatureUtil.byte2Base64Url(derToRaw(signature))
            return "$unsignedToken.$signatureBase64url"
        }

        fun signJwt(privateKey: PrivateKey, data: String): ByteArray {
            // todo 使い勝手があまり良くないので上のsignに寄せる
            val dataBytes = data.toByteArray(Charsets.UTF_8)
            val signature: ByteArray = Signature.getInstance(Constants.SIGNING_ALGORITHM).run {
                initSign(privateKey)
                update(dataBytes)
                sign()
            }

            return derToRaw(signature)
        }

        suspend fun verifyJwtWithJwks(jwt: String, jwksUrl: String): DecodedJWT {
            val decodedJwt = JWT.decode(jwt)
            val jwkSet = HttpsJwks(jwksUrl)
            val jwk = jwkSet.getJsonWebKeys().firstOrNull {
                it.keyId == decodedJwt.keyId
            } ?: throw IllegalArgumentException("適切なJWKが見つかりません。")

            val publicKey = jwk.publicKey

            val result = verifyJwt(jwt, publicKey)
            if (result.isRight()) {
                return (result as Either.Right).value
            } else {
                // todo 例外クラス変更(JWTVerificationExceptionはJWTライブラリのクラスなので一段階抽象的なクラスを用意する)
                throw JWTVerificationException((result as Either.Left).value)
            }
        }

        fun verifyJwt(jwt: String, publicKey: PublicKey): Either<String, DecodedJWT> { // todo 戻り値の型がauto0のライブラリの型で良いか検討する
            val decodedJwt = JWT.decode(jwt)
            val algorithm = when {
                publicKey is RSAPublicKey -> when (decodedJwt.algorithm) {
                    // RSA アルゴリズム
                    AlgorithmIdentifiers.RSA_USING_SHA256 -> Algorithm.RSA256(publicKey, null)
                    AlgorithmIdentifiers.RSA_USING_SHA384 -> Algorithm.RSA384(publicKey, null)
                    AlgorithmIdentifiers.RSA_USING_SHA512 -> Algorithm.RSA512(publicKey, null)
                    else -> throw UnsupportedOperationException("サポートされていないアルゴリズムです。")
                }

                publicKey is ECPublicKey -> when (decodedJwt.algorithm) {
                    // ECDSA アルゴリズム
                    AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256 -> Algorithm.ECDSA256(
                        publicKey,
                        null
                    )

                    AlgorithmIdentifiers.ECDSA_USING_P384_CURVE_AND_SHA384 -> Algorithm.ECDSA384(
                        publicKey,
                        null
                    )

                    AlgorithmIdentifiers.ECDSA_USING_P521_CURVE_AND_SHA512 -> Algorithm.ECDSA512(
                        publicKey,
                        null
                    )

                    else -> throw UnsupportedOperationException("サポートされていないアルゴリズムです。") // todo [プロジェクト完了後] ES256Kのモジュールに委譲する
                }

                else -> throw IllegalStateException("公開鍵の型がサポートされていません。")
            }

            val verifier = JWT.require(algorithm).build()
            return try {
                Either.Right(verifier.verify(decodedJwt))
            } catch (e: JWTVerificationException) {
                Either.Left(e.message ?: "JWTの検証に失敗しました")
            }
        }

        fun verifyJwtByX509(jwt: String): Result<Pair<DecodedJWT, Array<X509Certificate>>> {
            // https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.6
            // https://www.rfc-editor.org/rfc/rfc7515.html#appendix-B
            val decodedJwt = JWT.decode(jwt)
            val certs = decodedJwt.getHeaderClaim("x5c").asList(String::class.java)
            val certsUrl = decodedJwt.getHeaderClaim("x5u").asString()
            try {
                val certificates = if (!certs.isNullOrEmpty()) {
                    convertPemToX509Certificates(certs)
                } else if (certsUrl != null) {
                    SignatureUtil.getX509CertificatesFromUrl(certsUrl)
                } else {
                    null
                }

                if (certificates.isNullOrEmpty()) {
                    return Result.failure(Exception("証明書リストが取得できませんでした"))
                }
                val result = verifyJwt(jwt, certificates[0].publicKey)
                val isTestEnvironment =
                    System.getProperty("isTestEnvironment")?.toBoolean() ?: false
                val b = if (isTestEnvironment) {
                    validateCertificateChain(certificates, certificates.last())
                } else {
                    validateCertificateChain(certificates)
                }
                // todo row to der エンコーディングの変換ができずjava.security.Signatureを使った実装が未対応(ES256Kサポートのためには対応が必要)
                return if (result.isRight() && b) {
                    Result.success(Pair(decodedJwt, certificates))
                } else {
                    Result.failure(Exception("JWTの検証に失敗しました"))
                }
            } catch (e: IOException) {
                println(e)
                return Result.failure(Exception("JWTの検証に失敗しました"))
            }
        }

        fun verifyJwtByX5U(jwt: String): Either<String, DecodedJWT> {
            val decodedJwt = JWT.decode(jwt)
            val url = decodedJwt.getHeaderClaim("x5u").asString()
            try {
                val certificates = SignatureUtil.getX509CertificatesFromUrl(url)

                if (certificates.isNullOrEmpty()) {
                    return Either.Left("証明書リストが取得できませんでした")
                }
                val result = verifyJwt(jwt, certificates[0].publicKey)
                val isTestEnvironment =
                    System.getProperty("isTestEnvironment")?.toBoolean() ?: false
                val b = if (isTestEnvironment) {
                    validateCertificateChain(certificates, certificates.last())
                } else {
                    validateCertificateChain(certificates)
                }
                // todo row to der エンコーディングの変換ができずjava.security.Signatureを使った実装が未対応(ES256Kサポートのためには対応が必要)
//            // JWTのペイロードと署名部分を取得
//            val payload = decodedJwt.payload
//            val signature = decodedJwt.signature
//
//            // Base64デコードを行う
//            val payloadBytes = Base64.getUrlDecoder().decode(payload)
//            val signatureBytes = Base64.getUrlDecoder().decode(signature)
//
//            // 署名の検証
//            return SignatureUtil.verifySignature(certificates[0], payloadBytes, signatureBytes)
//            // return SignatureUtil.verifySignature(certificates[0], payloadBytes, sigBytesDer)
                return if (result.isRight() && b) {
                    Either.Right(decodedJwt)
                } else {
                    Either.Left("JWTの検証に失敗しました")
                }
            } catch (e: IOException) {
                println(e)
                return Either.Left("JWTの検証に失敗しました")
            }
        }

        fun decodeJwt(jwt: String): Triple<Map<String, Any>, Map<String, Any>, String> {
            val parts = jwt.split(".")
            if (parts.size == 3) {
                val headerJson = decodeBase64(parts[0])
                val payloadJson = decodeBase64(parts[1])
                val signature = parts[2]

                val headerMap = jsonToMap(headerJson)
                val payloadMap = jsonToMap(payloadJson)

                return Triple(headerMap, payloadMap, signature)
            } else {
                throw IllegalArgumentException("Invalid JWT format")
            }
        }

        private fun decodeBase64(data: String): String {
            val decodedBytes = Base64.getUrlDecoder().decode(data)
            return String(decodedBytes, StandardCharsets.UTF_8)
        }

        private fun jsonToMap(json: String): Map<String, Any> {
            val objectMapper = jacksonObjectMapper()
            return try {
                @Suppress("UNCHECKED_CAST") objectMapper.readValue(
                    json, Map::class.java
                ) as Map<String, Any>
            } catch (e: Exception) {
                throw IllegalArgumentException("Failed to parse JSON: $e")
            }
        }
    }
}