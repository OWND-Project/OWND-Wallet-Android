package com.ownd_project.tw2023_wallet_android

import com.auth0.jwt.JWT
import com.auth0.jwt.JWTCreator
import com.auth0.jwt.algorithms.Algorithm
import com.ownd_project.tw2023_wallet_android.signature.SignatureUtil
import com.ownd_project.tw2023_wallet_android.utils.generateEcKeyPair
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.ownd_project.tw2023_wallet_android.oid.hasSubjectAlternativeName
import com.ownd_project.tw2023_wallet_android.signature.JWT.Companion.verifyJwtByX5C
import com.ownd_project.tw2023_wallet_android.signature.JWT.Companion.verifyJwtByX5U
import com.ownd_project.tw2023_wallet_android.signature.JWT.Companion.verifyJwtWithX509Certs
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.util.Base64
import java.util.Date

class CredentialVerifierTest {
    private lateinit var wireMockServer: WireMockServer
    private val keyPairTestCA = generateEcKeyPair()
    private val keyPairTestIssuer = generateEcKeyPair()

    @Before
    fun setup() {
        System.setProperty("isTestEnvironment", "true")

        wireMockServer = WireMockServer().apply {
            start()
            WireMock.configureFor("localhost", port())
        }
    }

    @After
    fun teardown() {
        System.clearProperty("isTestEnvironment")

        wireMockServer.stop()
    }

    @Test
    fun testGetX509CertificatesFromUrl() {
        val cert = SignatureUtil.generateSelfSignedCertificate(keyPairTestIssuer)
        val pem = SignatureUtil.certificateToPem(cert)
        wireMockServer.stubFor(
            WireMock.get(WireMock.urlEqualTo("/test-certificate"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withBody(pem)
                        .withHeader("Content-Type", "application/x-pem-file")
                )
        )
        val testUrl = "http://localhost:${wireMockServer.port()}/test-certificate"
        val certificates = SignatureUtil.getX509CertificatesFromUrl(testUrl)

        Assert.assertNotNull(certificates)
        Assert.assertTrue(certificates!!.isNotEmpty())

        // 元のCertsインスタンスの内容と比較
        Assert.assertEquals(cert.serialNumber, certificates?.get(0)?.serialNumber ?: 0)
    }

    @Test
    fun testValidateCertificateChain() {
        val cert0 = SignatureUtil.generateCertificate(keyPairTestIssuer, keyPairTestCA, false)
        val cert1 =
            SignatureUtil.generateCertificate(keyPairTestCA, keyPairTestCA, true) // 認証局は自己証明
        val b = SignatureUtil.validateCertificateChain(arrayOf(cert0, cert1), cert1)
        Assert.assertTrue(b)
    }

    private fun getPemChain(): String {
        val cert0 = SignatureUtil.generateCertificate(
            keyPairTestIssuer,
            keyPairTestCA,
            false,
            listOf("alt1.verifier.com")
        )
        val cert1 =
            SignatureUtil.generateCertificate(keyPairTestCA, keyPairTestCA, true)
        val pem0 = SignatureUtil.certificateToPem(cert0)
        val pem1 = SignatureUtil.certificateToPem(cert1)
        return "$pem0\n$pem1"
    }

    private fun getTestTokenBuilder(): JWTCreator.Builder {
        return JWT.create()
            .withIssuer("https://university.example/issuers/565049")
            .withKeyId("http://university.example/credentials/3732")
            .withSubject("did:example:ebfeb1f712ebc6f1c276e12ec21")
            .withClaim(
                "vc", mapOf(
                    "@context" to listOf(
                        "https://www.w3.org/ns/credentials/v2",
                        "https://www.w3.org/ns/credentials/examples/v2"
                    ),
                    "id" to "http://university.example/credentials/3732",
                    "type" to listOf("VerifiableCredential", "ExampleDegreeCredential"),
                    "issuer" to "https://university.example/issuers/565049",
                    "validFrom" to "2010-01-01T00:00:00Z",
                    "credentialSubject" to mapOf(
                        "id" to "did:example:ebfeb1f712ebc6f1c276e12ec21",
                        "name" to "Sample Event ABC",
                        "date" to "2024-01-24T00:00:00Z",
                    )
                )
            )
            .withIssuedAt(Date())
    }

    @Test
    fun testVerifyJwtWithX509Certs1() {
        val pemChain = getPemChain()
        wireMockServer.stubFor(
            WireMock.get(WireMock.urlEqualTo("/test-certificate"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withBody(pemChain)
                        .withHeader("Content-Type", "application/x-pem-file")
                )
        )
        val x5uUrl = "http://localhost:${wireMockServer.port()}/test-certificate"

        val algorithm =
            Algorithm.ECDSA256(
                keyPairTestIssuer.public as ECPublicKey,
                keyPairTestIssuer.private as ECPrivateKey?
            )
        val token = getTestTokenBuilder()
            .withHeader(mapOf("x5u" to x5uUrl))
            .sign(algorithm)
        val result = verifyJwtWithX509Certs(token)
        Assert.assertTrue(result.isSuccess)
        val (decodedJwt, certificates) = result.getOrThrow()
        if (!certificates[0].hasSubjectAlternativeName("alt1.verifier.com")) {
            Assert.fail()
        }
        val vc = decodedJwt.getClaim("vc")
        Assert.assertNotNull(vc)
    }

    @Test
    fun testVerifyJwtWithX509Certs2() {
        val cert0 = SignatureUtil.generateCertificate(
            keyPairTestIssuer,
            keyPairTestCA,
            false,
            listOf("alt1.verifier.com")
        )
        val encodedCert0 = Base64.getEncoder().encodeToString(cert0.encoded)
        val cert1 =
            SignatureUtil.generateCertificate(keyPairTestCA, keyPairTestCA, true) // 認証局は自己証明
        val encodedCert1 = Base64.getEncoder().encodeToString(cert1.encoded)
        val certs = listOf(encodedCert0, encodedCert1)

        val algorithm =
            Algorithm.ECDSA256(
                keyPairTestIssuer.public as ECPublicKey,
                keyPairTestIssuer.private as ECPrivateKey?
            )
        val token = getTestTokenBuilder()
            .withHeader(mapOf("x5c" to certs))
            .sign(algorithm)
        val result = verifyJwtWithX509Certs(token)
        Assert.assertTrue(result.isSuccess)
        val (decodedJwt, certificates) = result.getOrThrow()
        if (!certificates[0].hasSubjectAlternativeName("alt1.verifier.com")) {
            Assert.fail()
        }
        val vc = decodedJwt.getClaim("vc")
        Assert.assertNotNull(vc)
    }

    @Test
    fun testVerifyJwtByX5U() {
        val pemChain = getPemChain()
        wireMockServer.stubFor(
            WireMock.get(WireMock.urlEqualTo("/test-certificate"))
                .willReturn(
                    WireMock.aResponse()
                        .withStatus(200)
                        .withBody(pemChain)
                        .withHeader("Content-Type", "application/x-pem-file")
                )
        )
        val x5uUrl = "http://localhost:${wireMockServer.port()}/test-certificate"

        val algorithm =
            Algorithm.ECDSA256(
                keyPairTestIssuer.public as ECPublicKey,
                keyPairTestIssuer.private as ECPrivateKey?
            )
        val token = getTestTokenBuilder()
            .withHeader(mapOf("x5u" to x5uUrl))
            .sign(algorithm)
        val result = verifyJwtByX5U(token)
        Assert.assertTrue(result.isRight())
        result.fold(
            ifLeft = {
                Assert.fail()
            },
            ifRight = {
                val vc = it.getClaim("vc")
                Assert.assertNotNull(vc)
            }
        )
    }

    @Test
    fun testVerifyJwtByX5C() {
        val cert0 = SignatureUtil.generateCertificate(
            keyPairTestIssuer,
            keyPairTestCA,
            false,
            listOf("alt1.verifier.com")
        )
        val encodedCert0 = Base64.getEncoder().encodeToString(cert0.encoded)
        val cert1 =
            SignatureUtil.generateCertificate(keyPairTestCA, keyPairTestCA, true) // 認証局は自己証明
        val encodedCert1 = Base64.getEncoder().encodeToString(cert1.encoded)
        val certs = listOf(encodedCert0, encodedCert1)

        val algorithm =
            Algorithm.ECDSA256(
                keyPairTestIssuer.public as ECPublicKey,
                keyPairTestIssuer.private as ECPrivateKey?
            )
        val token = getTestTokenBuilder()
            .withHeader(mapOf("x5c" to certs))
            .sign(algorithm)
        val result = verifyJwtByX5C(token)
        Assert.assertTrue(result.isSuccess)
        val (decodedJwt, certificates) = result.getOrThrow()
        if (!certificates[0].hasSubjectAlternativeName("alt1.verifier.com")) {
            Assert.fail()
        }
        val vc = decodedJwt.getClaim("vc")
        Assert.assertNotNull(vc)
    }
}

