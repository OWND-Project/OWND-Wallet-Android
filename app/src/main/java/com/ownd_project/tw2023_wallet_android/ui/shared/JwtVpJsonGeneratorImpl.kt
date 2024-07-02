package com.ownd_project.tw2023_wallet_android.ui.shared

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.ownd_project.tw2023_wallet_android.oid.HeaderOptions
import com.ownd_project.tw2023_wallet_android.oid.JwtVpJsonGenerator
import com.ownd_project.tw2023_wallet_android.oid.JwtVpJsonPayloadOptions
import com.ownd_project.tw2023_wallet_android.oid.JwtVpJsonPresentation
import com.ownd_project.tw2023_wallet_android.signature.JWT
import com.ownd_project.tw2023_wallet_android.utils.SigningOption
import com.ownd_project.tw2023_wallet_android.utils.KeyPairUtil
import com.ownd_project.tw2023_wallet_android.utils.KeyUtil
import com.ownd_project.tw2023_wallet_android.utils.KeyUtil.toJwkThumbprintUri
import java.security.PublicKey

class JwtVpJsonGeneratorImpl(private val keyAlias: String = Constants.KEY_PAIR_ALIAS_FOR_KEY_JWT_VP_JSON) :
    JwtVpJsonGenerator {
    override fun generateJwt(
        vcJwt: String,
        headerOptions: HeaderOptions,
        payloadOptions: JwtVpJsonPayloadOptions
    ): String {
        val jwk = getJwk()
        val header =
            mapOf("alg" to headerOptions.alg, "typ" to headerOptions.typ, "jwk" to jwk)
        val sub = toJwkThumbprintUri(jwk)
        payloadOptions.iss = sub
        val jwtPayload = JwtVpJsonPresentation.genVpJwtPayload(vcJwt, payloadOptions)
        val objectMapper = jacksonObjectMapper()
        val vpTokenPayload =
            objectMapper.convertValue(jwtPayload, Map::class.java) as Map<String, Any>
        return JWT.sign(keyAlias, header, vpTokenPayload)
    }

    override fun getJwk(): Map<String, String> {
        if (!KeyPairUtil.isKeyPairExist(keyAlias)) {
            KeyPairUtil.generateSignVerifyKeyPair(keyAlias)
        }
        val publicKey: PublicKey = KeyPairUtil.getPublicKey(keyAlias)
            ?: throw IllegalStateException("Public key not found for alias: $keyAlias")
        val jwk = KeyUtil.publicKeyToJwk(publicKey, SigningOption())
        return jwk
    }
}