package com.ownd_project.tw2023_wallet_android.oid

import com.fasterxml.jackson.annotation.JsonInclude

@JsonInclude(JsonInclude.Include.NON_NULL)
data class VpJwtPayload(
    val iss: String?,
    val jti: String?,
    val aud: String?,
    val nbf: Long?,
    val iat: Long?,
    val exp: Long?,
    val nonce: String?,
    val vp: Map<String, Any>
)
// https://www.rfc-editor.org/rfc/rfc7515.html
data class HeaderOptions(
    val alg: String = "ES256",
    val typ: String = "JWT",
    val jwk: String? = null
)

data class JwtVpJsonPayloadOptions(
    var iss: String? = null,
    var jti: String? = null,
    var aud: String,
    var nbf: Long? = null,
    var iat: Long? = null,
    var exp: Long? = null,
    var nonce: String
)

object JwtVpJsonPresentation {
    fun genDescriptorMap(
        inputDescriptorId: String,
        pathIndex: Int? = -1,
        pathNestedIndex: Int? = 0
    ): DescriptorMap {

        /*
        a non-normative example of the content of the presentation_submission parameter:
        ```
            {
              "definition_id": "example_jwt_vc",
              "id": "example_jwt_vc_presentation_submission",
              "descriptor_map": [
                {
                  "id": "id_credential",
                  "path": "$",
                  "format": "jwt_vp_json",
                  "path_nested": {
                    "path": "$.vp.verifiableCredential[0]",
                    "format": "jwt_vc_json"
                  }
                }
              ]
            }
        ```
         */
        return DescriptorMap(
            id = inputDescriptorId,
            path = if (pathIndex == -1) "$" else "$[${pathIndex}]",
            format = "jwt_vp_json",
            pathNested = Path(
                format = "jwt_vc_json",
                path = "$.vp.verifiableCredential[${pathNestedIndex}]"
            )
        )
    }

    fun genVpJwtPayload(vcJwt: String, payloadOptions: JwtVpJsonPayloadOptions): VpJwtPayload {
        val vpClaims = mapOf(
            "@context" to listOf("https://www.w3.org/2018/credentials/v1"),
            "type" to listOf("VerifiablePresentation"),
            "verifiableCredential" to listOf(vcJwt)
        )

        val currentTimeSeconds = System.currentTimeMillis() / 1000
        return VpJwtPayload(
            iss = payloadOptions.iss,
            jti = payloadOptions.jti,
            aud = payloadOptions.aud,
            nbf = payloadOptions.nbf ?: currentTimeSeconds,
            iat = payloadOptions.iat ?: currentTimeSeconds,
            exp = payloadOptions.exp ?: (currentTimeSeconds + 2 * 3600),
            nonce = payloadOptions.nonce,
            vp = vpClaims
        )
    }
}

// https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#name-presentation-response
interface JwtVpJsonGenerator {
    /*
    a non-normative example of the payload of the Verifiable Presentation in the vp_token parameter
    ```
    {
        "iss": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "jti": "urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5",
        "aud": "https://client.example.org/cb",
        "nbf": 1541493724,
        "iat": 1541493724,
        "exp": 1573029723,
        "nonce": "n-0S6_WzA2Mj",
        "vp": {
            "@context": [
                "https://www.w3.org/2018/credentials/v1"
            ],
            "type": [
                "VerifiablePresentation"
            ],
            "verifiableCredential": [
                "eyJhb...ssw5c"
            ]
        }
    }
    ```
    Note: The VP's nonce claim contains the value of the nonce of the presentation request and the aud claim contains the Client Identifier of the Verifier.
    This allows the Verifier to detect replay of a Presentation as recommended in Section 12.1.
     */
    fun generateJwt(
        vcJwt: String,
        headerOptions: HeaderOptions,
        payloadOptions: JwtVpJsonPayloadOptions
    ): String

    fun getJwk(): Map<String, String>
}