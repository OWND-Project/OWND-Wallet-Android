package com.ownd_project.tw2023_wallet_android.oid

import com.auth0.jwt.exceptions.JWTVerificationException
import com.ownd_project.tw2023_wallet_android.signature.ES256K.createJws
import com.ownd_project.tw2023_wallet_android.signature.JWT
import com.ownd_project.tw2023_wallet_android.utils.EnumDeserializer
import com.ownd_project.tw2023_wallet_android.utils.SDJwtUtil
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategies
import com.fasterxml.jackson.databind.module.SimpleModule
import com.fasterxml.jackson.module.kotlin.convertValue
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.ownd_project.tw2023_wallet_android.utils.SigningOption
import com.ownd_project.tw2023_wallet_android.utils.KeyUtil
import com.ownd_project.tw2023_wallet_android.utils.KeyUtil.toJwkThumbprintUri
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import java.security.KeyPair
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.UUID


class OpenIdProviderException(message: String) : Exception(message)

typealias FormData = Map<String, String>


class OpenIdProvider(
    val uri: String,
    val option: SigningOption = SigningOption(signingAlgo = "ES256K")
) {
    private lateinit var keyPair: KeyPair
    private lateinit var keyBinding: KeyBinding
    private lateinit var jwtVpJsonGenerator: JwtVpJsonGenerator
    private lateinit var authRequestProcessedData: ProcessedRequestData

    companion object {
        fun selectDisclosure(
            sdJwt: String,
            presentationDefinition: PresentationDefinition
        ): Pair<InputDescriptor, List<SDJwtUtil.Disclosure>>? {
            val parts = sdJwt.split('~')
            val newList = if (parts.size > 2) parts.drop(1).dropLast(1) else emptyList<String>()
            val disclosures = SDJwtUtil.decodeDisclosure(newList)
            // JsonPathによるフィルタのために一度JSONにシリアライズする
            val sourcePayload =
                disclosures.associate { it.key to it.value }
            /*
                example of source payload
                {
                  "claim1": "foo",
                  "claim2": "bar"
                }
             */

            presentationDefinition.inputDescriptors.forEach { inputDescriptor ->
                val matchingDisclosures = inputDescriptor.constraints.fields?.flatMap { field ->
                    /*
                    array of string values filtered by `inputDescriptor.constraints.fields.path`

                    example of input_descriptors
                        "input_descriptors": [
                          {
                            "constraints": {
                              "fields": [
                                {
                                  "path": ["$.claim1"], ここが配列になっている理由はformat毎に異なるpathを指定するため
                                }
                              ]
                            }
                          }
                        ]
                     */

                    // fieldのpathには`$.key`というJsonPath形式の文字列が入っているので, sourcePayloadから該当するkey, valueを取り出す
                    // todo ネストしたペイロードに対応するためにはJsonPathのライブラリを使用する
                    // todo `filter`も合致条件に加える
                    field.path.mapNotNull { jsonPath ->
                        val key = jsonPath.removePrefix("$.")
                        sourcePayload[key]
                        if (sourcePayload.containsKey(key)) key else null
                    }
                }?.let { fieldKeys ->
                    disclosures.filter { it.key in fieldKeys }
                }

                if (!matchingDisclosures.isNullOrEmpty()) {
                    return Pair(inputDescriptor, matchingDisclosures)
                }
            }
            return null
        }
    }

    fun setKeyPair(keyPair: KeyPair) {
        this.keyPair = keyPair
    }

    fun setKeyBinding(keyBinding: KeyBinding) {
        this.keyBinding = keyBinding
    }

    fun setJwtVpJsonGenerator(jwtVpJsonGenerator: JwtVpJsonGenerator) {
        this.jwtVpJsonGenerator = jwtVpJsonGenerator
    }

    fun getProcessedRequestData(): ProcessedRequestData {
        return this.authRequestProcessedData
    }

    suspend fun processAuthorizationRequest(): Result<ProcessedRequestData> {
        if (uri.isBlank()) {
            throw IllegalArgumentException(SIOPErrors.BAD_PARAMS.message)
        }

        val (scheme, authorizationRequestPayload, requestObjectJwt, registrationMetadata, presentationDefinition, requestIsSigned) = parseAndResolve(
            uri
        )

        return if (requestIsSigned) {
            val objectMapper: ObjectMapper = jacksonObjectMapper().apply {
                propertyNamingStrategy = PropertyNamingStrategies.SNAKE_CASE
                configure(DeserializationFeature.READ_ENUMS_USING_TO_STRING, true)
                configure(
                    DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
                    false
                ) // ランダムなプロパティは無視する
                val module = SimpleModule().apply {
                    addDeserializer(Audience::class.java, AudienceDeserializer())
                    addDeserializer(ResponseMode::class.java, EnumDeserializer(ResponseMode::class))
                }
                registerModule(module)
            }
            val decodedJwt = com.auth0.jwt.JWT.decode(requestObjectJwt)
            val payloadJson = String(Base64.getUrlDecoder().decode(decodedJwt.payload))
            val payload = objectMapper.readValue(payloadJson, RequestObjectPayloadImpl::class.java)

            val clientId = payload.clientId ?: authorizationRequestPayload.clientId
            if (clientId.isNullOrBlank()) {
                return Result.failure(Exception("Invalid client_id or response_uri"))
            }
            val clientScheme = payload.clientIdScheme ?: authorizationRequestPayload.clientIdScheme

            if (clientScheme == "x509_san_dns") {
                val verifyResult = JWT.verifyJwtWithX509Certs(requestObjectJwt)
                if (!verifyResult.isSuccess) {
                    return Result.failure(Exception("Invalid request"))
                }
                val (decodedJwt, certificates) = verifyResult.getOrThrow()
                // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
                /*
                the Client Identifier MUST be a DNS name and match a dNSName Subject Alternative Name (SAN) [RFC5280] entry in the leaf certificate passed with the request.
                 */
                if (!certificates[0].hasSubjectAlternativeName(clientId)) {
                    return Result.failure(Exception("client_id is not in SAN entry"))
                }
                val uri = payload.responseUri ?: payload.redirectUri
                if (clientId != uri) {
                    return Result.failure(Exception("Invalid client_id or host uri"))
                }
            } else {
                return Result.failure(Exception("Unsupported serialization of Authorization Request Error"))
            }

            val result = try {
                if (clientScheme == "redirect_uri") {
                    val responseUri = payload.responseUri ?: authorizationRequestPayload.responseUri
                    if (clientId.isNullOrBlank() || responseUri.isNullOrBlank() || clientId != responseUri) {
                        return Result.failure(Exception("Invalid client_id or response_uri"))
                    }
                }

                Result.success(
                    ProcessedRequestData(
                        scheme,
                        payload,
                        authorizationRequestPayload,
                        requestObjectJwt,
                        registrationMetadata,
                        presentationDefinition
                    )
                )
            } catch (e: JWTVerificationException) {
                Result.failure(e)
            }
            if (result.isSuccess) {
                this.authRequestProcessedData = result.getOrThrow()
            }
            return result
        } else {
            val clientScheme = authorizationRequestPayload.clientIdScheme
            if (clientScheme == "redirect_uri") {
                val clientId = authorizationRequestPayload.clientId
                val responseUri = authorizationRequestPayload.responseUri
                if (clientId.isNullOrBlank() || responseUri.isNullOrBlank() || clientId != responseUri) {
                    return Result.failure(Exception("Invalid client_id or response_uri"))
                }
            }
            val authRequest = ProcessedRequestData(
                scheme,
                null,
                authorizationRequestPayload,
                requestObjectJwt,
                registrationMetadata,
                presentationDefinition
            )
            this.authRequestProcessedData = authRequest
            Result.success(authRequest)
        }
    }

    fun respondToken(
        credentials: List<SubmissionCredential>?,
    ): Result<TokenSendResult> {

        val authRequest = mergeOAuth2AndOpenIdInRequestPayload(
            this.authRequestProcessedData.authorizationRequestPayload,
            this.authRequestProcessedData.requestObject
        )

        // https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID3.html#section-5.2
        // If the parameter is not present, the default value is fragment
        val responseMode = authRequest.responseMode
            ?: ResponseMode.FRAGMENT

        if (!isIdTokenRequired && !isVpTokenRequired) {
            return Result.failure(OpenIdProviderException("Both or either `id_token` and `vp_token` are required"))
        }

        var idTokenFormData: FormData? = null
        var idTokenForHistory: String? = null

        var vpTokenFormData: FormData? = null
        var vpForHistory: List<SharedCredential>? = null

        if (isIdTokenRequired) {
            val created = createSiopIdToken()
            when {
                created.isSuccess -> {
                    val value = created.getOrNull()
                    if (value != null) {
                        val (formData, rawIdToken) = value
                        idTokenFormData = formData
                        idTokenForHistory = rawIdToken
                    } else {
                        return Result.failure(OpenIdProviderException("Unable to create id token"))
                    }
                }

                created.isFailure -> {
                    return Result.failure(OpenIdProviderException("Unable to create id token"))
                }
            }

        }
        if (isVpTokenRequired) {
            credentials
                ?: return Result.failure(OpenIdProviderException("Credentials to be sent must be supplied"))
            val created = createVpToken(credentials)
            when {
                created.isSuccess -> {
                    val value = created.getOrNull()
                    if (value != null) {
                        val (formData, sharedCredentials) = value
                        vpTokenFormData = formData
                        vpForHistory = sharedCredentials
                    }
                }

                created.isFailure -> {
                    return Result.failure(OpenIdProviderException("Unable to create vp token"))
                }
            }
        }

        val mergedFormData =
            ((idTokenFormData ?: emptyMap()) + (vpTokenFormData ?: emptyMap())).toMutableMap()
        val state = authRequest.state
        if (!state.isNullOrBlank()) {
            mergedFormData["state"] = state
        }

        var uri: String? = null
        when (responseMode) {
            ResponseMode.DIRECT_POST, ResponseMode.DIRECT_POST_JWT, ResponseMode.POST -> {
                uri = authRequest.responseUri
            }

            else -> {
                uri = authRequest.redirectUri
            }
        }
        val whereToRespond = uri
            ?: return Result.failure(OpenIdProviderException("Either responseUri or redirectUri must be supplied"))


        try {
            val (statusCode, location, cookies) = sendRequest(
                whereToRespond,
                mergedFormData,
                responseMode
            )
            return Result.success(
                TokenSendResult(
                    statusCode = statusCode,
                    location = location,
                    cookies = cookies,
                    sharedIdToken = idTokenForHistory,
                    sharedCredentials = vpForHistory,
                )
            )
        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    val isIdTokenRequired: Boolean
        get() {
            // todo: 都度マージするのを避けるべき
            val authRequest = mergeOAuth2AndOpenIdInRequestPayload(
                this.authRequestProcessedData.authorizationRequestPayload,
                this.authRequestProcessedData.requestObject
            )
            val responseType = authRequest.responseType
                ?: throw OpenIdProviderException("responseType must be supplied")
            return responseType.contains("id_token")
        }

    val isVpTokenRequired: Boolean
        get() {
            // todo: 都度マージするのを避けるべき
            val authRequest = mergeOAuth2AndOpenIdInRequestPayload(
                this.authRequestProcessedData.authorizationRequestPayload,
                this.authRequestProcessedData.requestObject
            )
            val responseType = authRequest.responseType
                ?: throw OpenIdProviderException("responseType must be supplied")
            return responseType.contains("vp_token")
        }

    private fun createSiopIdToken(): Result<Pair<FormData, String>> {
        try {
            val authRequest = mergeOAuth2AndOpenIdInRequestPayload(
                this.authRequestProcessedData.authorizationRequestPayload,
                this.authRequestProcessedData.requestObject
            )
            val nonce = authRequest.nonce
            val SEC_IN_MS = 1000

            val subJwk = KeyUtil.keyPairToPublicJwk(keyPair, option)
            // todo: support rsa key
            val sub = toJwkThumbprintUri(subJwk)
            // https://openid.github.io/SIOPv2/openid-connect-self-issued-v2-wg-draft.html#section-11.1
            // The RP MUST validate that the aud (audience) Claim contains the value of the Client ID that the RP sent in the Authorization Request as an audience.
            // When the request has been signed, the value might be an HTTPS URL, or a Decentralized Identifier.
            val idTokenPayload = IDTokenPayloadImpl(
                iss = sub,
                aud = Audience.Single(authRequest.clientId!!),
                iat = (System.currentTimeMillis() / SEC_IN_MS).toLong(),
                exp = (System.currentTimeMillis() / SEC_IN_MS + 600).toLong(),
                sub = sub,
                nonce = nonce as? String,
                subJwk = subJwk,
            )
            val module = SimpleModule().apply {
                addSerializer(Audience::class.java, AudienceSerializer())
            }
            val mapper = jacksonObjectMapper().apply {
                propertyNamingStrategy = PropertyNamingStrategies.SNAKE_CASE
                registerModule(module)
            }
            val payloadJson = mapper.writeValueAsString(idTokenPayload)
            println("create id token")
            // todo support various algorithms using provider option's `signingAlgo`
            val idToken = createJws(keyPair, payloadJson, false)
            println("id token: $idToken")

            // As a temporary value, give DIRECT_POST a fixed value.
            // It needs to be modified when responding to redirect responses.
            val body = mutableMapOf("id_token" to idToken)
            return Result.success(body to idToken)
        } catch (e: Exception) {
            return Result.failure(e)
        }
    }

    private fun createVpToken(
        credentials: List<SubmissionCredential>,
    ): Result<Pair<FormData, List<SharedCredential>>> {
        try {
            val authRequest = mergeOAuth2AndOpenIdInRequestPayload(
                this.authRequestProcessedData.authorizationRequestPayload,
                this.authRequestProcessedData.requestObject
            )
            val presentationDefinition = this.authRequestProcessedData.presentationDefinition
                ?: throw IllegalArgumentException(SIOPErrors.BAD_PARAMS.message)

            // https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
            //   the default Response Mode for the OAuth 2.0 code Response Type is the query encoding
            //   the default Response Mode for the OAuth 2.0 token Response Type is the fragment encoding
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#section-5
            //   If the parameter is not present, the default value is fragment.
            val responseMode = authRequest.responseMode ?: ResponseMode.FRAGMENT

            // presentationDefinition.inputDescriptors を使って選択項目でフィルター
            val presentingContents = credentials.mapNotNull { it ->
                when (it.format) {
                    "vc+sd-jwt" -> {
                        createPresentationSubmissionSdJwtVc(it, authRequest, presentationDefinition)
                    }

                    "jwt_vc_json" -> {
                        createPresentationSubmissionJwtVc(it, authRequest)
                    }

                    else -> {
                        throw IllegalArgumentException(SIOPErrors.BAD_PARAMS.message)
                    }
                }
            }
            // presentation_submissionを生成
            val vpTokenValue = if (presentingContents.size == 1) {
                presentingContents[0].vpToken
            } else if (presentingContents.isNotEmpty()) {
                val tokens = presentingContents.map { it.vpToken }
                jacksonObjectMapper().writeValueAsString(tokens)
            } else {
                "" // 0件の場合はブランク
            }
            val presentationSubmission = PresentationSubmission(
                id = UUID.randomUUID().toString(),
                definitionId = presentationDefinition.id,
                descriptorMap = presentingContents.map { it.descriptorMap }
            )
            println(presentationSubmission)
            val objectMapper: ObjectMapper = jacksonObjectMapper().apply {
                propertyNamingStrategy = PropertyNamingStrategies.SNAKE_CASE
            }
            val jsonString = objectMapper.writeValueAsString(presentationSubmission)
            val body = mutableMapOf(
                "vp_token" to vpTokenValue,
                "presentation_submission" to jsonString
            )

            val purposeForSharing: String? = null // todo: 履歴に保持するために適切な値を設定する

            val sharedCredentials =
                presentingContents.map {
                    SharedCredential(
                        it.credential.id,
                        purposeForSharing,
                        it.disclosedClaims
                    )
                }

            return Result.success(body to sharedCredentials)
        } catch (e: Exception) {
            e.printStackTrace()
            return Result.failure(e)
        }
    }

    private fun createPresentationSubmissionSdJwtVc(
        credential: SubmissionCredential,
        authRequest: RequestObjectPayload,
        presentationDefinition: PresentationDefinition
    ): PresentingContent {
        val sdJwt = credential.credential
        val (_, selectedDisclosures) = selectDisclosure(sdJwt, presentationDefinition)!!
        return SdJwtVcPresentation.createPresentation(
            credential,
            selectedDisclosures,
            authRequest,
            keyBinding
        )
    }

    private fun createPresentationSubmissionJwtVc(
        credential: SubmissionCredential,
        authRequest: RequestObjectPayload,
    ): PresentingContent {
        if (authRequest.responseMode != ResponseMode.DIRECT_POST) {
            throw IllegalArgumentException("Unsupported response mode: ${authRequest.responseMode}")
        }
        return JwtVpJsonPresentation.createPresentation(
            credential,
            authRequest,
            jwtVpJsonGenerator
        )
    }
}

fun mergeOAuth2AndOpenIdInRequestPayload(
    payload: AuthorizationRequestPayload,
    requestObject: RequestObjectPayload? = null
): RequestObjectPayload {
    val module = SimpleModule().apply {
        addSerializer(Audience::class.java, AudienceSerializer())
    }
    val mapper = jacksonObjectMapper().apply {
        propertyNamingStrategy = PropertyNamingStrategies.SNAKE_CASE
        registerModule(module)
    }
    // AuthorizationRequestPayloadをMapに変換
    val payloadMap: Map<String, Any?> = mapper.convertValue(payload)

    // RequestObjectをMapに変換（nullの場合は空のMapを使用）
    val requestObjectMap: Map<String, Any?> = if (requestObject != null) {
        mapper.convertValue(requestObject)
    } else {
        emptyMap()
    }

    val mergedMap = payloadMap.toMutableMap().apply {
        requestObjectMap.forEach { (key, value) ->
            if (value != null) {
                this[key] = value
            }
        }
    }
    return createRequestObjectPayloadFromMap(mergedMap)
}

fun sendRequest(
    destinationUri: String,
    formData: FormData,
    responseMode: ResponseMode
): Triple<Int, String?, Array<String>> { //TokenSendResult {
    val client = OkHttpClient.Builder()
        .followRedirects(false)
        .build()

    val formBodyBuilder = FormBody.Builder()
    formData.forEach { (key, value) ->
        formBodyBuilder.add(key, value)
    }
    val formBody = formBodyBuilder.build()
    val request: Request

    when (responseMode) {
        ResponseMode.DIRECT_POST -> {
            request = Request.Builder()
                .url(destinationUri)
                .post(formBody)
                .build()
        }

        else -> {
            throw IllegalArgumentException("Unsupported response mode: $responseMode")
        }
    }

    client.newCall(request).execute().use { response ->
        var location: String? = null
        val statusCode = response.code()
        val contentType = response.header("Content-Type")
        val cookies = response.headers("Set-Cookie")

        if (statusCode == 200 && contentType?.contains("application/json") == true) {
            response.body()?.string()?.let { body ->
                val mapper = jacksonObjectMapper()
                val jsonNode = mapper.readTree(body)
                if (jsonNode.has("redirect_uri")) {
                    location = jsonNode.get("redirect_uri").asText()
                }
            }
        }

        val tmp = if (cookies.isNotEmpty()) cookies.toTypedArray() else emptyArray()
        return Triple(statusCode, location, tmp)
    }
}

fun satisfyConstrains(
    credential: Map<String, Any>,
    presentationDefinition: PresentationDefinition
): Boolean {
    // TODO: 暫定で固定パス(vc.credentialSubject)のクレデンシャルをサポートする
    val vc = credential["vc"] as? Map<String, Any> ?: run {
        println("unsupported format")
        println(credential)
        return false
    }
    val credentialSubject = vc["credentialSubject"] as? Map<String, Any> ?: run {
        println("unsupported format")
        println(credential)
        return false
    }
    val inputDescriptors = presentationDefinition.inputDescriptors

    var matchingFieldsCount = 0
    val matchedInputDescriptors = mutableListOf<InputDescriptor>()

    inputDescriptors.forEach { inputDescriptor ->
        var fields = inputDescriptor.constraints.fields ?: return@forEach
        val isFieldMatched = fields.all { field ->
            field.path.any { jsonPath ->
                val pathComponents = jsonPath.split(".")
                pathComponents.last().let { lastComponent ->
                    if (lastComponent != "$") {
                        val key = lastComponent.replace("vc.", "")
                        // credentialのキーとして含まれているか判定
                        credentialSubject.keys.contains(key)
                    } else false
                }
            }
        }
        if (isFieldMatched) {
            matchedInputDescriptors.add(inputDescriptor)
        }
    }

    println("matched : $matchedInputDescriptors")
    val matchedInputDescriptorsCount = matchedInputDescriptors.size
    return 0 < matchedInputDescriptorsCount
}

data class ProcessedRequestData(
    val scheme: String,
    val requestObject: RequestObjectPayload?,
    val authorizationRequestPayload: AuthorizationRequestPayload,
    val requestObjectJwt: String,
    val registrationMetadata: RPRegistrationMetadataPayload,
    val presentationDefinition: PresentationDefinition?,
)

data class SubmissionCredential(
    val id: String, // credential identifier
    val format: String, // specified by VCI
    val types: List<String>,
    val credential: String,
    val inputDescriptor: InputDescriptor,
)

data class DisclosedClaim(
    val id: String, // credential identifier
    val types: List<String>,
    val name: String
    // val path: String (when nested claim is supported, it may be needed like this)
)

data class SharedCredential(
    val id: String,
    val purposeForSharing: String?,
    val sharedClaims: List<DisclosedClaim>
)

data class TokenSendResult(
    val statusCode: Int,
    val location: String?,
    val cookies: Array<String>,

    val sharedIdToken: String?,
    val sharedCredentials: List<SharedCredential>?
)

fun X509Certificate.hasSubjectAlternativeName(target: String): Boolean {
    val altNames = this.subjectAlternativeNames ?: return false
    return altNames.any { target.contains(it[1].toString()) }
}