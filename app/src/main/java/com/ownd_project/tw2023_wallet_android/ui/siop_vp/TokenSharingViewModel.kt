package com.ownd_project.tw2023_wallet_android.ui.siop_vp

import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import arrow.core.Either
import com.ownd_project.tw2023_wallet_android.R
import com.ownd_project.tw2023_wallet_android.datastore.CredentialSharingHistoryStore
import com.ownd_project.tw2023_wallet_android.datastore.IdTokenSharingHistoryStore
import com.ownd_project.tw2023_wallet_android.pairwise.Account
import com.ownd_project.tw2023_wallet_android.pairwise.PairwiseAccount
import com.ownd_project.tw2023_wallet_android.datastore.PreferencesDataStore
import com.ownd_project.tw2023_wallet_android.pairwise.HDKeyRing
import com.ownd_project.tw2023_wallet_android.oid.OpenIdProvider
import com.ownd_project.tw2023_wallet_android.oid.PresentationDefinition
import com.ownd_project.tw2023_wallet_android.utils.SigningOption
import com.ownd_project.tw2023_wallet_android.oid.SubmissionCredential
import com.ownd_project.tw2023_wallet_android.signature.ECPrivateJwk
import com.ownd_project.tw2023_wallet_android.signature.SignatureUtil
import com.ownd_project.tw2023_wallet_android.ui.shared.Constants
import com.ownd_project.tw2023_wallet_android.ui.shared.KeyBindingImpl
import com.ownd_project.tw2023_wallet_android.utils.CertificateInfo
import com.ownd_project.tw2023_wallet_android.utils.CertificateUtil.getCertificateInformation
import com.google.protobuf.Timestamp
import com.ownd_project.tw2023_wallet_android.oid.TokenSendResult
import com.ownd_project.tw2023_wallet_android.ui.shared.JwtVpJsonGeneratorImpl
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.Instant

data class ClientInfo(
    var name: String = "",
    var url: String = "",
    var logoUrl: String = "",
    var policyUrl: String = "",
    var tosUrl: String = "",
    var jwkThumbprint: String = "",
    var identiconHash: Int = 0,
    var certificateInfo: CertificateInfo = CertificateInfo(null, null, null, null, null, null)
)

val TAG = TokenSharingViewModel::class.simpleName

class TokenSharingViewModel : ViewModel() {
    var isInitialized = false
    lateinit var openIdProvider: OpenIdProvider
    private val _clientInfo = MutableLiveData<ClientInfo>()
    val clientInfo: LiveData<ClientInfo> = _clientInfo

    private val _presentationDefinition = MutableLiveData<PresentationDefinition>()
    val presentationDefinition: LiveData<PresentationDefinition> = _presentationDefinition

    // リクエスト処理完了通知
    private val _initDone = MutableLiveData<Boolean>()
    val initDone: LiveData<Boolean> = _initDone

    // レスポンス処理完了通知
    private val _doneSuccessfully = MutableLiveData<Boolean>()
    val doneSuccessfully: LiveData<Boolean> = _doneSuccessfully

    // 提供結果
    private val _tokenSendResult = MutableLiveData<TokenSendResult>()
    val tokenSendResult: LiveData<TokenSendResult> = _tokenSendResult

    // クローズ要求通知
    private val _shouldClose = MutableLiveData<Boolean>()
    val shouldClose: LiveData<Boolean> = _shouldClose

    //エラー表示用のLiveData
    private val _errorMessage = MutableLiveData<String?>()
    val errorMessage: LiveData<String?> = _errorMessage

    private var index: Int = -1
    fun setIndex(index: Int) {
        this.index = index
    }

    fun requestClose() {
        _shouldClose.value = true
    }

    fun resetCloseRequest() {
        _shouldClose.value = false
    }

    fun resetErrorMessage() {
        _errorMessage.value = null
    }

    init {
        // 初期値を設定
        _clientInfo.value = ClientInfo()
    }

    fun setClientName(value: String) {
        _clientInfo.value = _clientInfo.value?.copy(name = value)
    }

    fun setClientUrl(value: String) {
        _clientInfo.value = _clientInfo.value?.copy(url = value)
    }

    fun setClientLogoUrl(value: String) {
        _clientInfo.value = _clientInfo.value?.copy(logoUrl = value)
    }

    fun setClientPolicyUrl(value: String) {
        _clientInfo.value = _clientInfo.value?.copy(policyUrl = value)
    }

    fun setClientTosUrl(value: String) {
        _clientInfo.value = _clientInfo.value?.copy(tosUrl = value)
    }

    fun setJwkThumbprint(value: String) {
        _clientInfo.value = _clientInfo.value?.copy(jwkThumbprint = value)
    }

    fun setIdenticon(value: Int) {
        _clientInfo.value = _clientInfo.value?.copy(identiconHash = value)
    }

    fun setCertificateInfo(value: CertificateInfo) {
        _clientInfo.value = _clientInfo.value?.copy(certificateInfo = value)
    }

    fun accessPairwiseAccountManager(fragment: Fragment, url: String, index: Int = -1) {
        viewModelScope.launch() {
            // SIOP要求を処理する前にペアワイズアカウントのキーペアの使用準備をする
            // 生体認証をpassできたらSIOP要求を処理する
            val dataStore = PreferencesDataStore(fragment.requireContext())
            val seedState = dataStore.getSeed(fragment)
            if (seedState != null) {
                if (seedState.isRight()) {
                    var seed = (seedState as Either.Right).value
                    Log.d(TAG, "accessed seed successfully")
                    if (seed.isNullOrEmpty()) {
                        // 初回のシード生成
                        val hdKeyRing = HDKeyRing(null)
                        seed = hdKeyRing.getMnemonicString()
                        dataStore.saveSeed(seed)
                    }
                    // SIOP要求処理(一度フラグメント側に制御を返す構造の方が望ましい)
                    processAuthRequest(fragment.requireContext(), url, seed, index)
                } else {
                    val biometricStatus = (seedState as Either.Left).value
                    Log.d(TAG, "BiometricStatus: $biometricStatus")
                    withContext(Dispatchers.Main) {
                        requestClose()
                    }
                }
            }
        }
    }

    private fun processAuthRequest(context: Context, url: String, seed: String, index: Int) {
        Log.d(TAG, "processSiopRequest")
        viewModelScope.launch(Dispatchers.IO) {
            val opt = SigningOption(signingCurve = "secp256k1", signingAlgo = "ES256K")
            openIdProvider = OpenIdProvider(url, opt)
            val result = openIdProvider.processAuthorizationRequest()
            result.fold(
                onFailure = { value ->
                    Log.e(TAG, "エラーが発生しました: ${value}")
                    withContext(Dispatchers.Main) {
                        _initDone.value = true
                        _errorMessage.value = value.message
                    }
                },
                onSuccess = { siopRequest ->
                    Log.d(TAG, "processSiopRequest success")
                    val (scheme, requestObject, authorizationRequestPayload, requestObjectJwt, registrationMetadata, presentationDefinition) = siopRequest
                    val certificateInfo =
                        authorizationRequestPayload.clientId?.let { getCertificateInformation(it) }
                    val accountManager = PairwiseAccount(context, seed)
                    val rp = authorizationRequestPayload.clientId!!
                    var account: Account? = accountManager.getAccount(rp, index)
                    if (account == null) {
                        account = accountManager.nextAccount()
                    }
                    setIndex(account.index)
                    val jwk = account!!.privateJwk
                    val privateJwk = object : ECPrivateJwk {
                        override val kty = jwk.kty
                        override val crv = jwk.crv
                        override val x = jwk.x
                        override val y = jwk.y
                        override val d = jwk.d
                    }
                    if (presentationDefinition == null) {
                        val keyPair = SignatureUtil.generateECKeyPair(privateJwk)
                        openIdProvider.setKeyPair(keyPair)
                    } else {
                        val keyBinding = KeyBindingImpl(Constants.KEY_PAIR_ALIAS_FOR_KEY_BINDING)
                        openIdProvider.setKeyBinding(keyBinding)

                        val jwtVpJsonGenerator =
                            JwtVpJsonGeneratorImpl(Constants.KEY_PAIR_ALIAS_FOR_KEY_JWT_VP_JSON)
                        openIdProvider.setJwtVpJsonGenerator(jwtVpJsonGenerator)
                    }

                    // getServerCertificates("https://datasign.jp/")
                    withContext(Dispatchers.Main) {
                        Log.d(TAG, "update ui")
                        if (registrationMetadata.clientName != null) {
                            setClientName(registrationMetadata.clientName)
                        }
                        val clientId =
                            requestObject?.clientId ?: authorizationRequestPayload.clientId
                        if (clientId != null) {
                            setClientUrl(clientId)
                        }
                        if (registrationMetadata.logoUri != null) {
                            setClientLogoUrl(registrationMetadata.logoUri)
                        }
                        if (registrationMetadata.policyUri != null) {
                            setClientPolicyUrl(registrationMetadata.policyUri)
                        }
                        if (registrationMetadata.tosUri != null) {
                            setClientTosUrl(registrationMetadata.tosUri)
                        }
                        if (account != null) {
                            setJwkThumbprint(account.thumbprint)
                            setIdenticon(account.hash)
                        }
                        if (certificateInfo != null) {
                            setCertificateInfo(certificateInfo)
                        }
                        if (presentationDefinition != null) {
                            _presentationDefinition.value = presentationDefinition!!
                        }
                        _initDone.value = true
                    }
                }
            )
        }
    }

    fun shareToken(fragment: Fragment, credentials: List<SubmissionCredential>?) {
        viewModelScope.launch(Dispatchers.IO) {
            val result = openIdProvider.respondToken(credentials)
            result.fold(
                onFailure = { value ->
                    Log.e(TAG, value.message, value)
                    withContext(Dispatchers.Main) {
                        val context = fragment.requireContext()
                        val msg = "${context.getString(R.string.error_occurred)} ${value.message}"
                        Toast.makeText(
                            context,
                            msg,
                            Toast.LENGTH_SHORT
                        ).show()
                        requestClose()
                    }
                },
                onSuccess = { tokenSendResult ->
                    if (tokenSendResult.sharedIdToken != null) {
                        // postに成功したらログイン履歴を記録
                        Log.d(TAG, "store id_token sharing history")
                        val store: IdTokenSharingHistoryStore =
                            IdTokenSharingHistoryStore.getInstance(fragment.requireContext())
                        val currentInstant = Instant.now()
                        val history =
                            com.ownd_project.tw2023_wallet_android.datastore.IdTokenSharingHistory.newBuilder()
                                .setRp(openIdProvider.getProcessedRequestData().authorizationRequestPayload.clientId)
                                .setAccountIndex(index)
                                .setCreatedAt(
                                    Timestamp.newBuilder()
                                        .setSeconds(currentInstant.epochSecond)
                                        .setNanos(currentInstant.nano)
                                        .build()
                                )
                                .build();
                        store.save(history)
                    }
                    if (tokenSendResult.sharedCredentials != null) {
                        val store =
                            CredentialSharingHistoryStore.getInstance(fragment.requireContext())
                        val currentInstant = Instant.now()
                        tokenSendResult.sharedCredentials?.forEach { it ->
                            val openIdProviderSiopRequest = openIdProvider.getProcessedRequestData()
                            val registrationPayload = openIdProviderSiopRequest.registrationMetadata
                            val builder =
                                com.ownd_project.tw2023_wallet_android.datastore.CredentialSharingHistory.newBuilder()
                                    .setRp(openIdProviderSiopRequest.authorizationRequestPayload.clientId)
                                    .setAccountIndex(index)
                                    .setCreatedAt(
                                        Timestamp.newBuilder()
                                            .setSeconds(currentInstant.epochSecond)
                                            .setNanos(currentInstant.nano)
                                            .build()
                                    )
                                    .setRpName(registrationPayload.clientName)
                                    .setRpPrivacyPolicyUrl(registrationPayload.policyUri)
                                    .setRpLogoUrl(registrationPayload.logoUri)
                                    .setCredentialID(it.id)
                            it.sharedClaims.forEach { claim ->
                                val tmp =
                                    com.ownd_project.tw2023_wallet_android.datastore.Claim.newBuilder()
                                        .setName(claim.name)
                                        .setPurpose("") // todo: The definition of DisclosedClaim needs to be revised to set this value.
                                        .setValue("") // todo: The definition of DisclosedClaim needs to be revised to set this value.
                                builder.addClaims(tmp)
                            }
                            val history = builder.build()
                            store.save(history)
                        }
                    }

                    withContext(Dispatchers.Main) {
                        _tokenSendResult.value = tokenSendResult
                        if (openIdProvider.isVpTokenRequired) {
                            _doneSuccessfully.value = true
                        } else {
                            val context = fragment.requireContext()
                            Toast.makeText(
                                context,
                                context.getString(R.string.signed_in),
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
            )
        }
    }
}