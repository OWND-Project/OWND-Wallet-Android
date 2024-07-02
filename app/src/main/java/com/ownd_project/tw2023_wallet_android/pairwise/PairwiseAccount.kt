package com.ownd_project.tw2023_wallet_android.pairwise

import android.content.Context
import arrow.core.Either
import com.ownd_project.tw2023_wallet_android.datastore.IdTokenSharingHistoryStore
import com.ownd_project.tw2023_wallet_android.signature.ECPublicJwk
import com.google.protobuf.Timestamp
import com.ownd_project.tw2023_wallet_android.datastore.IdTokenSharingHistory
import com.ownd_project.tw2023_wallet_android.utils.KeyUtil.toJwkThumbprint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.time.Instant
import java.util.Base64

val TAG: String = ::PairwiseAccount.javaClass.simpleName

class PairwiseAccount(
    private val context: Context,
    private val mnemonicWords: String,
    private val store: IdTokenSharingHistoryStore = IdTokenSharingHistoryStore.getInstance(
        context
    )
) {
    private val keyring: HDKeyRing = HDKeyRing(mnemonicWords)

    companion object {
        fun toECPublicJwk(jwk: PublicJwk): ECPublicJwk {
            return object : ECPublicJwk {
                override val kty = jwk.kty
                override val crv = jwk.crv
                override val x = jwk.x
                override val y = jwk.y
            }
        }
    }
    init {
    }

    suspend fun nextAccount(): Account {
        return withContext(Dispatchers.IO) {
            val accounts = store.getAll()

            val latestIndex = accounts.lastOrNull()?.accountIndex ?: -1
            val nextIndex = latestIndex + 1

            val publicJwk = keyring.getPublicJwk(nextIndex)
            val privateJwk = keyring.getPrivateJwk(nextIndex)
            val thumbprint = toJwkThumbprint(toECPublicJwk(publicJwk))
            val hash = thumbprintToInt(thumbprint)
            return@withContext Account(nextIndex, publicJwk, privateJwk, thumbprint, hash)
        }
    }
    suspend fun newAccount(rp: String): Either<String, Account> {
        return withContext(Dispatchers.IO) {
            val accounts = store.getAll()

            if (accounts.any { it.rp == rp }) {
                return@withContext Either.Left("the rp is already shared account")
            }

            val latestIndex = accounts.lastOrNull()?.accountIndex ?: -1
            val nextIndex = latestIndex + 1

            val publicJwk = keyring.getPublicJwk(nextIndex)
            val privateJwk = keyring.getPrivateJwk(nextIndex)
            val thumbprint = toJwkThumbprint(toECPublicJwk(publicJwk))
            val hash = thumbprintToInt(thumbprint)

            val currentInstant = Instant.now()
            val history = IdTokenSharingHistory.newBuilder()
                .setRp(rp)
                .setAccountIndex(nextIndex)
                .setCreatedAt(
                    Timestamp.newBuilder().setSeconds(currentInstant.epochSecond)
                        .setNanos(currentInstant.nano).build()
                ).build();
            store.save(history)
            return@withContext Either.Right(
                Account(
                    nextIndex,
                    publicJwk,
                    privateJwk,
                    thumbprint,
                    hash
                )
            )
        }
    }

    suspend fun getAccount(rp: String, index: Int = -1): Account? {
        return withContext(Dispatchers.IO) {
            val accounts = store.getAll().sortedByDescending { it.accountIndex }

            val matchingAccounts = if (index > -1) {
                // specificIndexが-1より大きい場合、accountIndexでフィルタ
                accounts.filter { it.rp == rp && it.accountIndex == index }
            } else {
                // specificIndexが-1以下の場合、rpだけでフィルタ
                // indexの降順でソート済みなので、新しいインデックスが優先される
                accounts.filter { it.rp == rp }
            }
            val matchingAccount = matchingAccounts.firstOrNull() ?: return@withContext null

            val index = matchingAccount.accountIndex

            val publicJwk = keyring.getPublicJwk(index)
            val privateJwk = keyring.getPrivateJwk(index)
            val thumbprint = toJwkThumbprint(toECPublicJwk(publicJwk))
            val hash = thumbprintToInt(thumbprint)

            return@withContext Account(index, publicJwk, privateJwk, thumbprint, hash)
        }
    }
}

data class Account(
    val index: Int,
    val publicJwk: PublicJwk,
    val privateJwk: Jwk,
    val thumbprint: String,
    val hash: Int
)

@OptIn(ExperimentalStdlibApi::class)
fun thumbprintToInt(thumbprint: String): Int {
    val bytes = Base64.getUrlDecoder().decode(thumbprint)
    val hexString = bytes.toHexString().substring(0, 4)
    return hexString.toInt(16)

}
