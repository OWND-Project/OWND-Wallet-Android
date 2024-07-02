package com.ownd_project.tw2023_wallet_android

import com.ownd_project.tw2023_wallet_android.pairwise.HDKeyRing
import com.ownd_project.tw2023_wallet_android.pairwise.PairwiseAccount.Companion.toECPublicJwk
import com.ownd_project.tw2023_wallet_android.utils.KeyUtil.toJwkThumbprint
import org.junit.Assert.assertEquals
import org.junit.Test

class KeyRingTest {
    @Test
    fun `generate seed`() {
        var keyRing = HDKeyRing(null)
        var mnemonicWords = keyRing.getMnemonicString()
        assertEquals(12, mnemonicWords.split(" ")?.size)

        keyRing = HDKeyRing(null, 256)
        mnemonicWords = keyRing.getMnemonicString()
        assertEquals(24, mnemonicWords.split(" ")?.size)
    }
    @Test
    fun `restore from seed`() {
        // KeyRingを初期化
        var keyRing = HDKeyRing(null)
        var mnemonicWords = keyRing.getMnemonicString()

        val address1 = keyRing.getAddress(1)
        val address2 = keyRing.getAddress(2)
        val address100 = keyRing.getAddress(100)

        val jwk1 = keyRing.getPrivateJwk(1)
        val jwk2 = keyRing.getPrivateJwk(2)
        val jwk100 = keyRing.getPrivateJwk(100)

        val jwk1Thumbprint = toJwkThumbprint(toECPublicJwk(keyRing.getPublicJwk(1)) )
        val jwk2Thumbprint = toJwkThumbprint(toECPublicJwk(keyRing.getPublicJwk(2)))
        val jwk100Thumbprint = toJwkThumbprint(toECPublicJwk(keyRing.getPublicJwk(100)))

        // リカバリーフレーズからKeyRingを復元
        var keyRingRecovered = HDKeyRing(mnemonicWords)

        // 復元したKeyRingからキーペアを復元
        val address1Recovered = keyRingRecovered.getAddress(1)
        val address2Recovered = keyRingRecovered.getAddress(2)
        val address100Recovered = keyRingRecovered.getAddress(100)

        val jwk1Recovered = keyRingRecovered.getPrivateJwk(1)
        val jwk2Recovered = keyRingRecovered.getPrivateJwk(2)
        val jwk100Recovered = keyRingRecovered.getPrivateJwk(100)

        val jwk1ThumbprintRecovered = toJwkThumbprint(toECPublicJwk(keyRingRecovered.getPublicJwk(1)))
        val jwk2ThumbprintRecovered = toJwkThumbprint(toECPublicJwk(keyRingRecovered.getPublicJwk(2)))
        val jwk100ThumbprintRecovered = toJwkThumbprint(toECPublicJwk(keyRingRecovered.getPublicJwk(100)))

        // オリジナルと復元したアドレスの比較
        assertEquals(address1, address1Recovered)
        assertEquals(address2, address2Recovered)
        assertEquals(address100, address100Recovered)

        // オリジナルと復元したJWKの比較
        assertEquals(jwk1.x, jwk1Recovered.x)
        assertEquals(jwk1.y, jwk1Recovered.y)
        assertEquals(jwk1.d, jwk1Recovered.d)

        assertEquals(jwk2.x, jwk2Recovered.x)
        assertEquals(jwk2.y, jwk2Recovered.y)
        assertEquals(jwk2.d, jwk2Recovered.d)

        assertEquals(jwk100.x, jwk100Recovered.x)
        assertEquals(jwk100.y, jwk100Recovered.y)
        assertEquals(jwk100.d, jwk100Recovered.d)

        // オリジナルと復元したJWK Thumbprintの比較
        assertEquals(jwk1Thumbprint, jwk1ThumbprintRecovered)
        assertEquals(jwk2Thumbprint, jwk2ThumbprintRecovered)
        assertEquals(jwk100Thumbprint, jwk100ThumbprintRecovered)
    }
}