package com.ownd_project.tw2023_wallet_android.ui.siop_vp

import android.app.AlertDialog
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.text.HtmlCompat
import androidx.fragment.app.Fragment
import androidx.fragment.app.activityViewModels
import androidx.fragment.app.viewModels
import androidx.lifecycle.Lifecycle
import androidx.navigation.fragment.findNavController
import androidx.navigation.fragment.navArgs
import com.bumptech.glide.Glide
import com.ownd_project.tw2023_wallet_android.MainActivity
import com.ownd_project.tw2023_wallet_android.R
import com.ownd_project.tw2023_wallet_android.databinding.FragmentIdTokenSharringBinding
import com.ownd_project.tw2023_wallet_android.databinding.FragmentIssuerDetailBinding
import com.ownd_project.tw2023_wallet_android.oid.TokenSendResult
import com.ownd_project.tw2023_wallet_android.oid.PresentationDefinition
import com.ownd_project.tw2023_wallet_android.oid.SubmissionCredential
import com.ownd_project.tw2023_wallet_android.ui.shared.CredentialSharingViewModel
import com.ownd_project.tw2023_wallet_android.utils.MetadataUtil
import com.ownd_project.tw2023_wallet_android.utils.viewBinding


// todo レイアウト調整
// todo SVGをURLから表示

class TokenSharingFragment : Fragment(R.layout.fragment_id_token_sharring) {
    companion object {
        private val tag = TokenSharingFragment::class.simpleName
    }

    private val binding by viewBinding(FragmentIdTokenSharringBinding::bind)
    private lateinit var issuerDetailBinding: FragmentIssuerDetailBinding

    private val args: TokenSharingFragmentArgs by navArgs()
    private val sharedViewModel by activityViewModels<CredentialSharingViewModel>()
    private val viewModel: TokenSharingViewModel by viewModels()
    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        issuerDetailBinding =
            FragmentIssuerDetailBinding.bind(view.findViewById(R.id.issuer_details))


        val activity = requireActivity()
        val menuProvider = TokenSharingFragmentMenuProvider(this, activity.menuInflater)
        activity.addMenuProvider(menuProvider, viewLifecycleOwner, Lifecycle.State.RESUMED)

        viewModel.initDone.observe(viewLifecycleOwner, ::onInitDone)
        viewModel.tokenSendResult.observe(viewLifecycleOwner, ::onPostResult)

        binding.greenBackgroundView.visibility = View.GONE
        binding.brownBackgroundView.visibility = View.GONE
        binding.buttonSelectCredential.visibility = View.GONE

        viewModel.errorMessage.observe(viewLifecycleOwner) { errorMessage ->
            errorMessage?.let {
                Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
                viewModel.resetErrorMessage()
            }
        }

        if (!viewModel.isInitialized) {
            binding.progressOverlay.visibility = View.VISIBLE
            // 初期化処理を行う
            viewModel.isInitialized = true
            val url = args.siopRequest
            val index = args.index
            viewModel.accessPairwiseAccountManager(this, url, index)
        } else {
            Log.d(tag, "onViewCreated finish")
        }

        // クライアント情報をUIへ反映
        viewModel.clientInfo.observe(viewLifecycleOwner, ::onSetClientInfo)

        // PresentationDefinitionがセットされたら表示をVPモードに変更
        viewModel.presentationDefinition.observe(viewLifecycleOwner, ::onSetPresentationDefinition)

        // 証明書選択ボタン
        binding.buttonSelectCredential.setOnClickListener(::onOpenSelectCredential)

        // クレデンシャル変更ボタン
        binding.doChange.setOnClickListener(::onOpenSelectCredential)

        // クレデンシャル詳細で選択された提供するクレデンシャルがセットされた
        sharedViewModel.selectedCredential.observe(viewLifecycleOwner, ::onSelectCredential)

        // id_token / クレデンシャル 提供ボタン
        binding.buttonSharring.setOnClickListener(::onSharingCredential)

        // 画面クローズ要求処理
        viewModel.shouldClose.observe(viewLifecycleOwner, ::onUpdateCloseFragment)

        // 処理成功通知
        viewModel.doneSuccessfully.observe(viewLifecycleOwner, ::onUpdateProcessCompletion)
    }

    private fun onSetClientInfo(data: ClientInfo) {
        val orgNameTextView = issuerDetailBinding.tvIssuerName
        val orgLogoView = issuerDetailBinding.ivIssuerLogo
        // 所在地
        val locationLabelView = issuerDetailBinding.subTextLocation
        val locationView = issuerDetailBinding.labelLocation
        // 連絡先
        val contactLabelView = issuerDetailBinding.subTextContact
        val contactView = issuerDetailBinding.labelContact
        // 国
        val countryLabelView = issuerDetailBinding.subTextCountry
        val countryView = issuerDetailBinding.labelCountry
        // ドメイン
        val domainLabelView = issuerDetailBinding.subTextDomain
        val domainView = issuerDetailBinding.labelDomain
        // 利用規約
        val tosLabelView = issuerDetailBinding.subTextTos
        val tosView = issuerDetailBinding.labelTos
        // プライバシーポリシー
        val policyLabelView = issuerDetailBinding.subTextPolicy
        val policyView = issuerDetailBinding.labelPolicy

        binding.title.text = getString(R.string.id_token_sharing_title, data.name)
        orgNameTextView.text = data.name
        binding.sharringInfo.text = getString(R.string.id_token_sharing_sharing_info, data.name)
        binding.pairwiseIdDescription.text =
            getString(R.string.id_token_sharing_pairwise_id_description, data.name)

        binding.identicon.hash = data.identiconHash
        binding.pairwiseId.text =
            getString(R.string.id_token_sharing_pairwise_id, data.jwkThumbprint)
        if (!data.logoUrl.isNullOrEmpty()) {
            orgLogoView.visibility = View.VISIBLE
        }
        if (!data.policyUrl.isNullOrEmpty()) {
            policyLabelView.visibility = View.VISIBLE
            policyView.visibility = View.VISIBLE
            policyView.text = data.policyUrl
            policyView.setOnClickListener {
                val builder = CustomTabsIntent.Builder()
                val customTabsIntent = builder.build()
                // Custom Tabs(アプリ内ブラウザ)のキャンセル時にロックさせないため(暫定)
                // MainActivityのisLockingをfalseにセット
                (activity as? MainActivity)?.setIsLocking(true)
                customTabsIntent.launchUrl(requireContext(), Uri.parse(data.policyUrl))
            }
        }
        if (!data.tosUrl.isNullOrEmpty()) {
            tosLabelView.visibility = View.VISIBLE
            tosView.visibility = View.VISIBLE
            tosView.text = data.tosUrl
            tosView.setOnClickListener {
                val builder = CustomTabsIntent.Builder()
                val customTabsIntent = builder.build()
                // Custom Tabs(アプリ内ブラウザ)のキャンセル時にロックさせないため(暫定)
                // MainActivityのisLockingをfalseにセット
                (activity as? MainActivity)?.setIsLocking(true)
                customTabsIntent.launchUrl(requireContext(), Uri.parse(data.tosUrl))
            }
        }
        val location = data.certificateInfo.getFullAddress()
        if (!location.isNullOrEmpty()) {
            locationLabelView.visibility = View.VISIBLE
            locationView.visibility = View.VISIBLE
            locationView.text = location
        }
        if (!data.certificateInfo.country.isNullOrEmpty()) {
            // country
            // 国(todo 仕様確認: サーバー証明書が無い場合に表示する項目だとするとどうやって国を判定する？)
            countryLabelView.visibility = View.VISIBLE
            countryView.visibility = View.VISIBLE
            countryView.text = data.certificateInfo.country
        }
        if (!data.certificateInfo.domain.isNullOrEmpty()) {
            // domain
            domainLabelView.visibility = View.VISIBLE
            domainView.visibility = View.VISIBLE
            domainView.text = data.certificateInfo.domain
        }
        if (data.certificateInfo.email != null) {
            contactLabelView.visibility = View.VISIBLE
            contactView.visibility = View.VISIBLE
            contactView.text = data.certificateInfo.email
        }
        Glide.with(this)
            .load(data.logoUrl)
            .into(binding.verifierLogo1)
//            Glide.with(this)
//                .load(it.logoUrl)
//                .into(verifierLogoImageView2)
        Glide.with(this)
            .load(data.logoUrl)
            .into(orgLogoView)
//            GlideToVectorYou
//                .init()
//                .with(context)
//                .withListener(object : GlideToVectorYouListener {
//                    override fun onLoadFailed() {
//                        Log.e("IdTokenSharringFragment", "SVG image load failed")
//                    }
//
//                    override fun onResourceReady() {
//                        // 画像読み込み成功時の処理
//                        Log.d("IdTokenSharringFragment", "SVG image load succeeded")
//                    }
//                })
//                .load(Uri.parse(logoUrl), verifierLogoImageView)
    }

    private fun onSetPresentationDefinition(data: PresentationDefinition?) {
        Log.d(tag, "PresentationDefinition is set")
        val changeLabel = binding.doChange
        if (data != null) {
            // SIOPモードの領域を非表示
            binding.sharringInfoLayout.visibility = View.GONE
            // VPモードの常時表示領域を表示
            binding.title.visibility = View.GONE
            data.name?.let {
                binding.title.visibility = View.VISIBLE
                binding.title.text = it
            }
            // todo RecycleViewで複数件に対応する
            binding.sharingClaimTitle.visibility = View.GONE
            data.inputDescriptors[0].name?.let {
                binding.sharingClaimTitle.visibility = View.VISIBLE
                binding.sharingClaimTitle.text = it
            }
            binding.sharingClaimSubTitle.visibility = View.GONE
            data.inputDescriptors[0].purpose?.let {
                binding.sharingClaimSubTitle.visibility = View.VISIBLE
                binding.sharingClaimSubTitle.text = it
            }
            if (sharedViewModel.selectedCredential.value == null) {
                // クレデンシャルが未選択の場合にVPモードの初期表示状態にセット
                sharedViewModel.setPresentationDefinition(data)
                binding.greenBackgroundView.visibility = View.GONE
                changeLabel.visibility = View.GONE
                binding.buttonSelectCredential.visibility = View.VISIBLE
                val htmlText = getString(R.string.do_change)
                changeLabel.text =
                    HtmlCompat.fromHtml(htmlText, HtmlCompat.FROM_HTML_MODE_LEGACY)
                // 提供するボタンを非表示
                binding.buttonSharring.visibility = View.GONE
            }
        }
    }

    private fun onOpenSelectCredential(view: View) {
        Log.d(tag, "on click")
        val action = TokenSharingFragmentDirections.actionIdTokenSharringToNavigationCertificate()
        findNavController().navigate(action)
    }

    private fun onSelectCredential(data: SubmissionCredential?) {
        Log.d(tag, "SubmissionCredential is set")
        val greenLayout = binding.greenBackgroundView
        val brownLayout = binding.brownBackgroundView
        val changeLabel = binding.doChange
        val selectedCredentialInfo = binding.selectedCredentialInfo
        val selectButton = binding.buttonSelectCredential
        if (data == null) {
            // クリアされた
            greenLayout.visibility = View.GONE
            changeLabel.visibility = View.GONE
            brownLayout.visibility = View.VISIBLE
            selectButton.visibility = View.VISIBLE
        } else {
            val metadata = sharedViewModel.credentialIssuerMetadata
            val types = MetadataUtil.extractTypes(data.format, data.credential)
            val cs = MetadataUtil.findMatchingCredentials(data.format, types, metadata)
            val displayData = cs?.display
            greenLayout.visibility = View.VISIBLE
            changeLabel.visibility = View.VISIBLE
            brownLayout.visibility = View.GONE
            selectButton.visibility = View.GONE
            if (displayData != null) {
                val info = getString(R.string.selected_credential_info)
                selectedCredentialInfo.text =
                    getString(R.string.selected_credential_info, displayData[0].name)
            }
            // 提供するボタンを表示
            binding.buttonSharring.visibility = View.VISIBLE
        }
    }

    private fun onSharingCredential(view: View) {
        Log.d(tag, "on click")
        val selectedCredential = sharedViewModel.selectedCredential.value
        if (selectedCredential != null) {
            // todo 複数対応
            viewModel.shareToken(this, listOf(selectedCredential))
        } else {
            viewModel.shareToken(this, null)
        }
    }

    private fun onUpdateProcessCompletion(done: Boolean) {
        if (done) {
            val builder = AlertDialog.Builder(context)
            builder.setTitle(getString(R.string.sharing_credential_done))
            builder.setMessage(getString(R.string.sharing_credential_done_support_text))
            builder.setPositiveButton(R.string.close) { dialog, id ->
                sharedViewModel.reset()
                onUpdateCloseFragment(true)
            }
            val dialog: AlertDialog = builder.create()
            dialog.show()
        }
    }

    private fun onUpdateCloseFragment(close: Boolean) {
        // フラグメントを終了させる処理
        // 例: FragmentManagerを使用してフラグメントを削除
        if (close) {
//            parentFragmentManager.beginTransaction().remove(this).commit()
            requireActivity().finish()
        }
    }

    private fun onInitDone(done: Boolean) {
        if (done) {
            binding.progressOverlay.visibility = View.GONE
        }
    }

    private fun onPostResult(tokenSendResult: TokenSendResult) {
        if (tokenSendResult.location != null) {
            val url = tokenSendResult.location
            val cookies = tokenSendResult.cookies
            val action =
                TokenSharingFragmentDirections.actionIdTokenSharringToWebViewFragment(url, cookies)
            findNavController().navigate(action)
        }
    }
}