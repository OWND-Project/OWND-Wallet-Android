package com.ownd_project.tw2023_wallet_android.ui.recipient

import android.content.Context
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModelProvider
import androidx.navigation.findNavController
import androidx.navigation.fragment.navArgs
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.ownd_project.tw2023_wallet_android.R
import com.ownd_project.tw2023_wallet_android.databinding.FragmentRecipientDetailBinding
import com.ownd_project.tw2023_wallet_android.utils.DisplayUtil


class RecipientDetailFragment : Fragment() {

    // navArgsデリゲートを使用して遷移元から引数を取得
    private val args: RecipientDetailFragmentArgs by navArgs()

    private var _binding: FragmentRecipientDetailBinding? = null
    private val binding get() = _binding!!

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {

        DisplayUtil.setFragmentTitle(
            activity as? AppCompatActivity, getString(R.string.title_recipient)
        )

        val recipientViewModel = ViewModelProvider(requireActivity())[RecipientViewModel::class.java]


        _binding = FragmentRecipientDetailBinding.inflate(inflater, container, false)

        recipientViewModel.sharingHistories.observe(viewLifecycleOwner) { histories ->
            if (histories != null) {
                // tmp をfilterして、historiesByRpとして変数定義する。
                // filterの条件は、引数で受け取ったrpと、tmpのrpが一致するもののみとする。
                val historiesByRp = histories.itemsList.filter { it.rp == args.rp }

                if (historiesByRp.isNullOrEmpty()) {
                    Log.d(tag, "sharing histories that match the rp is empty")
                }else{
                    binding.histories.visibility = View.VISIBLE
                    // `fragment_recipient_detail`のRecyclerViewを取得して、`historiesByRp`を表示する
                    // RecyclerViewのAdapterは、`RecipientDetailAdapter`を使用する
                    // Adapterのコンストラクタには、`historiesByRp`を渡す
                    val adapter = RecipientDetailAdapter(requireContext(), recipientViewModel, historiesByRp)
                    binding.histories.layoutManager = LinearLayoutManager(context)
                    binding.histories.adapter = adapter
                }
            }else{
                Log.d(tag, "empty sharing histories")
            }
        }

        // Inflate the layout for this fragment
        return binding.root
    }


    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        val activity = requireActivity()
        val menuProvider = RecipientDetailFragmentMenuProvider(this, activity.menuInflater)
        activity.addMenuProvider(menuProvider, viewLifecycleOwner, Lifecycle.State.RESUMED)

        // 取得した引数を使用してUIを更新
        val rp = args.rp

        val rpTextView = view.findViewById<TextView>(R.id.rp_text_view)
        rpTextView.text = rp
    }
}



class RecipientDetailAdapter(
    private val context: Context,
    private val recipientViewModel: RecipientViewModel,
    private val histories: List<com.ownd_project.tw2023_wallet_android.datastore.CredentialSharingHistory>) :
    RecyclerView.Adapter<RecipientDetailAdapter.ViewHolder>() {

    class ViewHolder(view: View) : RecyclerView.ViewHolder(view) {
        val provideDate: TextView = view.findViewById(R.id.provide_date)
        val claims: TextView = view.findViewById(R.id.claims)
        val numberOfClaims: TextView = view.findViewById(R.id.number_of_claims)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_detail_history, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val history = histories[position]
        val claims = history.claimsList
        val claimsText = concatenateAndTruncate(claims, 15)
        val numberOfClaims = context.getString(R.string.number_of_claims, claims.size.toString())

        holder.provideDate.text = timestampToString(history.createdAt)
        holder.claims.text = claimsText
        holder.numberOfClaims.text = numberOfClaims

        holder.itemView.setOnClickListener {
            recipientViewModel.setTargetHistory(history)
            val action = RecipientDetailFragmentDirections.actionToSharedClaimDetail()
            it.findNavController().navigate(action)
        }
    }

    private fun Bundle.putCredentialSharingHistory(
        key: String,
        credentialSharingHistory: com.ownd_project.tw2023_wallet_android.datastore.CredentialSharingHistory,
    ) {
        putByteArray(key, credentialSharingHistory.toByteArray())
    }

    override fun getItemCount() = histories.size
}