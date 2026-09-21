package com.example.smart_key

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.navigation.fragment.findNavController
import com.example.smart_key.data.CredentialStore
import com.example.smart_key.databinding.FragmentPairingBinding
import com.example.smart_key.pairing.PairingClient
import com.example.smart_key.pairing.PairingSession
import com.example.smart_key.protocol.SmartKeyCrypto
import com.example.smart_key.protocol.SmartKeyProtocol
import com.google.android.material.snackbar.Snackbar

/**
 * Pairing screen: enter the code shown by the door unit and run the exchange
 * described in shared-protocols/pairing-spec.md.
 */
class PairingFragment : Fragment(), PairingClient.Listener {

    private var _binding: FragmentPairingBinding? = null
    private val binding get() = _binding!!

    private lateinit var store: CredentialStore
    private var client: PairingClient? = null

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { granted ->
        if (granted.values.all { it }) beginPairing()
        else showStatus(getString(R.string.permissions_required))
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentPairingBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        store = CredentialStore(requireContext().applicationContext)

        binding.startPairing.setOnClickListener { onStartClicked() }
        binding.cancelPairing.setOnClickListener {
            client?.cancel()
            client = null
            setBusy(false)
            showStatus(getString(R.string.pairing_idle))
        }
    }

    private fun onStartClicked() {
        val code = binding.pairingCode.text?.toString().orEmpty()
        if (code.length != SmartKeyProtocol.PAIRING_CODE_LEN || !code.all { it.isDigit() }) {
            showStatus(getString(R.string.pairing_code_invalid))
            return
        }
        val needed = arrayOf(
            Manifest.permission.BLUETOOTH_SCAN,
            Manifest.permission.BLUETOOTH_CONNECT
        )
        val missing = needed.filter {
            ContextCompat.checkSelfPermission(requireContext(), it) !=
                PackageManager.PERMISSION_GRANTED
        }
        if (missing.isNotEmpty()) {
            permissionLauncher.launch(missing.toTypedArray())
            return
        }
        beginPairing()
    }

    private fun beginPairing() {
        val code = binding.pairingCode.text?.toString().orEmpty()
        val session = PairingSession(userId = store.userId, pairingCode = code)
        setBusy(true)
        client = PairingClient(requireContext().applicationContext, session, this).also {
            it.start()
        }
    }

    // ---------------------------------------------- PairingClient.Listener

    override fun onProgress(message: String) {
        requireActivity().runOnUiThread { showStatus(message) }
    }

    override fun onSuccess(lockId: ByteArray, ltk: ByteArray, slot: Int) {
        val label = binding.doorLabel.text?.toString()?.takeIf { it.isNotBlank() } ?: "Door"
        // Only the derived sub keys are persisted; the raw LTK is wiped here.
        store.add(lockId, ltk, label)
        SmartKeyCrypto.wipe(ltk)

        requireActivity().runOnUiThread {
            setBusy(false)
            client = null
            Snackbar.make(binding.root, "Paired with $label", Snackbar.LENGTH_LONG).show()
            findNavController().popBackStack()
        }
    }

    override fun onFailure(message: String) {
        requireActivity().runOnUiThread {
            setBusy(false)
            client = null
            showStatus(message)
        }
    }

    private fun setBusy(busy: Boolean) {
        binding.pairingProgress.visibility = if (busy) View.VISIBLE else View.GONE
        binding.startPairing.isEnabled = !busy
        binding.cancelPairing.isEnabled = busy
        binding.pairingCode.isEnabled = !busy
        binding.doorLabel.isEnabled = !busy
    }

    private fun showStatus(message: String) {
        binding.pairingStatus.text = message
    }

    override fun onDestroyView() {
        client?.cancel()
        client = null
        super.onDestroyView()
        _binding = null
    }
}
