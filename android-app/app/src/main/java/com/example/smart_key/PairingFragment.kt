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

    /**
     * Door label captured when pairing starts.
     *
     * Read here rather than in onSuccess(), because that callback arrives on a
     * BLE thread where touching a View is illegal and the binding may already
     * be null.
     */
    private var pendingLabel: String = "Door"

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
        // Re-validate: the permission round trip means this can run long after
        // onStartClicked(), and the user may have edited the field since.
        if (code.length != SmartKeyProtocol.PAIRING_CODE_LEN || !code.all { it.isDigit() }) {
            showStatus(getString(R.string.pairing_code_invalid))
            return
        }
        pendingLabel = binding.doorLabel.text?.toString()?.takeIf { it.isNotBlank() } ?: "Door"

        val session = PairingSession(userId = store.userId, pairingCode = code)
        setBusy(true)
        client = PairingClient(requireContext().applicationContext, session, this).also {
            it.start()
        }
    }

    // ---------------------------------------------- PairingClient.Listener
    //
    // These arrive on a BLE binder thread at arbitrary times, including after
    // the fragment has been detached (user navigated away, screen rotated, or
    // a previous callback already popped the back stack).
    //
    // requireActivity() would then throw IllegalStateException on a non-UI
    // thread, where nothing catches it — killing the whole process. So every
    // callback hops to the UI thread through a view that may legitimately be
    // gone, and does nothing if it is.

    /**
     * Run [block] on the UI thread, but only if the fragment is still attached
     * and its view alive. Silently drops the update otherwise.
     */
    private fun onUi(block: () -> Unit) {
        val view = _binding?.root ?: return
        view.post {
            // Re-check: the fragment may have been torn down between posting
            // and running.
            if (_binding == null || !isAdded) return@post
            block()
        }
    }

    override fun onProgress(message: String) = onUi { showStatus(message) }

    override fun onSuccess(lockId: ByteArray, ltk: ByteArray, slot: Int) {
        // Persist before touching the UI: the credential must survive even if
        // this fragment is already gone, otherwise a pairing that the door
        // considers complete would be lost on our side.
        val label = pendingLabel
        store.add(lockId, ltk, label)
        SmartKeyCrypto.wipe(ltk)

        onUi {
            setBusy(false)
            client = null
            Snackbar.make(binding.root, "Paired with $label", Snackbar.LENGTH_LONG).show()
            // Guard against popping twice if a late callback arrives.
            findNavController().takeIf { it.currentDestination?.id == R.id.PairingFragment }
                ?.popBackStack()
        }
    }

    override fun onFailure(message: String) = onUi {
        setBusy(false)
        client = null
        showStatus(message)
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
