package com.example.smart_key

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.navigation.fragment.findNavController
import com.example.smart_key.ble.PresenceService
import com.example.smart_key.data.CredentialStore
import com.example.smart_key.databinding.FragmentStatusBinding
import com.google.android.material.snackbar.Snackbar
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.launch

/**
 * Main screen: presence state, the paired doors, and the entry point to pairing.
 */
class StatusFragment : Fragment() {

    private var _binding: FragmentStatusBinding? = null
    private val binding get() = _binding!!

    private lateinit var store: CredentialStore

    /** Everything the presence service needs before it can start. */
    private val requiredPermissions = buildList {
        add(Manifest.permission.BLUETOOTH_ADVERTISE)
        add(Manifest.permission.BLUETOOTH_CONNECT)
        add(Manifest.permission.BLUETOOTH_SCAN)
        add(Manifest.permission.POST_NOTIFICATIONS)
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { granted ->
        if (granted.values.all { it }) {
            PresenceService.start(requireContext())
        } else {
            Snackbar.make(binding.root, R.string.permissions_required, Snackbar.LENGTH_LONG).show()
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        _binding = FragmentStatusBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        store = CredentialStore(requireContext().applicationContext)

        binding.pairButton.setOnClickListener {
            findNavController().navigate(R.id.action_Status_to_Pairing)
        }
        binding.presenceToggle.setOnClickListener { togglePresence() }

        viewLifecycleOwner.lifecycleScope.launch {
            viewLifecycleOwner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                combine(PresenceService.state, PresenceService.warnings) { state, warning ->
                    state to warning
                }.collect { (state, warning) ->
                    render(state)
                    warning?.let {
                        Snackbar.make(binding.root, it, Snackbar.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        renderDoors()
        render(PresenceService.state.value)
    }

    private fun togglePresence() {
        if (PresenceService.state.value == PresenceService.State.STOPPED) {
            val missing = requiredPermissions.filter {
                ContextCompat.checkSelfPermission(requireContext(), it) !=
                    PackageManager.PERMISSION_GRANTED
            }
            if (missing.isNotEmpty()) {
                permissionLauncher.launch(missing.toTypedArray())
                return
            }
            if (store.all().isEmpty()) {
                Snackbar.make(binding.root, R.string.status_no_doors, Snackbar.LENGTH_LONG).show()
                return
            }
            PresenceService.start(requireContext())
        } else {
            PresenceService.stop(requireContext())
        }
    }

    private fun render(state: PresenceService.State) {
        val hasDoors = store.all().isNotEmpty()
        binding.statusText.setText(
            when {
                !hasDoors -> R.string.status_no_doors
                state == PresenceService.State.LISTENING -> R.string.status_listening
                state == PresenceService.State.ADVERTISING -> R.string.status_advertising
                state == PresenceService.State.CONNECTED -> R.string.status_connected
                state == PresenceService.State.UNLOCKED -> R.string.status_unlocked
                else -> R.string.status_stopped
            }
        )
        binding.statusDetail.visibility = if (hasDoors) View.GONE else View.VISIBLE
        binding.presenceToggle.isEnabled = hasDoors
        binding.presenceToggle.setText(
            if (state == PresenceService.State.STOPPED) R.string.presence_start
            else R.string.presence_stop
        )
    }

    /** Rebuild the list of paired doors with a "forget" action for each. */
    private fun renderDoors() {
        binding.doorList.removeAllViews()
        store.all().forEach { credential ->
            val row = layoutInflater.inflate(
                android.R.layout.simple_list_item_2, binding.doorList, false
            )
            row.findViewById<TextView>(android.R.id.text1).text = credential.label
            row.findViewById<TextView>(android.R.id.text2).text = credential.shortId
            row.setOnLongClickListener {
                store.remove(credential.lockId)
                renderDoors()
                render(PresenceService.state.value)
                Snackbar.make(binding.root, "Forgot ${credential.label}", Snackbar.LENGTH_SHORT)
                    .show()
                true
            }
            binding.doorList.addView(row)
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
