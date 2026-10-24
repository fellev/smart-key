/**
 * @file smartkey_ble.h
 * @brief BLE presence engine: scanner, GATT client and pairing peripheral.
 *
 * Implements the door unit half of protocol-spec.md §2 and §5. The whole
 * presence path (advertisement match → connect → handshake → LED) runs inside
 * the NimBLE host task so it meets the sub-second budget of §8.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "smartkey_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Door unit presence states, mirroring protocol-spec.md §9. */
typedef enum {
    SKB_STATE_IDLE = 0,
    SKB_STATE_CONNECTING,
    SKB_STATE_HANDSHAKING,
    /**
     * Authenticated, but the phone is not close enough to the board.
     * The LED stays off and the button is refused; the connection is kept so
     * that stepping closer re-grants instantly without a new handshake.
     */
    SKB_STATE_LINGERING,
    /** Authenticated **and** measured to be next to the board: LED on. */
    SKB_STATE_GRANTED,
    SKB_STATE_PAIRING,
} skb_state_t;

/** Snapshot of the currently authorised session. */
typedef struct {
    bool active;
    uint8_t user_id[SKP_ID_SIZE];
    uint8_t session_id[SKP_SESSION_ID_SIZE];
    char user_name[32];
    int8_t rssi;         /**< most recent raw sample */
    int8_t filtered_rssi; /**< median of the sliding window */
    bool near;           /**< filtered proximity verdict */
} skb_session_t;

/** Called on every presence state change (from the NimBLE host task). */
typedef void (*skb_state_cb_t)(skb_state_t state, const skb_session_t *session, void *ctx);

/** Called when a phone was successfully paired. */
typedef void (*skb_paired_cb_t)(size_t slot, void *ctx);

typedef struct {
    skb_state_cb_t on_state;
    skb_paired_cb_t on_paired;
    void *ctx;
} skb_config_t;

/**
 * @brief Initialise NimBLE and start scanning for SmartKey phone beacons.
 *
 * Requires sks_init() to have completed (the credential store provides the
 * pseudonym table input).
 */
esp_err_t skb_init(const skb_config_t *cfg);

/** @brief Current presence state. */
skb_state_t skb_state(void);

/** @brief Copy the active session; @return false when there is none. */
bool skb_get_session(skb_session_t *out);

/**
 * @brief Report an unlock attempt to the phone (protocol-spec.md §6).
 * @param result one of skp_unlock_result_t
 */
esp_err_t skb_report_unlock(uint8_t result);

/**
 * @brief The door was actually opened: release the session and go idle.
 *
 * Call after a *successful* unlock. The session is dropped, the LED goes out
 * and the unit returns to IDLE rather than staying lit while the user is
 * still standing at the door ("one approach, one opening").
 *
 * The phone that just unlocked is then refused until it is seen to leave, so
 * that going idle does not simply result in an immediate reconnection from
 * the phone still in the user's hand. See protocol-spec.md §9.1.
 *
 * The frame reporting the unlock is flushed to the phone before the link is
 * torn down, so the app still shows "Door opened".
 */
void skb_release_after_unlock(void);

/**
 * @brief True while a phone is being refused after opening the door.
 *
 * Diagnostic only — makes the otherwise invisible "why is the LED not coming
 * back on?" state visible on the console.
 */
bool skb_rearm_holding(void);

/**
 * @brief Enter pairing mode for CONFIG_SMARTKEY_PAIRING_WINDOW_S seconds.
 *
 * Stops the scanner and starts the pairing advertisement instead
 * (pairing-spec.md §1).
 */
esp_err_t skb_start_pairing(void);

/** @brief Leave pairing mode early and resume scanning. */
esp_err_t skb_stop_pairing(void);

/** @brief The pairing code for the current window, or NULL when not pairing. */
const char *skb_pairing_code(void);

/** @brief Recompute the pseudonym lookup table (call after pairing/revocation). */
void skb_refresh_pseudonyms(void);

/** Scan throughput snapshot, used to measure the cost of the door beacon. */
typedef struct {
    uint32_t adv_seen;     /**< all advertisement reports */
    uint32_t adv_smartkey; /**< valid SmartKey phone beacons */
    uint32_t adv_known;    /**< from a paired phone (these feed the LED filter) */
    uint32_t elapsed_ms;   /**< measurement window */
    bool door_beacon_on;   /**< whether the recovery beacon is currently running */
} skb_scan_report_t;

/**
 * @brief Read (and optionally clear) the scan throughput counters.
 *
 * Enabling the door beacon makes the radio interleave advertising with
 * scanning. Scanning is the latency-critical half, so this exists to prove
 * empirically that the advertisement rate has not dropped rather than
 * assuming it. See the README section "Verifying beacon/scan coexistence".
 */
void skb_scan_report(skb_scan_report_t *out, bool reset);

#ifdef __cplusplus
}
#endif
