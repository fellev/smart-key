/**
 * @file smartkey_pairing.h
 * @brief Internal interface between the BLE engine and the pairing responder.
 *
 * The door unit is a GATT *client* during normal presence operation but a GATT
 * *server* while pairing (pairing-spec.md §1), so the pairing code lives in its
 * own translation unit.
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "smartkey_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Register the pairing GATT service. Call once, before the host syncs. */
esp_err_t skp_pairing_gatt_register(void);

/**
 * @brief Arm the pairing responder and start the pairing advertisement.
 * @param code        8 digit pairing code for this window
 * @param own_addr_type address type inferred by the host
 */
esp_err_t skp_pairing_begin(const char *code, uint8_t own_addr_type);

/** Stop advertising and disarm the responder. */
void skp_pairing_end(void);

/** Called by the BLE engine when a phone was paired successfully. */
void skp_pairing_set_callback(skb_paired_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
