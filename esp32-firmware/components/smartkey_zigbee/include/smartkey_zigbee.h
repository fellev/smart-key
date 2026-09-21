/**
 * @file smartkey_zigbee.h
 * @brief Zigbee 3.0 On/Off client that asks Home Assistant to open the door.
 *
 * See protocol-spec.md §10 for the endpoint / cluster mapping. When
 * CONFIG_SMARTKEY_ZIGBEE_ENABLED is off, every function is a logging stub so the
 * BLE side can be developed without a coordinator.
 */
#pragma once

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Endpoint and identifiers, must match protocol-spec.md §10. */
#define SKZ_ENDPOINT 1
#define SKZ_MANUFACTURER "SmartKey"
#define SKZ_MODEL "SK-DOOR-C5"

/** Network state of the end device. */
typedef enum {
    SKZ_STATE_DISABLED = 0, /**< built without Zigbee support */
    SKZ_STATE_INIT,         /**< stack starting */
    SKZ_STATE_JOINING,      /**< steering / rejoining */
    SKZ_STATE_JOINED,       /**< on the network, ready to send commands */
} skz_state_t;

/** Result of an unlock command, reported back to the application. */
typedef void (*skz_result_cb_t)(bool success, void *ctx);

/**
 * @brief Start the Zigbee stack (non blocking; joining continues in background).
 */
esp_err_t skz_init(skz_result_cb_t cb, void *ctx);

/** @brief Current network state. */
skz_state_t skz_state(void);

/** @brief True once the device is on a network and can send commands. */
bool skz_ready(void);

/**
 * @brief Send the "open the door" command (On, or Toggle when configured).
 *
 * Asynchronous: the callback passed to skz_init() reports the APS ack.
 * @return ESP_ERR_INVALID_STATE when not joined yet.
 */
esp_err_t skz_send_unlock(void);

/** @brief Leave the network and erase Zigbee NVRAM (factory reset). */
esp_err_t skz_factory_reset(void);

#ifdef __cplusplus
}
#endif
