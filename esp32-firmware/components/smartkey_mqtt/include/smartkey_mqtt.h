/**
 * @file smartkey_mqtt.h
 * @brief Wi-Fi and MQTT Home Assistant button and device-trigger integration.
 */
#pragma once

#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Start Wi-Fi station mode and connect to the configured MQTT broker. */
esp_err_t skm_init(const uint8_t lock_id[16]);

/** Queue the accepted physical-button event for non-blocking publication. */
esp_err_t skm_send_unlock(void);

#ifdef __cplusplus
}
#endif
