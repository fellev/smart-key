/**
 * @file smartkey_io.h
 * @brief LED indication and unlock button.
 *
 * The LED is driven directly from whichever task calls skio_led_set(), so the
 * "grant" decision reaches the pin without any queue hop (protocol-spec.md §8.2).
 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Visual states of the permission LED. */
typedef enum {
    SKIO_LED_OFF = 0,     /**< no authorised phone in range */
    SKIO_LED_ON,          /**< access granted, press the button */
    SKIO_LED_BLINK_SLOW,  /**< 1 Hz — connecting / handshaking */
    SKIO_LED_BLINK_FAST,  /**< 5 Hz — error or factory reset */
    SKIO_LED_BLINK_PAIR,  /**< 2 Hz — pairing mode */
} skio_led_state_t;

/** Button events delivered to the application callback. */
typedef enum {
    SKIO_BUTTON_PRESSED = 0,    /**< short press: unlock request */
    SKIO_BUTTON_HELD_PAIRING,   /**< held for CONFIG_SMARTKEY_PAIRING_HOLD_MS */
    SKIO_BUTTON_HELD_RESET,     /**< held for CONFIG_SMARTKEY_FACTORY_RESET_HOLD_MS */
} skio_button_event_t;

typedef void (*skio_button_cb_t)(skio_button_event_t event, void *ctx);

/**
 * @brief Configure the LED and button GPIOs and start the IO task.
 * @param cb  invoked from the IO task for every debounced button event
 */
esp_err_t skio_init(skio_button_cb_t cb, void *ctx);

/** @brief Set the LED state. Safe to call from any task, returns immediately. */
void skio_led_set(skio_led_state_t state);

/** @brief Current LED state. */
skio_led_state_t skio_led_get(void);

/** @brief True while the button is physically down. */
bool skio_button_is_down(void);

#ifdef __cplusplus
}
#endif
