/**
 * @file smartkey_main.c
 * @brief SmartKey door unit application.
 *
 * Ties the four components together:
 *
 *   smartkey_ble    presence detection + mutual authentication  -> LED
 *   smartkey_io     LED and button
 *   smartkey_zigbee On/Off command to Home Assistant
 *   smartkey_store  paired credentials
 *
 * See shared-protocols/protocol-spec.md §9 for the state machine.
 */

#include <inttypes.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "smartkey_ble.h"
#include "smartkey_console.h"
#include "smartkey_io.h"
#include "smartkey_proto.h"
#include "smartkey_store.h"
#include "smartkey_zigbee.h"

static const char *TAG = "smartkey";

/** Rate limiting state for the unlock button (security-model.md §3). */
typedef struct {
    int64_t last_unlock_us;
    uint8_t unlocks_this_minute;
    int64_t minute_started_us;
} rate_limit_t;

static rate_limit_t s_rate;

/**
 * @brief Map the BLE presence state to what the LED should show.
 *
 * The LED means exactly one thing: "an authorised phone is *right here* and
 * the button will work". LINGERING (authenticated but not close enough) is
 * therefore off, not blinking — a blink would invite the user to press.
 */
static skio_led_state_t led_for_state(skb_state_t state)
{
    switch (state) {
    case SKB_STATE_GRANTED:
        return SKIO_LED_ON;
    case SKB_STATE_CONNECTING:
    case SKB_STATE_HANDSHAKING:
        return SKIO_LED_BLINK_SLOW;
    case SKB_STATE_PAIRING:
        return SKIO_LED_BLINK_PAIR;
    case SKB_STATE_LINGERING:
    case SKB_STATE_IDLE:
    default:
        return SKIO_LED_OFF;
    }
}

/**
 * @brief Presence state changed — this is the latency critical path.
 *
 * Called directly from the NimBLE host task, so the LED reacts without any
 * queue hop (protocol-spec.md §8.2).
 */
static void on_ble_state(skb_state_t state, const skb_session_t *session, void *ctx)
{
    (void)ctx;
    skio_led_set(led_for_state(state));

    if (state == SKB_STATE_GRANTED && session != NULL) {
        ESP_LOGI(TAG, "LED on for '%s' (filtered rssi %d dBm)", session->user_name,
                 session->filtered_rssi);
    } else if (state == SKB_STATE_LINGERING && session != NULL) {
        ESP_LOGI(TAG, "'%s' is authorised but not at the door (filtered rssi %d dBm)",
                 session->user_name, session->filtered_rssi);
    } else if (state == SKB_STATE_IDLE) {
        ESP_LOGI(TAG, "no authorised phone in range");
    }
}

static void on_paired(size_t slot, void *ctx)
{
    (void)ctx;
    ESP_LOGI(TAG, "new phone paired into slot %u", (unsigned)slot);
    /* Three quick flashes as visual confirmation. */
    for (int i = 0; i < 3; i++) {
        skio_led_set(SKIO_LED_ON);
        vTaskDelay(pdMS_TO_TICKS(120));
        skio_led_set(SKIO_LED_OFF);
        vTaskDelay(pdMS_TO_TICKS(120));
    }
}

static void on_zigbee_result(bool success, void *ctx)
{
    (void)ctx;
    ESP_LOGI(TAG, "zigbee unlock %s", success ? "acknowledged" : "failed");
    skb_report_unlock(success ? SKP_UNLOCK_OK : SKP_UNLOCK_ZIGBEE_ERROR);

    if (success) {
        /* The door is open: stop inviting further presses and go idle.
         * Only on success — if the relay never actuated, the user still
         * needs the LED and the button to try again. */
        skb_release_after_unlock();
    }
}

/** @return true when another unlock is allowed right now. */
static bool rate_limit_allows(void)
{
    int64_t now = esp_timer_get_time();

    if (now - s_rate.minute_started_us > 60 * 1000000LL) {
        s_rate.minute_started_us = now;
        s_rate.unlocks_this_minute = 0;
    }
    if (s_rate.unlocks_this_minute >= 10) {
        ESP_LOGW(TAG, "rate limit: more than 10 unlocks in a minute");
        return false;
    }
    if ((now - s_rate.last_unlock_us) < CONFIG_SMARTKEY_UNLOCK_MIN_INTERVAL_MS * 1000LL) {
        ESP_LOGW(TAG, "rate limit: unlocks are too close together");
        return false;
    }

    s_rate.last_unlock_us = now;
    s_rate.unlocks_this_minute++;
    return true;
}

/**
 * @brief Short press: unlock only when an authenticated phone is *at the door*.
 *
 * This is the same condition that lights the LED, so what the user sees and
 * what the button does can never disagree.
 */
static void handle_unlock_request(void)
{
    const skb_state_t state = skb_state();
    if (state != SKB_STATE_GRANTED) {
        if (state == SKB_STATE_LINGERING) {
            ESP_LOGW(TAG, "button pressed but the phone is not close enough");
        } else {
            ESP_LOGW(TAG, "button pressed without an authorised phone in range");
        }
        /* Two fast blinks as "denied" feedback, then back to the real state. */
        skio_led_set(SKIO_LED_BLINK_FAST);
        vTaskDelay(pdMS_TO_TICKS(600));
        skio_led_set(led_for_state(skb_state()));
        return;
    }

    if (!rate_limit_allows()) {
        skb_report_unlock(SKP_UNLOCK_RATE_LIMITED);
        return;
    }

    skb_session_t session;
    if (skb_get_session(&session)) {
        ESP_LOGI(TAG, "unlock requested by '%s'", session.user_name);
    }

    esp_err_t err = skz_send_unlock();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "zigbee command failed: %s", esp_err_to_name(err));
        skb_report_unlock(SKP_UNLOCK_ZIGBEE_ERROR);
        return;
    }
#if !CONFIG_SMARTKEY_ZIGBEE_ENABLED
    /* No coordinator to acknowledge; report success immediately. */
    skb_report_unlock(SKP_UNLOCK_OK);
    skb_release_after_unlock();
#endif
}

static void handle_factory_reset(void)
{
    ESP_LOGW(TAG, "FACTORY RESET: erasing all credentials");
    skio_led_set(SKIO_LED_BLINK_FAST);
    sks_erase_all();
    skz_factory_reset();
    skb_refresh_pseudonyms();
    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();
}

/** Button events arrive from the IO task. */
static void on_button(skio_button_event_t event, void *ctx)
{
    (void)ctx;
    switch (event) {
    case SKIO_BUTTON_PRESSED:
        handle_unlock_request();
        break;
    case SKIO_BUTTON_HELD_PAIRING:
        skb_start_pairing();
        break;
    case SKIO_BUTTON_HELD_RESET:
        handle_factory_reset();
        break;
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "SmartKey door unit starting (protocol SKP1 v%d)", SKP_VERSION);

    ESP_ERROR_CHECK(sks_init());

    const uint8_t *id = sks_lock_id();
    ESP_LOGI(TAG, "lock id %02x%02x%02x%02x..., %u/%u credentials stored", id[0], id[1], id[2],
             id[3], (unsigned)sks_count(), (unsigned)sks_capacity());

    ESP_ERROR_CHECK(skio_init(on_button, NULL));
    ESP_ERROR_CHECK(skz_init(on_zigbee_result, NULL));

    skb_config_t ble_cfg = {
        .on_state = on_ble_state,
        .on_paired = on_paired,
        .ctx = NULL,
    };
    ESP_ERROR_CHECK(skb_init(&ble_cfg));

    smartkey_console_start();

    if (sks_count() == 0) {
        ESP_LOGW(TAG, "no phones paired yet - hold the button for %d s to start pairing",
                 CONFIG_SMARTKEY_PAIRING_HOLD_MS / 1000);
    }
}
