/**
 * @file smartkey_io.c
 * @brief LED blinker and debounced button, running in one small task.
 */

#include "smartkey_io.h"

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "sk_io";

#define IO_TICK_MS 10
#define LED_SLOW_PERIOD_MS 1000
#define LED_FAST_PERIOD_MS 200
#define LED_PAIR_PERIOD_MS 500

static volatile skio_led_state_t s_led_state = SKIO_LED_OFF;
static volatile bool s_button_down;
static skio_button_cb_t s_cb;
static void *s_cb_ctx;

static inline void led_write(bool on)
{
#if CONFIG_SMARTKEY_LED_ACTIVE_LOW
    gpio_set_level(CONFIG_SMARTKEY_LED_GPIO, on ? 0 : 1);
#else
    gpio_set_level(CONFIG_SMARTKEY_LED_GPIO, on ? 1 : 0);
#endif
}

/** Map a blink state to its period; 0 means "steady". */
static uint32_t blink_period_ms(skio_led_state_t state)
{
    switch (state) {
    case SKIO_LED_BLINK_SLOW:
        return LED_SLOW_PERIOD_MS;
    case SKIO_LED_BLINK_FAST:
        return LED_FAST_PERIOD_MS;
    case SKIO_LED_BLINK_PAIR:
        return LED_PAIR_PERIOD_MS;
    default:
        return 0;
    }
}

static void update_led(uint32_t elapsed_ms)
{
    skio_led_state_t state = s_led_state;
    uint32_t period = blink_period_ms(state);
    if (period == 0) {
        led_write(state == SKIO_LED_ON);
        return;
    }
    led_write((elapsed_ms % period) < (period / 2));
}

/**
 * @brief Debounce the button and classify press duration.
 *
 * A long hold fires its event as soon as the threshold is reached (so the user
 * gets LED feedback while still holding), and the release is then swallowed.
 */
static void update_button(uint32_t elapsed_ms)
{
    static bool stable_down;
    static bool raw_last;
    static uint32_t raw_since;
    static uint32_t down_since;
    static bool reset_fired;
    static bool pairing_fired;

    /* Active low: the button shorts the pin to ground. */
    bool raw = gpio_get_level(CONFIG_SMARTKEY_BUTTON_GPIO) == 0;
    if (raw != raw_last) {
        raw_last = raw;
        raw_since = elapsed_ms;
        return;
    }
    if ((elapsed_ms - raw_since) < CONFIG_SMARTKEY_BUTTON_DEBOUNCE_MS) {
        return;
    }
    if (raw == stable_down) {
        /* Still held: check the long press thresholds, longest first. */
        if (stable_down) {
            uint32_t held = elapsed_ms - down_since;
            if (!reset_fired && held >= CONFIG_SMARTKEY_FACTORY_RESET_HOLD_MS) {
                reset_fired = true;
                ESP_LOGW(TAG, "button held %ums: factory reset", (unsigned)held);
                if (s_cb) {
                    s_cb(SKIO_BUTTON_HELD_RESET, s_cb_ctx);
                }
            } else if (!pairing_fired && held >= CONFIG_SMARTKEY_PAIRING_HOLD_MS) {
                /* Keep counting afterwards so the reset threshold can still hit. */
                pairing_fired = true;
                ESP_LOGI(TAG, "button held %ums: pairing mode", (unsigned)held);
                if (s_cb) {
                    s_cb(SKIO_BUTTON_HELD_PAIRING, s_cb_ctx);
                }
            }
        }
        return;
    }

    stable_down = raw;
    s_button_down = raw;
    if (raw) {
        down_since = elapsed_ms;
        reset_fired = false;
        pairing_fired = false;
    } else if (!pairing_fired && !reset_fired &&
               (elapsed_ms - down_since) < CONFIG_SMARTKEY_PAIRING_HOLD_MS) {
        ESP_LOGD(TAG, "button short press");
        if (s_cb) {
            s_cb(SKIO_BUTTON_PRESSED, s_cb_ctx);
        }
    }
}

static void io_task(void *arg)
{
    (void)arg;
    const int64_t start_us = esp_timer_get_time();
    for (;;) {
        uint32_t elapsed_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
        update_led(elapsed_ms);
        update_button(elapsed_ms);
        vTaskDelay(pdMS_TO_TICKS(IO_TICK_MS));
    }
}

esp_err_t skio_init(skio_button_cb_t cb, void *ctx)
{
    s_cb = cb;
    s_cb_ctx = ctx;

    gpio_config_t led_cfg = {
        .pin_bit_mask = 1ULL << CONFIG_SMARTKEY_LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    esp_err_t err = gpio_config(&led_cfg);
    if (err != ESP_OK) {
        return err;
    }
    led_write(false);

    gpio_config_t btn_cfg = {
        .pin_bit_mask = 1ULL << CONFIG_SMARTKEY_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    err = gpio_config(&btn_cfg);
    if (err != ESP_OK) {
        return err;
    }

    if (xTaskCreate(io_task, "sk_io", 3072, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "led gpio %d, button gpio %d", CONFIG_SMARTKEY_LED_GPIO,
             CONFIG_SMARTKEY_BUTTON_GPIO);
    return ESP_OK;
}

void skio_led_set(skio_led_state_t state)
{
    if (s_led_state == state) {
        return;
    }
    s_led_state = state;
    /* Apply steady states immediately so the LED never waits for the next tick. */
    if (blink_period_ms(state) == 0) {
        led_write(state == SKIO_LED_ON);
    }
}

skio_led_state_t skio_led_get(void)
{
    return s_led_state;
}

bool skio_button_is_down(void)
{
    return s_button_down;
}
