/**
 * @file smartkey_console.c
 * @brief Serial console for provisioning, revocation and diagnostics.
 */

#include "smartkey_console.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_console.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "smartkey_ble.h"
#include "smartkey_io.h"
#include "smartkey_store.h"
#include "smartkey_zigbee.h"

static const char *TAG = "sk_console";

static const char *state_name(skb_state_t state)
{
    switch (state) {
    case SKB_STATE_IDLE:
        return "idle";
    case SKB_STATE_CONNECTING:
        return "connecting";
    case SKB_STATE_HANDSHAKING:
        return "handshaking";
    case SKB_STATE_LINGERING:
        return "authenticated (too far, LED off)";
    case SKB_STATE_GRANTED:
        return "granted (at the door, LED on)";
    case SKB_STATE_PAIRING:
        return "pairing";
    default:
        return "?";
    }
}

static const char *zigbee_state_name(skz_state_t state)
{
    switch (state) {
    case SKZ_STATE_DISABLED:
        return "disabled";
    case SKZ_STATE_INIT:
        return "initialising";
    case SKZ_STATE_JOINING:
        return "joining";
    case SKZ_STATE_JOINED:
        return "joined";
    default:
        return "?";
    }
}

static int cmd_status(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    const uint8_t *id = sks_lock_id();
    printf("lock id  : ");
    for (int i = 0; i < SKP_ID_SIZE; i++) {
        printf("%02x", id[i]);
    }
    printf("\nprotocol : SKP1 v%d\n", SKP_VERSION);
    printf("presence : %s\n", state_name(skb_state()));
    printf("zigbee   : %s\n", zigbee_state_name(skz_state()));
    printf("led      : %d\n", (int)skio_led_get());
    printf("users    : %u/%u\n", (unsigned)sks_count(), (unsigned)sks_capacity());

    const char *code = skb_pairing_code();
    if (code != NULL) {
        printf("pairing code: %s\n", code);
    }

    skb_session_t session;
    if (skb_get_session(&session)) {
        printf("session  : '%s'\n", session.user_name);
        printf("rssi     : %d dBm raw, %d dBm filtered -> %s\n", session.rssi,
               session.filtered_rssi, session.near ? "NEAR" : "far");
    }
    printf("led gate : on >= %d dBm, off < %d dBm (median of %d samples)\n",
           CONFIG_SMARTKEY_PROXIMITY_NEAR_DBM, CONFIG_SMARTKEY_PROXIMITY_FAR_DBM,
           CONFIG_SMARTKEY_PROXIMITY_WINDOW);
#if CONFIG_SMARTKEY_RELEASE_AFTER_UNLOCK
    printf("re-arm   : after unlock, hold until < %d dBm or unseen %d ms (cap %d ms)\n",
           CONFIG_SMARTKEY_REARM_DEPART_DBM, CONFIG_SMARTKEY_REARM_ABSENT_MS,
           CONFIG_SMARTKEY_REARM_MAX_HOLD_MS);
    if (skb_rearm_holding()) {
        printf("           HOLDING: door was just opened, waiting for the phone to leave\n");
    }
#else
    printf("re-arm   : disabled (LED stays on after an unlock)\n");
#endif
    return 0;
}

/**
 * Live RSSI readout, for choosing the proximity thresholds on site.
 *
 * Hold the phone where the LED *should* come on, read the filtered value, and
 * set CONFIG_SMARTKEY_PROXIMITY_NEAR_DBM a few dB below it.
 */
static int cmd_rssi(int argc, char **argv)
{
    int seconds = 20;
    if (argc == 2) {
        seconds = atoi(argv[1]);
        if (seconds < 1 || seconds > 600) {
            printf("usage: rssi [seconds 1..600]\n");
            return 1;
        }
    }

    printf("Sampling for %d s. Walk to where the LED should turn on.\n", seconds);
    printf("Press Ctrl-C or wait for the countdown to finish.\n\n");
    printf("  %-8s %-10s %-10s %s\n", "time", "raw", "filtered", "verdict");

    const int period_ms = 250;
    for (int elapsed = 0; elapsed < seconds * 1000; elapsed += period_ms) {
        skb_session_t session;
        if (skb_get_session(&session)) {
            printf("  %5d.%1ds %4d dBm  %4d dBm  %s\n", elapsed / 1000,
                   (elapsed % 1000) / 100, session.rssi, session.filtered_rssi,
                   session.near ? "NEAR (led on)" : "far  (led off)");
        } else {
            printf("  %5d.%1ds %-10s %-10s %s\n", elapsed / 1000, (elapsed % 1000) / 100,
                   "-", "-", state_name(skb_state()));
        }
        vTaskDelay(pdMS_TO_TICKS(period_ms));
    }
    printf("\nSet CONFIG_SMARTKEY_PROXIMITY_NEAR_DBM a few dB below the filtered\n"
           "value you saw at the door, and FAR_DBM about 10-12 dB below that.\n");
    return 0;
}

/**
 * @brief Measure the advertisement reception rate.
 *
 * The door beacon and the scanner share one radio, so enabling the beacon
 * could in principle starve scanning — and every advertisement missed is an
 * RSSI sample the LED proximity filter never sees. Run this with the beacon
 * off, then again with it on, and compare adv/s: that is the whole
 * coexistence question, answered with numbers instead of assumptions.
 */
static int cmd_scanstats(int argc, char **argv)
{
    int seconds = 20;
    if (argc == 2) {
        seconds = atoi(argv[1]);
        if (seconds < 1 || seconds > 600) {
            printf("usage: scanstats [seconds 1..600]\n");
            return 1;
        }
    }

    skb_scan_report_t before;
    skb_scan_report(&before, true); /* clear, then measure a clean window */

    printf("Measuring scan throughput for %d s", seconds);
    printf(" (door beacon %s).\n", before.door_beacon_on ? "ON" : "off");
    printf("Keep a paired phone in range and stationary for a fair reading.\n\n");

    vTaskDelay(pdMS_TO_TICKS(seconds * 1000));

    skb_scan_report_t r;
    skb_scan_report(&r, false);

    const float secs = r.elapsed_ms > 0 ? (float)r.elapsed_ms / 1000.0f : 1.0f;
    printf("  window          : %.1f s\n", secs);
    printf("  door beacon     : %s\n", r.door_beacon_on ? "ON" : "off");
    printf("  all adverts     : %u  (%.1f/s)\n", (unsigned)r.adv_seen, r.adv_seen / secs);
    printf("  SmartKey adverts: %u  (%.1f/s)\n", (unsigned)r.adv_smartkey,
           r.adv_smartkey / secs);
    printf("  from paired phone: %u  (%.1f/s)  <- feeds the LED filter\n",
           (unsigned)r.adv_known, r.adv_known / secs);
    printf("\nA paired phone advertises at ~10/s. If 'from paired phone' stays\n"
           "above ~5/s the proximity filter still fills its %d sample window\n"
           "well inside the 1 s budget, so the beacon is safe to keep enabled.\n",
           CONFIG_SMARTKEY_PROXIMITY_MIN_SAMPLES);
    return 0;
}

static int cmd_users(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    for (size_t i = 0; i < sks_capacity(); i++) {
        const sks_credential_t *cred = sks_get(i);
        if (cred == NULL) {
            continue;
        }
        printf("[%u] %-16s %s user ", (unsigned)i, cred->name,
               cred->enabled ? "enabled " : "REVOKED ");
        for (int j = 0; j < 4; j++) {
            printf("%02x", cred->user_id[j]);
        }
        printf("...\n");
    }
    if (sks_count() == 0) {
        printf("no credentials stored\n");
    }
    return 0;
}

static int cmd_pair(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    esp_err_t err = skb_start_pairing();
    if (err != ESP_OK) {
        printf("failed to enter pairing mode: %s\n", esp_err_to_name(err));
        return 1;
    }
    const char *code = skb_pairing_code();
    printf("pairing mode open for %d s, code: %s\n", CONFIG_SMARTKEY_PAIRING_WINDOW_S,
           code != NULL ? code : "?");
    return 0;
}

/** Shared by 'revoke' and 'enable'. */
static int set_enabled(int argc, char **argv, bool enabled)
{
    if (argc != 2) {
        printf("usage: %s <slot>\n", argv[0]);
        return 1;
    }
    size_t slot = (size_t)strtoul(argv[1], NULL, 10);
    esp_err_t err = sks_set_enabled(slot, enabled);
    if (err != ESP_OK) {
        printf("slot %u: %s\n", (unsigned)slot, esp_err_to_name(err));
        return 1;
    }
    skb_refresh_pseudonyms();
    printf("slot %u %s\n", (unsigned)slot, enabled ? "enabled" : "revoked");
    return 0;
}

static int cmd_revoke(int argc, char **argv)
{
    return set_enabled(argc, argv, false);
}

static int cmd_enable(int argc, char **argv)
{
    return set_enabled(argc, argv, true);
}

static int cmd_forget(int argc, char **argv)
{
    if (argc != 2) {
        printf("usage: forget <slot>\n");
        return 1;
    }
    size_t slot = (size_t)strtoul(argv[1], NULL, 10);
    esp_err_t err = sks_remove(slot);
    if (err != ESP_OK) {
        printf("slot %u: %s\n", (unsigned)slot, esp_err_to_name(err));
        return 1;
    }
    skb_refresh_pseudonyms();
    printf("slot %u erased\n", (unsigned)slot);
    return 0;
}

static int cmd_reset(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("erasing all credentials and rebooting\n");
    sks_erase_all();
    skz_factory_reset();
    esp_restart();
    return 0;
}

void smartkey_console_start(void)
{
    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    repl_config.prompt = "smartkey>";
    repl_config.max_cmdline_length = 128;

    const esp_console_cmd_t commands[] = {
        {.command = "status", .help = "Show lock, presence and Zigbee status", .func = cmd_status},
        {.command = "users", .help = "List the paired phones", .func = cmd_users},
        {.command = "rssi",
         .help = "Live proximity readout for tuning: rssi [seconds]",
         .func = cmd_rssi},
        {.command = "scanstats",
         .help = "Measure advert reception rate: scanstats [seconds]",
         .func = cmd_scanstats},
        {.command = "pair", .help = "Open the pairing window", .func = cmd_pair},
        {.command = "revoke", .help = "Disable a slot: revoke <slot>", .func = cmd_revoke},
        {.command = "enable", .help = "Re-enable a slot: enable <slot>", .func = cmd_enable},
        {.command = "forget", .help = "Erase a slot: forget <slot>", .func = cmd_forget},
        {.command = "reset", .help = "Factory reset and reboot", .func = cmd_reset},
    };
    for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        ESP_ERROR_CHECK(esp_console_cmd_register(&commands[i]));
    }

#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
    esp_console_dev_usb_serial_jtag_config_t dev_config =
        ESP_CONSOLE_DEV_USB_SERIAL_JTAG_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_usb_serial_jtag(&dev_config, &repl_config, &repl));
#else
    esp_console_dev_uart_config_t dev_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&dev_config, &repl_config, &repl));
#endif

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
    ESP_LOGI(TAG, "console ready, type 'help'");
}
