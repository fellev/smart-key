/**
 * @file smartkey_zigbee.c
 * @brief On/Off switch end device that drives the door relay through Home Assistant.
 *
 * Implements protocol-spec.md §10. The whole file collapses to logging stubs when
 * CONFIG_SMARTKEY_ZIGBEE_ENABLED is disabled, so the presence logic can be tested
 * on a board without a coordinator in range.
 */

#include "smartkey_zigbee.h"

#include "esp_log.h"

static const char *TAG = "sk_zigbee";

#if CONFIG_SMARTKEY_ZIGBEE_ENABLED

#include <string.h>

#include "esp_zigbee_core.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "ha/esp_zigbee_ha_standard.h"

/** Fallback target when the coordinator has not configured a binding yet. */
#define COORDINATOR_SHORT_ADDR 0x0000
#define COORDINATOR_ENDPOINT 1

static skz_result_cb_t s_cb;
static void *s_cb_ctx;
static volatile skz_state_t s_state = SKZ_STATE_INIT;
static uint8_t s_last_tsn;

/** Convert a C string into the ZCL length-prefixed character string format. */
static void set_string_attr(char *dst, size_t dst_size, const char *src)
{
    size_t len = strlen(src);
    if (len > dst_size - 2) {
        len = dst_size - 2;
    }
    dst[0] = (char)len;
    memcpy(dst + 1, src, len);
    dst[len + 1] = '\0';
}

/**
 * @brief Scheduler-compatible wrapper around the commissioning starter.
 *
 * esp_zb_scheduler_alarm() expects a void(uint8_t) callback while
 * esp_zb_bdb_start_top_level_commissioning() returns esp_err_t, so casting the
 * pointer directly would be undefined behaviour.
 */
static void retry_commissioning(uint8_t mode)
{
    esp_err_t err = esp_zb_bdb_start_top_level_commissioning(mode);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "commissioning retry failed: %s", esp_err_to_name(err));
    }
}

void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct)
{
    uint32_t *p_sg_p = signal_struct->p_app_signal;
    esp_err_t err_status = signal_struct->esp_err_status;
    esp_zb_app_signal_type_t sig_type = (esp_zb_app_signal_type_t)*p_sg_p;

    switch (sig_type) {
    case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP:
        ESP_LOGI(TAG, "stack initialised, starting");
        esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_INITIALIZATION);
        break;

    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
        if (err_status == ESP_OK) {
            if (esp_zb_bdb_is_factory_new()) {
                ESP_LOGI(TAG, "factory new, starting network steering");
                s_state = SKZ_STATE_JOINING;
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
            } else {
                s_state = SKZ_STATE_JOINED;
                ESP_LOGI(TAG, "rejoined network, short address 0x%04hx",
                         esp_zb_get_short_address());
            }
        } else {
            ESP_LOGW(TAG, "stack start failed (%s), retrying", esp_err_to_name(err_status));
            esp_zb_scheduler_alarm(retry_commissioning,
                                   ESP_ZB_BDB_MODE_INITIALIZATION, 1000);
        }
        break;

    case ESP_ZB_BDB_SIGNAL_STEERING:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "joined network, pan 0x%04hx channel %d", esp_zb_get_pan_id(),
                     esp_zb_get_current_channel());
            s_state = SKZ_STATE_JOINED;
        } else {
            ESP_LOGW(TAG, "network steering failed (%s), retrying in 3 s",
                     esp_err_to_name(err_status));
            s_state = SKZ_STATE_JOINING;
            esp_zb_scheduler_alarm(retry_commissioning,
                                   ESP_ZB_BDB_MODE_NETWORK_STEERING, 3000);
        }
        break;

    case ESP_ZB_ZDO_SIGNAL_LEAVE:
        ESP_LOGW(TAG, "left the network");
        s_state = SKZ_STATE_JOINING;
        break;

    default:
        ESP_LOGD(TAG, "signal %s (0x%x), status %s", esp_zb_zdo_signal_to_string(sig_type),
                 (unsigned)sig_type, esp_err_to_name(err_status));
        break;
    }
}

static esp_err_t action_handler(esp_zb_core_action_callback_id_t callback_id, const void *message)
{
    if (callback_id == ESP_ZB_CORE_CMD_DEFAULT_RESP_CB_ID) {
        const esp_zb_zcl_cmd_default_resp_message_t *resp = message;
        bool ok = resp->status_code == ESP_ZB_ZCL_STATUS_SUCCESS;
        ESP_LOGI(TAG, "default response, status 0x%x", resp->status_code);
        if (s_cb != NULL) {
            s_cb(ok, s_cb_ctx);
        }
    }
    return ESP_OK;
}

/** Build endpoint 1: On/Off switch (client) + Basic/Identify (server). */
static esp_zb_ep_list_t *create_endpoint_list(void)
{
    esp_zb_on_off_switch_cfg_t switch_cfg = ESP_ZB_DEFAULT_ON_OFF_SWITCH_CONFIG();
    esp_zb_ep_list_t *ep_list = esp_zb_on_off_switch_ep_create(SKZ_ENDPOINT, &switch_cfg);

    /* Advertise a recognisable manufacturer / model to Home Assistant. */
    esp_zb_cluster_list_t *clusters = esp_zb_ep_list_get_ep(ep_list, SKZ_ENDPOINT);
    esp_zb_attribute_list_t *basic = esp_zb_cluster_list_get_cluster(
        clusters, ESP_ZB_ZCL_CLUSTER_ID_BASIC, ESP_ZB_ZCL_CLUSTER_SERVER_ROLE);
    if (basic != NULL) {
        char manufacturer[18];
        char model[20];
        set_string_attr(manufacturer, sizeof(manufacturer), SKZ_MANUFACTURER);
        set_string_attr(model, sizeof(model), SKZ_MODEL);
        esp_zb_basic_cluster_add_attr(basic, ESP_ZB_ZCL_ATTR_BASIC_MANUFACTURER_NAME_ID,
                                      manufacturer);
        esp_zb_basic_cluster_add_attr(basic, ESP_ZB_ZCL_ATTR_BASIC_MODEL_IDENTIFIER_ID, model);
    }
    return ep_list;
}

static void zigbee_task(void *arg)
{
    (void)arg;
    esp_zb_cfg_t zb_cfg = {
        .esp_zb_role = ESP_ZB_DEVICE_TYPE_ED,
        .install_code_policy = false,
        .nwk_cfg.zed_cfg =
            {
                .ed_timeout = ESP_ZB_ED_AGING_TIMEOUT_64MIN,
                /* Short keep-alive: the door unit is mains powered and the unlock
                 * command must leave the radio immediately. */
                .keep_alive = 3000,
            },
    };
    esp_zb_init(&zb_cfg);
    esp_zb_device_register(create_endpoint_list());
    esp_zb_core_action_handler_register(action_handler);
    esp_zb_set_primary_network_channel_set(ESP_ZB_TRANSCEIVER_ALL_CHANNELS_MASK);
    ESP_ERROR_CHECK(esp_zb_start(false));
    esp_zb_stack_main_loop();
}

esp_err_t skz_init(skz_result_cb_t cb, void *ctx)
{
    s_cb = cb;
    s_cb_ctx = ctx;
    s_state = SKZ_STATE_INIT;

    esp_zb_platform_config_t platform_cfg = {
        .radio_config = {.radio_mode = ZB_RADIO_MODE_NATIVE},
        .host_config = {.host_connection_mode = ZB_HOST_CONNECTION_MODE_NONE},
    };
    esp_err_t err = esp_zb_platform_config(&platform_cfg);
    if (err != ESP_OK) {
        return err;
    }
    if (xTaskCreate(zigbee_task, "sk_zigbee", 4096, NULL, 5, NULL) != pdPASS) {
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

skz_state_t skz_state(void)
{
    return s_state;
}

bool skz_ready(void)
{
    return s_state == SKZ_STATE_JOINED;
}

esp_err_t skz_send_unlock(void)
{
    if (!skz_ready()) {
        ESP_LOGW(TAG, "unlock requested but not joined to a network");
        return ESP_ERR_INVALID_STATE;
    }

    esp_zb_zcl_on_off_cmd_t cmd = {
        .zcl_basic_cmd =
            {
                .src_endpoint = SKZ_ENDPOINT,
                .dst_endpoint = COORDINATOR_ENDPOINT,
                .dst_addr_u.addr_short = COORDINATOR_SHORT_ADDR,
            },
        /* Use the binding table so the installer can point the switch at any
         * relay from Home Assistant; unbound commands reach the coordinator. */
        .address_mode = ESP_ZB_APS_ADDR_MODE_DST_ADDR_ENDP_NOT_PRESENT,
#if CONFIG_SMARTKEY_ZIGBEE_USE_TOGGLE
        .on_off_cmd_id = ESP_ZB_ZCL_CMD_ON_OFF_TOGGLE_ID,
#else
        .on_off_cmd_id = ESP_ZB_ZCL_CMD_ON_OFF_ON_ID,
#endif
    };

    esp_zb_lock_acquire(portMAX_DELAY);
    s_last_tsn = esp_zb_zcl_on_off_cmd_req(&cmd);
    esp_zb_lock_release();

    ESP_LOGI(TAG, "unlock command sent, tsn %u", s_last_tsn);
    return ESP_OK;
}

esp_err_t skz_factory_reset(void)
{
    ESP_LOGW(TAG, "zigbee factory reset");
    esp_zb_lock_acquire(portMAX_DELAY);
    esp_zb_factory_reset();
    esp_zb_lock_release();
    return ESP_OK;
}

#else /* !CONFIG_SMARTKEY_ZIGBEE_ENABLED */

esp_err_t skz_init(skz_result_cb_t cb, void *ctx)
{
    (void)cb;
    (void)ctx;
    ESP_LOGW(TAG, "zigbee disabled by Kconfig; unlock requests will only be logged");
    return ESP_OK;
}

skz_state_t skz_state(void)
{
    return SKZ_STATE_DISABLED;
}

bool skz_ready(void)
{
    return true; /* keep the rest of the flow testable without a coordinator */
}

esp_err_t skz_send_unlock(void)
{
    ESP_LOGI(TAG, "[stub] unlock command (zigbee disabled)");
    return ESP_OK;
}

esp_err_t skz_factory_reset(void)
{
    return ESP_OK;
}

#endif /* CONFIG_SMARTKEY_ZIGBEE_ENABLED */
