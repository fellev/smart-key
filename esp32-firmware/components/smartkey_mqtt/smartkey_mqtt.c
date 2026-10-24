/**
 * @file smartkey_mqtt.c
 * @brief Wi-Fi station setup and MQTT discovery/event publishing.
 */

#include "smartkey_mqtt.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "mqtt_client.h"

static const char *TAG = "sk_mqtt";

#define DEVICE_ID_HEX_SIZE 33
#define EVENT_TOPIC_SIZE 64
#define DISCOVERY_TOPIC_SIZE 112

static char s_device_id[DEVICE_ID_HEX_SIZE];
static char s_event_topic[EVENT_TOPIC_SIZE];
static char s_discovery_topic[DISCOVERY_TOPIC_SIZE];
static char s_button_discovery_topic[DISCOVERY_TOPIC_SIZE];
static esp_mqtt_client_handle_t s_client;
static QueueHandle_t s_unlock_queue;
static volatile bool s_mqtt_connected;

static void mqtt_publish_task(void *arg)
{
    (void)arg;
    uint8_t request;
    for (;;) {
        if (xQueueReceive(s_unlock_queue, &request, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (s_client == NULL || !s_mqtt_connected) {
            ESP_LOGW(TAG, "dropped unlock event for %s because MQTT disconnected before publish",
                     s_event_topic);
            continue;
        }

        int message_id = esp_mqtt_client_publish(s_client, s_event_topic, "unlock", 6, 0, 0);
        if (message_id < 0) {
            ESP_LOGE(TAG, "could not publish unlock event to %s", s_event_topic);
        } else {
            ESP_LOGI(TAG, "published unlock event: topic=%s payload=unlock", s_event_topic);
        }
    }
}

static void publish_discovery(void)
{
    char discovery[512];
    char device_name[40];

    snprintf(device_name, sizeof(device_name), "SmartKey Door (%.8s)", s_device_id);
    int length = snprintf(
        discovery, sizeof(discovery),
        "{\"automation_type\":\"trigger\",\"platform\":\"device_automation\","
        "\"topic\":\"%s\",\"payload\":\"unlock\",\"type\":\"button_short_press\","
        "\"subtype\":\"button_1\",\"device\":{\"identifiers\":[\"smartkey_%s\"],"
        "\"name\":\"%s\",\"manufacturer\":\"SmartKey\",\"model\":\"SK-DOOR-C5\"}}",
        s_event_topic, s_device_id, device_name);
    if (length < 0 || (size_t)length >= sizeof(discovery)) {
        ESP_LOGE(TAG, "Home Assistant discovery payload exceeded its buffer");
        return;
    }

    int message_id = esp_mqtt_client_enqueue(s_client, s_discovery_topic, discovery, length, 1, 1,
                                              true);
    if (message_id < 0) {
        ESP_LOGE(TAG, "could not queue Home Assistant discovery message (%d)", message_id);
        return;
    }
    ESP_LOGI(TAG, "Home Assistant SmartKey device trigger discovery queued");

    length = snprintf(
        discovery, sizeof(discovery),
        "{\"name\":\"Open door\",\"unique_id\":\"smartkey_%s_open_door\","
        "\"command_topic\":\"%s\",\"payload_press\":\"unlock\","
        "\"device\":{\"identifiers\":[\"smartkey_%s\"],\"name\":\"%s\","
        "\"manufacturer\":\"SmartKey\",\"model\":\"SK-DOOR-C5\"}}",
        s_device_id, s_event_topic, s_device_id, device_name);
    if (length < 0 || (size_t)length >= sizeof(discovery)) {
        ESP_LOGE(TAG, "Home Assistant MQTT button payload exceeded its buffer");
        return;
    }

    message_id = esp_mqtt_client_enqueue(s_client, s_button_discovery_topic, discovery, length, 1,
                                         1, true);
    if (message_id < 0) {
        ESP_LOGE(TAG, "could not queue Home Assistant MQTT button discovery (%d)", message_id);
        return;
    }
    ESP_LOGI(TAG, "Home Assistant Open door button discovery queued");
}

static void mqtt_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id,
                               void *event_data)
{
    (void)arg;
    (void)event_base;
    (void)event_data;
    if (event_id == MQTT_EVENT_CONNECTED) {
        s_mqtt_connected = true;
        ESP_LOGI(TAG, "connected to MQTT broker");
        publish_discovery();
    } else if (event_id == MQTT_EVENT_DISCONNECTED) {
        s_mqtt_connected = false;
        ESP_LOGW(TAG, "disconnected from MQTT broker");
    } else if (event_id == MQTT_EVENT_ERROR) {
        s_mqtt_connected = false;
        ESP_LOGE(TAG, "MQTT transport error");
    }
}

static void start_mqtt_client(void)
{
    if (s_client != NULL) {
        return;
    }

    const esp_mqtt_client_config_t mqtt_config = {
        .broker.address.uri = CONFIG_SMARTKEY_MQTT_BROKER_URI,
        .session.keepalive = 30,
        .network.timeout_ms = 3000,
    };
    s_client = esp_mqtt_client_init(&mqtt_config);
    if (s_client == NULL) {
        ESP_LOGE(TAG, "could not create MQTT client");
        return;
    }

    esp_err_t err = esp_mqtt_client_register_event(s_client, ESP_EVENT_ANY_ID, mqtt_event_handler,
                                                    NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "could not register MQTT event handler: %s", esp_err_to_name(err));
        return;
    }

    err = esp_mqtt_client_start(s_client);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "could not start MQTT client: %s", esp_err_to_name(err));
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id,
                               void *event_data)
{
    (void)arg;

    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_err_t err = esp_wifi_connect();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "could not start Wi-Fi connection: %s", esp_err_to_name(err));
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_mqtt_connected = false;
        const wifi_event_sta_disconnected_t *ev = event_data;
        ESP_LOGW(TAG, "Wi-Fi disconnected (reason %d, rssi %d); reconnecting",
                 ev ? ev->reason : -1, ev ? ev->rssi : 0);
        esp_err_t err = esp_wifi_connect();
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "could not reconnect to Wi-Fi: %s", esp_err_to_name(err));
        }
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        const ip_event_got_ip_t *event = event_data;
        ESP_LOGI(TAG, "Wi-Fi connected with address " IPSTR, IP2STR(&event->ip_info.ip));
        start_mqtt_client();
    }
}

esp_err_t skm_init(const uint8_t lock_id[16])
{
    if (lock_id == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    size_t ssid_len = strlen(CONFIG_SMARTKEY_WIFI_SSID);
    size_t password_len = strlen(CONFIG_SMARTKEY_WIFI_PASSWORD);
    if (ssid_len == 0) {
        ESP_LOGE(TAG, "Wi-Fi SSID is empty; configure it in menuconfig");
        return ESP_ERR_INVALID_ARG;
    }
    if (ssid_len > sizeof(((wifi_config_t *)0)->sta.ssid) ||
        password_len > sizeof(((wifi_config_t *)0)->sta.password)) {
        ESP_LOGE(TAG, "Wi-Fi SSID or password exceeds the supported length");
        return ESP_ERR_INVALID_ARG;
    }

    for (size_t i = 0; i < 16; i++) {
        snprintf(&s_device_id[i * 2], 3, "%02x", lock_id[i]);
    }
    int event_topic_len =
        snprintf(s_event_topic, sizeof(s_event_topic), "smartkey/%s/event", s_device_id);
    int discovery_topic_len = snprintf(s_discovery_topic, sizeof(s_discovery_topic),
                                       "homeassistant/device_automation/smartkey_%s_unlock/config",
                                       s_device_id);
    int button_discovery_topic_len =
        snprintf(s_button_discovery_topic, sizeof(s_button_discovery_topic),
                 "homeassistant/button/smartkey_%s/open_door/config", s_device_id);
    if (event_topic_len < 0 || (size_t)event_topic_len >= sizeof(s_event_topic) ||
        discovery_topic_len < 0 || (size_t)discovery_topic_len >= sizeof(s_discovery_topic) ||
        button_discovery_topic_len < 0 ||
        (size_t)button_discovery_topic_len >= sizeof(s_button_discovery_topic)) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_err_t err = esp_netif_init();
    if (err != ESP_OK) {
        return err;
    }
    err = esp_event_loop_create_default();
    if (err != ESP_OK) {
        return err;
    }
    if (esp_netif_create_default_wifi_sta() == NULL) {
        return ESP_FAIL;
    }

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&wifi_init_config);
    if (err != ESP_OK) {
        return err;
    }

    err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_event_handler, NULL);
    if (err != ESP_OK) {
        return err;
    }

    wifi_config_t wifi_config = {0};
    memcpy(wifi_config.sta.ssid, CONFIG_SMARTKEY_WIFI_SSID, ssid_len);
    memcpy(wifi_config.sta.password, CONFIG_SMARTKEY_WIFI_PASSWORD, password_len);

    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_wifi_set_mode(WIFI_MODE_STA);
    if (err != ESP_OK) {
        return err;
    }
    err = esp_wifi_set_config(WIFI_IF_STA, &wifi_config);
    if (err != ESP_OK) {
        return err;
    }

    s_unlock_queue = xQueueCreate(1, sizeof(uint8_t));
    if (s_unlock_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }
    if (xTaskCreate(mqtt_publish_task, "sk_mqtt_pub", 4096, NULL, 5, NULL) != pdPASS) {
        vQueueDelete(s_unlock_queue);
        s_unlock_queue = NULL;
        return ESP_ERR_NO_MEM;
    }
    return esp_wifi_start();
}

esp_err_t skm_send_unlock(void)
{
    if (s_unlock_queue == NULL || s_client == NULL || !s_mqtt_connected) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t request = 1;
    if (xQueueSend(s_unlock_queue, &request, 0) != pdTRUE) {
        ESP_LOGW(TAG, "unlock event queue is full");
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}
